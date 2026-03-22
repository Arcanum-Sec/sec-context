<!-- Source: Arcanum sec-context (https://github.com/arcanum-sec/sec-context), CC BY 4.0, Jason Haddix / Arcanum Information Security -->

## 10. File Handling

**CWE References:** CWE-22 (Path Traversal), CWE-434 (Unrestricted Upload), CWE-377 (Insecure Temp File), CWE-59 (Symlink Following), CWE-732 (Incorrect Permission Assignment)
**Severity:** High to Critical | **Related:** [[File-Handling]]

> **Risk:** File handling vulnerabilities enable attackers to read/write arbitrary files, execute malicious uploads, or escalate privileges through symlink attacks. AI-generated code frequently uses unsafe path concatenation and skips file validation entirely.

### 10.1 Path Traversal Vulnerabilities

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Direct path concatenation allows traversal
// ========================================
FUNCTION download_file_vulnerable(user_requested_filename):
    // VULNERABLE: Attacker can request "../../etc/passwd"
    file_path = "/var/app/uploads/" + user_requested_filename

    content = read_file(file_path)
    RETURN content
END FUNCTION

@route("/api/files/download")
FUNCTION handle_download_bad(request):
    filename = request.query.filename
    // No validation - attacker controls path
    RETURN download_file_vulnerable(filename)
END FUNCTION

// Attack examples:
// ?filename=../../etc/passwd          -> reads /etc/passwd
// ?filename=....//....//etc/passwd    -> bypasses simple ../ filters
// ?filename=..%2F..%2Fetc/passwd      -> URL encoded traversal
// ?filename=/etc/passwd               -> absolute path injection

// ========================================
// GOOD: Secure path handling with validation
// ========================================
CONSTANT UPLOAD_DIR = "/var/app/uploads"

FUNCTION download_file_secure(user_requested_filename):
    // Step 1: Reject obviously malicious input
    IF user_requested_filename IS NULL OR user_requested_filename == "":
        THROW ValidationError("Filename required")
    END IF

    // Step 2: Get only the base filename, reject path components
    safe_filename = get_basename(user_requested_filename)

    // Step 3: Reject filenames that are empty after basename extraction
    IF safe_filename == "" OR safe_filename == "." OR safe_filename == "..":
        THROW ValidationError("Invalid filename")
    END IF

    // Step 4: Build the full path
    full_path = join_path(UPLOAD_DIR, safe_filename)

    // Step 5: Resolve to absolute path and verify it's within allowed directory
    resolved_path = resolve_absolute_path(full_path)

    IF NOT resolved_path.starts_with(UPLOAD_DIR + "/"):
        log.security("Path traversal attempt blocked", {
            requested: user_requested_filename,
            resolved: resolved_path
        })
        THROW SecurityError("Access denied")
    END IF

    // Step 6: Verify file exists and is a regular file (not directory/symlink)
    IF NOT file_exists(resolved_path) OR NOT is_regular_file(resolved_path):
        THROW NotFoundError("File not found")
    END IF

    RETURN read_file(resolved_path)
END FUNCTION

// Alternative: Use database lookups instead of filesystem paths
FUNCTION download_file_by_id(file_id):
    // Validate file_id format (UUID)
    IF NOT is_valid_uuid(file_id):
        THROW ValidationError("Invalid file ID")
    END IF

    // Look up file metadata in database
    file_record = database.query(
        "SELECT storage_path, original_name, owner_id FROM files WHERE id = ?",
        [file_id]
    )

    IF file_record IS NULL:
        THROW NotFoundError("File not found")
    END IF

    // Verify ownership
    IF file_record.owner_id != current_user.id:
        THROW ForbiddenError("Access denied")
    END IF

    // Storage path is server-controlled, not user input
    RETURN read_file(file_record.storage_path)
END FUNCTION

// Path validation helper
FUNCTION is_safe_path(base_dir, requested_path):
    // Resolve both paths to absolute canonical form
    base_resolved = resolve_canonical_path(base_dir)
    full_resolved = resolve_canonical_path(join_path(base_dir, requested_path))

    // Ensure resolved path is within base directory
    RETURN full_resolved.starts_with(base_resolved + PATH_SEPARATOR)
END FUNCTION
```

### 10.2 Unrestricted File Uploads

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No validation on uploaded files
// ========================================
@route("/api/upload")
FUNCTION upload_file_vulnerable(request):
    uploaded_file = request.files.get("file")

    // VULNERABLE: Accepts any file type
    filename = uploaded_file.filename

    // VULNERABLE: Uses user-provided filename directly
    save_path = "/var/app/uploads/" + filename

    // VULNERABLE: No size limits
    uploaded_file.save(save_path)

    // VULNERABLE: May be served with executable MIME type
    RETURN {url: "/files/" + filename}
END FUNCTION

// Attack scenarios:
// - Upload shell.php -> execute PHP code
// - Upload malicious.html -> stored XSS
// - Upload ../../../etc/cron.d/malicious -> write to system dirs
// - Upload huge file -> disk exhaustion DoS
// - Upload polyglot (valid image + embedded JS) -> bypass checks

// ========================================
// GOOD: Comprehensive upload validation
// ========================================
CONSTANT ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "pdf", "doc", "docx"}
CONSTANT ALLOWED_MIME_TYPES = {
    "image/jpeg", "image/png", "image/gif",
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
}
CONSTANT MAX_FILE_SIZE = 10 * 1024 * 1024  // 10 MB
CONSTANT UPLOAD_DIR = "/var/app/uploads"

@route("/api/upload")
FUNCTION upload_file_secure(request):
    uploaded_file = request.files.get("file")

    IF uploaded_file IS NULL:
        RETURN error_response(400, "No file provided")
    END IF

    // Step 1: Check file size BEFORE reading into memory
    content_length = request.headers.get("Content-Length")
    IF content_length IS NOT NULL AND int(content_length) > MAX_FILE_SIZE:
        RETURN error_response(413, "File too large")
    END IF

    // Step 2: Validate original filename extension
    original_filename = uploaded_file.filename
    extension = get_extension(original_filename).lower()

    IF extension NOT IN ALLOWED_EXTENSIONS:
        log.warning("Rejected upload with extension", {extension: extension})
        RETURN error_response(400, "File type not allowed")
    END IF

    // Step 3: Read file with size limit
    file_content = uploaded_file.read(MAX_FILE_SIZE + 1)

    IF len(file_content) > MAX_FILE_SIZE:
        RETURN error_response(413, "File too large")
    END IF

    // Step 4: Validate MIME type from file content (magic bytes)
    detected_mime = detect_mime_type(file_content)

    IF detected_mime NOT IN ALLOWED_MIME_TYPES:
        log.warning("MIME type mismatch", {
            claimed: uploaded_file.content_type,
            detected: detected_mime
        })
        RETURN error_response(400, "File type not allowed")
    END IF

    // Step 5: For images, verify they parse correctly (anti-polyglot)
    IF detected_mime.starts_with("image/"):
        TRY:
            image = parse_image(file_content)
            // Re-encode to strip any embedded data
            file_content = encode_image(image, format=extension)
        CATCH ImageParseError:
            RETURN error_response(400, "Invalid image file")
        END TRY
    END IF

    // Step 6: Generate random filename (never use user input)
    random_name = generate_uuid() + "." + extension
    save_path = join_path(UPLOAD_DIR, random_name)

    // Step 7: Save with restrictive permissions
    write_file(save_path, file_content, permissions=0o644)

    // Step 8: Store metadata in database
    file_id = database.insert("files", {
        id: generate_uuid(),
        storage_name: random_name,
        original_name: sanitize_filename(original_filename),
        mime_type: detected_mime,
        size: len(file_content),
        owner_id: current_user.id,
        uploaded_at: current_timestamp()
    })

    log.info("File uploaded", {file_id: file_id, size: len(file_content)})

    RETURN {
        file_id: file_id,
        // Serve through controlled endpoint, not direct file access
        url: "/api/files/" + file_id
    }
END FUNCTION

// Serve uploaded files safely
@route("/api/files/{file_id}")
FUNCTION serve_file_secure(request, file_id):
    file_record = database.get_file(file_id)

    IF file_record IS NULL OR file_record.owner_id != current_user.id:
        RETURN error_response(404, "File not found")
    END IF

    file_path = join_path(UPLOAD_DIR, file_record.storage_name)
    content = read_file(file_path)

    RETURN response(200, content, headers={
        // Force download for non-image types
        "Content-Disposition": "attachment; filename=\"" +
                              sanitize_header(file_record.original_name) + "\"",
        // Prevent MIME sniffing
        "X-Content-Type-Options": "nosniff",
        // Strict content type
        "Content-Type": file_record.mime_type
    })
END FUNCTION
```

### 10.3 Missing File Type Validation

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Extension-only or no validation
// ========================================
FUNCTION validate_image_bad(filename, file_content):
    // VULNERABLE: Only checks extension, easily spoofed
    extension = get_extension(filename).lower()

    IF extension IN ["jpg", "jpeg", "png", "gif"]:
        RETURN TRUE  // Attacker renames malware.exe to malware.jpg
    END IF

    RETURN FALSE
END FUNCTION

FUNCTION validate_mime_header_bad(file_content):
    // VULNERABLE: Only checks claimed MIME type header
    mime = request.headers.get("Content-Type")

    IF mime.starts_with("image/"):
        RETURN TRUE  // Attacker sets Content-Type: image/png for shell.php
    END IF

    RETURN FALSE
END FUNCTION

// ========================================
// GOOD: Multi-layer file type validation
// ========================================

// Magic bytes signatures for common file types
MAGIC_SIGNATURES = {
    "jpg": [0xFF, 0xD8, 0xFF],
    "png": [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
    "gif": [0x47, 0x49, 0x46, 0x38],  // GIF8
    "pdf": [0x25, 0x50, 0x44, 0x46],  // %PDF
    "zip": [0x50, 0x4B, 0x03, 0x04],
    "docx": [0x50, 0x4B, 0x03, 0x04],  // DOCX is ZIP-based
}

FUNCTION validate_file_type(filename, file_content, allowed_types):
    // Layer 1: Extension validation
    extension = get_extension(filename).lower()

    IF extension NOT IN allowed_types:
        RETURN {valid: FALSE, reason: "Extension not allowed"}
    END IF

    // Layer 2: Magic bytes validation
    detected_type = detect_type_by_magic(file_content)

    IF detected_type IS NULL:
        RETURN {valid: FALSE, reason: "Unknown file type"}
    END IF

    IF detected_type NOT IN allowed_types:
        RETURN {valid: FALSE, reason: "Content type not allowed"}
    END IF

    // Layer 3: Extension matches content
    IF NOT extension_matches_content(extension, detected_type):
        RETURN {valid: FALSE, reason: "Extension does not match content"}
    END IF

    // Layer 4: For specific types, deep validation
    IF detected_type IN ["jpg", "jpeg", "png", "gif"]:
        IF NOT validate_image_structure(file_content):
            RETURN {valid: FALSE, reason: "Invalid image structure"}
        END IF
    ELSE IF detected_type == "pdf":
        IF NOT validate_pdf_safe(file_content):
            RETURN {valid: FALSE, reason: "PDF contains unsafe content"}
        END IF
    ELSE IF detected_type IN ["docx", "xlsx"]:
        IF NOT validate_office_safe(file_content):
            RETURN {valid: FALSE, reason: "Document contains macros"}
        END IF
    END IF

    RETURN {valid: TRUE, detected_type: detected_type}
END FUNCTION

FUNCTION detect_type_by_magic(file_content):
    IF len(file_content) < 8:
        RETURN NULL
    END IF

    header = file_content[0:8]

    FOR type_name, signature IN MAGIC_SIGNATURES:
        IF header.starts_with(bytes(signature)):
            RETURN type_name
        END IF
    END FOR

    RETURN NULL
END FUNCTION

FUNCTION validate_image_structure(file_content):
    TRY:
        // Use secure image library to parse
        image = image_library.decode(file_content)

        // Check for reasonable dimensions (anti-DoS)
        IF image.width > 10000 OR image.height > 10000:
            RETURN FALSE
        END IF

        // Check pixel count (decompression bomb protection)
        IF image.width * image.height > 100000000:  // 100 megapixels
            RETURN FALSE
        END IF

        RETURN TRUE

    CATCH ImageDecodeError:
        RETURN FALSE
    END TRY
END FUNCTION

FUNCTION validate_pdf_safe(file_content):
    TRY:
        pdf = pdf_library.parse(file_content)

        // Check for JavaScript (often used in attacks)
        IF pdf.contains_javascript():
            RETURN FALSE
        END IF

        // Check for embedded files
        IF pdf.has_embedded_files():
            RETURN FALSE
        END IF

        // Check for form actions pointing to URLs
        IF pdf.has_external_actions():
            RETURN FALSE
        END IF

        RETURN TRUE

    CATCH PDFParseError:
        RETURN FALSE
    END TRY
END FUNCTION

FUNCTION validate_office_safe(file_content):
    TRY:
        // Office files are ZIP archives
        archive = zip_library.open(file_content)

        // Check for macro-enabled formats
        FOR entry IN archive.entries():
            IF entry.name.contains("vbaProject") OR entry.name.ends_with(".bin"):
                RETURN FALSE  // Contains macros
            END IF
        END FOR

        RETURN TRUE

    CATCH ZipError:
        RETURN FALSE
    END TRY
END FUNCTION
```

### 10.4 Insecure Temporary File Handling

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Predictable or insecure temp files
// ========================================

// Mistake 1: Predictable filename
FUNCTION create_temp_bad_predictable(data):
    // VULNERABLE: Attacker can predict and pre-create file
    temp_path = "/tmp/myapp_" + current_user.id + ".tmp"

    // Race condition: attacker creates symlink before this
    write_file(temp_path, data)

    RETURN temp_path
END FUNCTION

// Mistake 2: World-readable permissions
FUNCTION create_temp_bad_permissions(data):
    temp_path = "/tmp/myapp_" + random_string(8) + ".tmp"

    // VULNERABLE: Default permissions may be world-readable (0644)
    write_file(temp_path, data)  // Other users can read

    RETURN temp_path
END FUNCTION

// Mistake 3: Not cleaning up
FUNCTION process_upload_bad_cleanup(uploaded_data):
    temp_path = "/tmp/upload_" + generate_uuid()
    write_file(temp_path, uploaded_data)

    TRY:
        result = process_file(temp_path)
        // VULNERABLE: Temp file remains on disk if exception occurs elsewhere
        RETURN result
    CATCH Error as e:
        // Temp file leaked!
        THROW e
    END TRY
END FUNCTION

// Mistake 4: Using system temp without isolation
FUNCTION create_temp_bad_shared(data):
    // VULNERABLE: Shared /tmp can be accessed by other users/processes
    temp_path = temp_directory() + "/" + random_string(8)
    write_file(temp_path, data)
    RETURN temp_path
END FUNCTION

// ========================================
// GOOD: Secure temporary file handling
// ========================================

// Use language's secure temp file creation
FUNCTION create_temp_secure(data, suffix=".tmp"):
    // mkstemp equivalent: creates file with random name and 0600 permissions
    temp_file = create_secure_temp_file(
        prefix="myapp_",
        suffix=suffix,
        dir="/var/app/tmp"  // App-specific temp directory
    )

    // Write data to already-open file handle (no race condition)
    temp_file.write(data)
    temp_file.flush()

    RETURN temp_file
END FUNCTION

// Process with guaranteed cleanup
FUNCTION process_upload_secure(uploaded_data):
    temp_file = NULL

    TRY:
        // Create secure temp file
        temp_file = create_secure_temp_file(
            prefix="upload_",
            suffix=get_safe_extension(uploaded_data.filename),
            dir=APPLICATION_TEMP_DIR
        )

        // Write with explicit permissions
        temp_file.write(uploaded_data.content)
        temp_file.flush()

        // Process the file
        result = process_file(temp_file.path)

        RETURN result

    FINALLY:
        // Always clean up, even on exception
        IF temp_file IS NOT NULL:
            TRY:
                temp_file.close()
                delete_file(temp_file.path)
            CATCH:
                log.warning("Failed to clean up temp file", {path: temp_file.path})
            END TRY
        END IF
    END TRY
END FUNCTION

// Context manager pattern for automatic cleanup
FUNCTION with_temp_file(data, callback):
    temp_file = create_secure_temp_file(prefix="ctx_")

    TRY:
        temp_file.write(data)
        temp_file.flush()

        RETURN callback(temp_file.path)

    FINALLY:
        temp_file.close()
        secure_delete(temp_file.path)  // Overwrite before delete for sensitive data
    END TRY
END FUNCTION

// Usage:
result = with_temp_file(sensitive_data, FUNCTION(path):
    RETURN external_processor.process(path)
END FUNCTION)

// Secure temp directory per-request
FUNCTION create_temp_directory_secure():
    // Create directory with random name and 0700 permissions
    temp_dir = create_secure_temp_directory(
        prefix="session_",
        dir=APPLICATION_TEMP_DIR
    )

    // Set restrictive permissions
    set_permissions(temp_dir, 0o700)

    RETURN temp_dir
END FUNCTION

// Application startup: ensure temp directory security
FUNCTION initialize_temp_directory():
    temp_dir = APPLICATION_TEMP_DIR

    // Create if doesn't exist
    IF NOT directory_exists(temp_dir):
        create_directory(temp_dir, permissions=0o700)
    END IF

    // Verify permissions
    current_perms = get_permissions(temp_dir)
    IF current_perms != 0o700:
        set_permissions(temp_dir, 0o700)
    END IF

    // Verify ownership
    IF get_owner(temp_dir) != get_current_user():
        THROW SecurityError("Temp directory has incorrect ownership")
    END IF

    // Clean up old temp files on startup
    cleanup_old_temp_files(temp_dir, max_age_hours=24)
END FUNCTION

// Secure delete for sensitive data
FUNCTION secure_delete(file_path):
    IF file_exists(file_path):
        // Overwrite with random data before deletion
        file_size = get_file_size(file_path)
        random_data = crypto.random_bytes(file_size)
        write_file(file_path, random_data)
        sync_to_disk(file_path)

        // Now delete
        delete_file(file_path)
    END IF
END FUNCTION
```

### 10.5 Symlink Vulnerabilities

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Following symlinks without validation
// ========================================
FUNCTION read_user_file_vulnerable(user_id, filename):
    user_dir = "/var/app/users/" + user_id
    file_path = user_dir + "/" + filename

    // VULNERABLE: If filename is symlink to /etc/passwd, reads it
    IF file_exists(file_path):
        RETURN read_file(file_path)
    END IF

    RETURN NULL
END FUNCTION

FUNCTION delete_file_vulnerable(user_id, filename):
    user_dir = "/var/app/users/" + user_id
    file_path = user_dir + "/" + filename

    // VULNERABLE: Attacker creates symlink to critical file
    // Symlink: /var/app/users/123/data -> /etc/passwd
    // delete_file follows the symlink and deletes /etc/passwd
    delete_file(file_path)
END FUNCTION

// TOCTOU (Time of Check to Time of Use) vulnerability
FUNCTION process_file_toctou(file_path):
    // Check if file is safe
    IF is_symlink(file_path):
        THROW SecurityError("Symlinks not allowed")
    END IF

    // VULNERABLE: Race condition between check and use
    // Attacker replaces regular file with symlink here

    // Process the file (now following attacker's symlink)
    content = read_file(file_path)
    RETURN process_content(content)
END FUNCTION

// ========================================
// GOOD: Safe symlink handling
// ========================================

// Option 1: Reject symlinks entirely
FUNCTION read_user_file_no_symlinks(user_id, filename):
    user_dir = "/var/app/users/" + user_id

    // Validate filename
    IF NOT is_safe_filename(filename):
        THROW ValidationError("Invalid filename")
    END IF

    file_path = join_path(user_dir, filename)

    // Use lstat to check WITHOUT following symlinks
    file_stat = lstat(file_path)  // NOT stat()

    IF file_stat IS NULL:
        THROW NotFoundError("File not found")
    END IF

    // Reject if symlink
    IF file_stat.is_symlink:
        log.security("Symlink access blocked", {path: file_path})
        THROW SecurityError("Access denied")
    END IF

    // Reject if not regular file
    IF NOT file_stat.is_regular_file:
        THROW ValidationError("Not a regular file")
    END IF

    // Use O_NOFOLLOW flag when opening
    file_handle = open_file(file_path, flags=O_RDONLY | O_NOFOLLOW)
    content = file_handle.read()
    file_handle.close()

    RETURN content
END FUNCTION

// Option 2: Resolve and validate path before access
FUNCTION read_file_resolved(base_dir, relative_path):
    // Get the real path resolving all symlinks
    requested_path = join_path(base_dir, relative_path)
    real_path = realpath(requested_path)

    // Verify real path is within allowed base directory
    real_base = realpath(base_dir)

    IF NOT real_path.starts_with(real_base + "/"):
        log.security("Path escape via symlink", {
            requested: requested_path,
            resolved: real_path,
            base: real_base
        })
        THROW SecurityError("Access denied")
    END IF

    RETURN read_file(real_path)
END FUNCTION

// Option 3: Atomic operations to prevent TOCTOU
FUNCTION process_file_atomic(file_path):
    // Open with O_NOFOLLOW - fails if symlink
    TRY:
        file_handle = open_file(file_path, flags=O_RDONLY | O_NOFOLLOW)
    CATCH SymlinkError:
        THROW SecurityError("Symlinks not allowed")
    END TRY

    // fstat the open handle, not the path (prevents TOCTOU)
    file_stat = fstat(file_handle)

    // Verify it's still a regular file
    IF NOT file_stat.is_regular_file:
        file_handle.close()
        THROW ValidationError("Not a regular file")
    END IF

    // Read from the verified handle
    content = file_handle.read()
    file_handle.close()

    RETURN process_content(content)
END FUNCTION

// Safe file writing with symlink protection
FUNCTION write_file_safe(directory, filename, content):
    // Validate filename
    IF NOT is_safe_filename(filename):
        THROW ValidationError("Invalid filename")
    END IF

    file_path = join_path(directory, filename)

    // Check if path already exists
    existing_stat = lstat(file_path)

    IF existing_stat IS NOT NULL:
        IF existing_stat.is_symlink:
            THROW SecurityError("Cannot overwrite symlink")
        END IF
    END IF

    // Open with O_CREAT | O_EXCL to fail if exists (then retry with O_TRUNC)
    // Or use O_NOFOLLOW if supported for writing
    TRY:
        // Write to temp file first, then atomic rename
        temp_path = join_path(directory, "." + generate_uuid() + ".tmp")

        file_handle = open_file(temp_path,
            flags=O_WRONLY | O_CREAT | O_EXCL,
            permissions=0o644
        )
        file_handle.write(content)
        file_handle.flush()
        file_handle.close()

        // Atomic rename (on same filesystem)
        rename_file(temp_path, file_path)

    CATCH FileExistsError:
        // Handle race condition
        THROW ConcurrencyError("File creation conflict")
    END TRY
END FUNCTION

// Directory traversal with symlink safety
FUNCTION list_directory_safe(dir_path):
    real_dir = realpath(dir_path)
    entries = []

    FOR entry IN list_directory(real_dir):
        entry_path = join_path(real_dir, entry.name)
        entry_stat = lstat(entry_path)  // Don't follow symlinks

        entry_info = {
            name: entry.name,
            is_file: entry_stat.is_regular_file,
            is_dir: entry_stat.is_directory,
            is_symlink: entry_stat.is_symlink,
            size: entry_stat.size IF entry_stat.is_regular_file ELSE 0
        }

        // Optionally resolve symlink target for display
        IF entry_stat.is_symlink:
            entry_info.symlink_target = readlink(entry_path)
            // Check if symlink points outside directory
            real_target = realpath(entry_path)
            entry_info.safe = real_target.starts_with(real_dir + "/")
        END IF

        entries.append(entry_info)
    END FOR

    RETURN entries
END FUNCTION
```

### 10.6 Unsafe File Permissions

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Overly permissive file permissions
// ========================================

// Mistake 1: World-readable sensitive files
FUNCTION save_config_bad(config_data):
    // VULNERABLE: Default umask may create 0644 (world-readable)
    write_file("/etc/myapp/config.json", json_encode(config_data))
    // Config contains database passwords, API keys, etc.
END FUNCTION

// Mistake 2: World-writable files
FUNCTION create_log_bad():
    log_path = "/var/log/myapp/app.log"

    // VULNERABLE: 0666 allows any user to modify logs
    write_file(log_path, "", permissions=0o666)
END FUNCTION

// Mistake 3: Executable when shouldn't be
FUNCTION save_upload_bad(content, filename):
    path = "/var/app/uploads/" + filename

    // VULNERABLE: 0755 makes file executable
    write_file(path, content, permissions=0o755)
    // Attacker uploads shell script and executes it
END FUNCTION

// Mistake 4: Directory permissions too open
FUNCTION create_user_dir_bad(user_id):
    dir_path = "/var/app/users/" + user_id

    // VULNERABLE: 0777 allows anyone to read/write/traverse
    create_directory(dir_path, permissions=0o777)
END FUNCTION

// Mistake 5: Not checking permissions on read
FUNCTION load_config_bad():
    config_path = "/etc/myapp/secrets.json"

    // VULNERABLE: Loads config without verifying it hasn't been tampered
    RETURN json_decode(read_file(config_path))
END FUNCTION

// ========================================
// GOOD: Secure file permissions
// ========================================

// Permission constants
CONSTANT PERM_OWNER_ONLY = 0o600        // -rw-------
CONSTANT PERM_OWNER_READ_ONLY = 0o400   // -r--------
CONSTANT PERM_STANDARD_FILE = 0o644     // -rw-r--r--
CONSTANT PERM_PRIVATE_DIR = 0o700       // drwx------
CONSTANT PERM_STANDARD_DIR = 0o755      // drwxr-xr-x

FUNCTION save_sensitive_config(config_data):
    config_path = "/etc/myapp/secrets.json"

    // Set restrictive umask for this operation
    old_umask = set_umask(0o077)

    TRY:
        // Write to temp file first
        temp_path = config_path + ".tmp"
        write_file(temp_path, json_encode(config_data))

        // Explicitly set permissions (don't rely on umask)
        set_permissions(temp_path, PERM_OWNER_ONLY)

        // Set ownership to service account
        set_owner(temp_path, "myapp", "myapp")

        // Atomic rename
        rename_file(temp_path, config_path)

    FINALLY:
        // Restore umask
        set_umask(old_umask)
    END TRY
END FUNCTION

FUNCTION create_log_secure():
    log_dir = "/var/log/myapp"
    log_path = log_dir + "/app.log"

    // Ensure directory exists with correct permissions
    IF NOT directory_exists(log_dir):
        create_directory(log_dir, permissions=PERM_STANDARD_DIR)
        set_owner(log_dir, "myapp", "myapp")
    END IF

    // Create log file with appropriate permissions
    // 0640 = owner read/write, group read, others none
    IF NOT file_exists(log_path):
        write_file(log_path, "", permissions=0o640)
        set_owner(log_path, "myapp", "adm")  // adm group can read logs
    END IF
END FUNCTION

FUNCTION save_upload_secure(content, filename, user_id):
    uploads_dir = "/var/app/uploads"
    user_dir = join_path(uploads_dir, user_id)

    // Ensure user directory exists
    IF NOT directory_exists(user_dir):
        create_directory(user_dir, permissions=PERM_PRIVATE_DIR)
    END IF

    // Generate safe filename
    safe_name = generate_uuid() + get_safe_extension(filename)
    file_path = join_path(user_dir, safe_name)

    // Save with NO execute permission, owner read/write only
    write_file(file_path, content, permissions=PERM_OWNER_ONLY)

    RETURN file_path
END FUNCTION

FUNCTION load_config_secure(config_path):
    // Verify file exists
    IF NOT file_exists(config_path):
        THROW ConfigError("Config file not found")
    END IF

    // Check permissions before loading
    file_stat = stat(config_path)

    // Reject if world-readable or world-writable
    IF file_stat.mode & 0o004:  // World readable
        THROW SecurityError("Config file is world-readable")
    END IF

    IF file_stat.mode & 0o002:  // World writable
        THROW SecurityError("Config file is world-writable")
    END IF

    // Verify ownership
    expected_owner = get_service_user()
    IF file_stat.owner != expected_owner:
        THROW SecurityError("Config file has incorrect ownership")
    END IF

    // Safe to load
    RETURN json_decode(read_file(config_path))
END FUNCTION

// Verify and fix permissions on startup
FUNCTION verify_file_permissions():
    critical_files = [
        {path: "/etc/myapp/secrets.json", expected: 0o600, type: "file"},
        {path: "/etc/myapp", expected: 0o700, type: "directory"},
        {path: "/var/app/private", expected: 0o700, type: "directory"},
        {path: "/var/app/uploads", expected: 0o755, type: "directory"}
    ]

    FOR item IN critical_files:
        IF NOT exists(item.path):
            log.warning("Missing path", {path: item.path})
            CONTINUE
        END IF

        current_stat = stat(item.path)
        current_mode = current_stat.mode & 0o777  // Permission bits only

        IF current_mode != item.expected:
            log.warning("Fixing permissions", {
                path: item.path,
                current: format_octal(current_mode),
                expected: format_octal(item.expected)
            })
            set_permissions(item.path, item.expected)
        END IF

        // Check for world-writable
        IF current_mode & 0o002:
            log.error("World-writable file detected", {path: item.path})
            THROW SecurityError("Critical file is world-writable: " + item.path)
        END IF
    END FOR

    log.info("File permissions verified")
END FUNCTION

// Secure file copy
FUNCTION copy_file_secure(source, destination, preserve_permissions=FALSE):
    // Read source
    source_stat = stat(source)

    IF source_stat.is_symlink:
        THROW SecurityError("Cannot copy symlinks")
    END IF

    content = read_file(source)

    // Determine permissions for destination
    IF preserve_permissions:
        dest_perms = source_stat.mode & 0o777
        // But never preserve world-writable
        dest_perms = dest_perms & ~0o002
    ELSE:
        // Default to secure permissions
        dest_perms = PERM_OWNER_ONLY
    END IF

    // Write with explicit permissions
    write_file(destination, content, permissions=dest_perms)
END FUNCTION
```

---
