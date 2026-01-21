# Unrestricted File Uploads


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
