# Symlink Vulnerabilities


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
