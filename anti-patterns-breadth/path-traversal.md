# Path Traversal Vulnerabilities


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
