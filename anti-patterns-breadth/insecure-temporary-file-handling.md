# Insecure Temporary File Handling


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
