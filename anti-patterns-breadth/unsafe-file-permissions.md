# Unsafe File Permissions


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
