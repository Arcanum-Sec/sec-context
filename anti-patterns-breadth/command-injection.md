# Command Injection (Unsanitized Shell Commands)


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Shell command with user input
// ========================================
FUNCTION ping_host(hostname):
    // Vulnerable: User controls shell command
    command = "ping -c 4 " + hostname
    RETURN shell.execute(command)
END FUNCTION

FUNCTION convert_file(input_path, output_format):
    // Vulnerable: Multiple injection points
    command = "convert " + input_path + " output." + output_format
    RETURN shell.execute(command)
END FUNCTION

// Attack: hostname = "google.com; rm -rf /"
// Result: ping -c 4 google.com; rm -rf /
// This executes the ping AND deletes the filesystem

// ========================================
// GOOD: Use argument arrays, avoid shell
// ========================================
FUNCTION ping_host(hostname):
    // Validate input format first
    IF NOT is_valid_hostname(hostname):
        THROW Error("Invalid hostname format")
    END IF

    // Safe: Arguments passed as array, no shell interpolation
    RETURN process.execute(["ping", "-c", "4", hostname], shell=FALSE)
END FUNCTION

FUNCTION convert_file(input_path, output_format):
    // Validate allowed formats
    allowed_formats = ["png", "jpg", "gif", "webp"]
    IF output_format NOT IN allowed_formats:
        THROW Error("Invalid output format")
    END IF

    // Validate path is within allowed directory
    IF NOT path.is_within(input_path, UPLOAD_DIRECTORY):
        THROW Error("Invalid file path")
    END IF

    output_path = path.join(OUTPUT_DIR, "output." + output_format)
    RETURN process.execute(["convert", input_path, output_path], shell=FALSE)
END FUNCTION

// Helper: Validate hostname format
FUNCTION is_valid_hostname(hostname):
    // Only allow alphanumeric, dots, and hyphens
    pattern = "^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$"
    RETURN regex.match(pattern, hostname)
END FUNCTION
```
