# Missing Canonicalization


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Validation without canonicalization
// ========================================
FUNCTION check_path_unsafe(requested_path):
    // Vulnerable: Path not canonicalized before validation
    IF requested_path.starts_with("/uploads/"):
        // Bypass: "../../../etc/passwd" doesn't start with /uploads/
        // But resolves to outside the directory!
        RETURN read_file(requested_path)
    END IF
    THROW AccessDenied("Invalid path")
END FUNCTION

FUNCTION check_url_unsafe(url):
    // Vulnerable: URL manipulation bypasses check
    // Blocked: "http://internal-server"
    // Bypass: "http://internal-server%00.example.com"
    // Bypass: "http://0x7f000001" (127.0.0.1 in hex)
    // Bypass: "http://localhost" vs "http://LOCALHOST" vs "http://127.0.0.1"

    IF url.contains("internal-server"):
        THROW AccessDenied("Internal URLs not allowed")
    END IF

    RETURN http.get(url)
END FUNCTION

FUNCTION validate_filename_unsafe(filename):
    // Vulnerable: Unicode normalization bypass
    // Blocked: "config.php"
    // Bypass: "config.php" with full-width characters (ｃｏｎｆｉｇ.php)
    // Bypass: "config.php\x00.txt" (null byte injection)

    IF filename.ends_with(".php"):
        THROW AccessDenied("PHP files not allowed")
    END IF

    save_file(filename)
END FUNCTION

FUNCTION check_html_unsafe(content):
    // Vulnerable: Case-sensitive blacklist
    // Blocked: "<script>"
    // Bypass: "<SCRIPT>", "<ScRiPt>", "<script ", etc.

    IF content.contains("<script>"):
        THROW AccessDenied("Scripts not allowed")
    END IF

    RETURN content
END FUNCTION

// ========================================
// GOOD: Canonicalize before validation
// ========================================
FUNCTION check_path_safe(requested_path):
    // Canonicalize path first
    base_path = path.resolve("/uploads")
    canonical_path = path.resolve(requested_path)

    // Verify canonical path is within allowed directory
    IF NOT canonical_path.starts_with(base_path):
        log.warning("Path traversal attempt", {
            requested: requested_path,
            resolved: canonical_path
        })
        THROW AccessDenied("Invalid path")
    END IF

    // Additional: Verify path doesn't contain null bytes
    IF requested_path.contains("\x00"):
        THROW AccessDenied("Invalid path characters")
    END IF

    RETURN read_file(canonical_path)
END FUNCTION

FUNCTION check_url_safe(url):
    // Parse and canonicalize URL
    TRY:
        parsed = url_parser.parse(url)
    CATCH ParseError:
        THROW AccessDenied("Invalid URL")
    END TRY

    // Normalize hostname
    host = parsed.hostname.lower()

    // Resolve to IP to catch obfuscation
    TRY:
        resolved_ip = dns.resolve(host)
    CATCH DNSError:
        THROW AccessDenied("Cannot resolve host")
    END TRY

    // Check against blocked IP ranges
    blocked_ranges = [
        "127.0.0.0/8",     // Localhost
        "10.0.0.0/8",      // Private
        "172.16.0.0/12",   // Private
        "192.168.0.0/16",  // Private
        "169.254.0.0/16"   // Link-local
    ]

    FOR range IN blocked_ranges:
        IF ip_in_range(resolved_ip, range):
            THROW AccessDenied("Internal addresses not allowed")
        END IF
    END FOR

    // Additional: Block by resolved hostname
    IF host IN BLOCKED_HOSTS:
        THROW AccessDenied("Host not allowed")
    END IF

    RETURN http.get(url)
END FUNCTION

FUNCTION validate_filename_safe(filename):
    // Remove null bytes
    clean_name = filename.replace("\x00", "")

    // Normalize Unicode (NFC form)
    normalized = unicode_normalize("NFC", clean_name)

    // Convert to ASCII-safe representation
    ascii_name = transliterate_to_ascii(normalized)

    // Extract actual extension (after normalization)
    extension = path.get_extension(ascii_name).lower()

    // Whitelist allowed extensions
    allowed_extensions = [".jpg", ".png", ".gif", ".pdf", ".txt"]
    IF extension NOT IN allowed_extensions:
        THROW AccessDenied("File type not allowed: " + extension)
    END IF

    // Generate safe filename
    safe_name = uuid() + extension
    save_file(safe_name)
END FUNCTION

FUNCTION sanitize_html_safe(content):
    // Case-insensitive checking
    lower_content = content.lower()

    // Better: Use HTML parser and whitelist approach
    parsed = html_parser.parse(content)

    // Remove all script elements regardless of case
    FOR element IN parsed.find_all("script"):
        element.remove()
    END FOR

    // Remove event handlers
    FOR element IN parsed.find_all():
        FOR attr IN element.attributes:
            IF attr.name.lower().starts_with("on"):
                element.remove_attribute(attr.name)
            END IF
        END FOR
    END FOR

    // Best: Use a sanitization library like DOMPurify
    RETURN DOMPurify.sanitize(content)
END FUNCTION

// Canonicalization order matters:
// 1. Decode (URL decode, Unicode normalize)
// 2. Canonicalize (resolve paths, lowercase hostnames)
// 3. Validate (check against rules)
// 4. Encode for output context (HTML encode, URL encode)
```

---
