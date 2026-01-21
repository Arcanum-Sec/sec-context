# Missing File Type Validation


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
