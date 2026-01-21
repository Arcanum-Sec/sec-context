# Improper Error Handling in APIs


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Error messages revealing internal details
// ========================================

// Exposes database structure
@route("/api/users/{id}")
FUNCTION get_user_bad_errors(request, id):
    TRY:
        user = database.get_user(id)
        RETURN response(200, user)
    CATCH DatabaseError as e:
        // VULNERABLE: Exposes table names, query structure
        RETURN response(500, {
            error: "Database error",
            query: "SELECT * FROM users WHERE id = " + id,
            message: e.message,  // "Column 'password_hash' cannot be null"
            stack_trace: e.stack_trace
        })
    END TRY
END FUNCTION

// Reveals filesystem paths
@route("/api/files/{file_id}")
FUNCTION get_file_bad(request, file_id):
    TRY:
        content = read_file("/var/app/uploads/" + file_id)
        RETURN response(200, content)
    CATCH FileNotFoundError as e:
        // VULNERABLE: Exposes server filesystem structure
        RETURN response(404, {
            error: "File not found: /var/app/uploads/" + file_id,
            available_files: list_directory("/var/app/uploads/")
        })
    END TRY
END FUNCTION

// Authentication timing oracle
@route("/api/auth/login")
FUNCTION login_timing_oracle(request):
    user = database.find_by_email(request.body.email)

    IF user IS NULL:
        // Returns immediately - attacker knows email doesn't exist
        RETURN response(401, {error: "User not found"})
    END IF

    IF NOT verify_password(request.body.password, user.password_hash):
        // Takes longer due to password verification
        RETURN response(401, {error: "Invalid password"})
    END IF

    RETURN response(200, {token: create_token(user)})
END FUNCTION

// Inconsistent error format breaks security tools
@route("/api/orders")
FUNCTION create_order_inconsistent(request):
    IF NOT valid_items(request.body.items):
        RETURN response(400, "Invalid items")  // String
    END IF

    IF NOT has_stock(request.body.items):
        RETURN response(400, {msg: "Out of stock"})  // Different key
    END IF

    IF payment_failed:
        RETURN {status: "error", reason: "Payment failed"}  // No status code
    END IF
END FUNCTION

// ========================================
// GOOD: Secure, consistent error handling
// ========================================

// Standardized error response class
CLASS APIError:
    status: Integer
    code: String  // Machine-readable error code
    message: String  // User-friendly message
    request_id: String  // For support/debugging

    FUNCTION to_response():
        RETURN response(this.status, {
            error: {
                code: this.code,
                message: this.message,
                request_id: this.request_id
            }
        })
    END FUNCTION
END CLASS

// Error codes mapping (documented in API docs)
ERROR_CODES = {
    "AUTH_REQUIRED": {status: 401, message: "Authentication required"},
    "AUTH_INVALID": {status: 401, message: "Invalid credentials"},
    "FORBIDDEN": {status: 403, message: "Access denied"},
    "NOT_FOUND": {status: 404, message: "Resource not found"},
    "VALIDATION_ERROR": {status: 400, message: "Invalid request data"},
    "RATE_LIMITED": {status: 429, message: "Too many requests"},
    "INTERNAL_ERROR": {status: 500, message: "An unexpected error occurred"}
}

// Global error handler
FUNCTION global_error_handler(error, request):
    request_id = generate_request_id()

    // Log full error details internally
    log.error("Request failed", {
        request_id: request_id,
        path: request.path,
        method: request.method,
        user_id: request.user.id IF request.user ELSE NULL,
        error_type: error.type,
        error_message: error.message,
        stack_trace: error.stack_trace,
        request_body: redact_sensitive(request.body)
    })

    // Return sanitized error to client
    IF error IS APIError:
        error.request_id = request_id
        RETURN error.to_response()
    ELSE IF error IS ValidationError:
        RETURN APIError(
            status=400,
            code="VALIDATION_ERROR",
            message=error.user_message,  // Safe message
            request_id=request_id
        ).to_response()
    ELSE:
        // Generic error - never expose internal details
        RETURN APIError(
            status=500,
            code="INTERNAL_ERROR",
            message="An unexpected error occurred. Reference: " + request_id,
            request_id=request_id
        ).to_response()
    END IF
END FUNCTION

// Secure authentication with constant-time comparison
@route("/api/auth/login")
FUNCTION login_secure_errors(request):
    email = request.body.email
    password = request.body.password

    user = database.find_by_email(email)

    // Always perform password check to prevent timing oracle
    IF user IS NOT NULL:
        password_valid = constant_time_compare(
            hash_password(password, user.salt),
            user.password_hash
        )
    ELSE:
        // Fake password check to maintain consistent timing
        constant_time_compare(
            hash_password(password, generate_fake_salt()),
            DUMMY_HASH
        )
        password_valid = FALSE
    END IF

    IF NOT password_valid:
        // Same error message whether user exists or not
        log.security("Failed login attempt", {
            email_hash: sha256(email),  // Don't log raw email
            ip: request.client_ip
        })
        RETURN APIError(
            status=401,
            code="AUTH_INVALID",
            message="Invalid email or password"
        ).to_response()
    END IF

    RETURN response(200, {token: create_token(user)})
END FUNCTION

// File operations without path disclosure
@route("/api/files/{file_id}")
FUNCTION get_file_secure(request, file_id):
    // Validate file_id format (UUID only)
    IF NOT is_valid_uuid(file_id):
        RETURN APIError(
            status=400,
            code="VALIDATION_ERROR",
            message="Invalid file ID format"
        ).to_response()
    END IF

    // Look up file in database (not filesystem path)
    file_record = database.get_file(file_id)

    IF file_record IS NULL:
        RETURN APIError(
            status=404,
            code="NOT_FOUND",
            message="File not found"
        ).to_response()
    END IF

    // Check ownership
    IF file_record.owner_id != request.user.id:
        // Same error as not found - don't reveal existence
        RETURN APIError(
            status=404,
            code="NOT_FOUND",
            message="File not found"
        ).to_response()
    END IF

    TRY:
        content = storage.read(file_record.storage_key)
        RETURN response(200, content, headers={
            "Content-Type": file_record.mime_type
        })
    CATCH StorageError as e:
        log.error("File read failed", {
            file_id: file_id,
            storage_key: file_record.storage_key,
            error: e.message
        })
        RETURN APIError(
            status=500,
            code="INTERNAL_ERROR",
            message="Unable to retrieve file"
        ).to_response()
    END TRY
END FUNCTION

// Validation errors without revealing schema
FUNCTION validate_request(schema, data):
    errors = []

    FOR field, rules IN schema:
        IF field NOT IN data AND rules.required:
            errors.append({
                field: field,
                message: "This field is required"
            })
        ELSE IF field IN data:
            value = data[field]

            // Type validation
            IF NOT check_type(value, rules.type):
                errors.append({
                    field: field,
                    message: "Invalid value"  // Don't say "expected integer"
                })
            // Length validation
            ELSE IF rules.max_length AND len(value) > rules.max_length:
                errors.append({
                    field: field,
                    message: "Value too long"
                })
            END IF
        END IF
    END FOR

    IF errors.length > 0:
        THROW ValidationError(errors)
    END IF
END FUNCTION
```

---
