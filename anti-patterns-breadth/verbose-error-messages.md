# Verbose Error Messages Exposing Internals


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Detailed errors exposed to users
// ========================================

FUNCTION handle_request(request):
    TRY:
        result = process_request(request)
        RETURN success_response(result)

    CATCH DatabaseError as e:
        // Exposes: database type, table names, query structure
        RETURN error_response("Database error: " + e.full_message)

    CATCH FileNotFoundError as e:
        // Exposes: full file system path, reveals server structure
        RETURN error_response("File not found: " + e.path)

    CATCH Exception as e:
        // Exposes: full stack trace with file paths, line numbers, code snippets
        RETURN error_response(e.stack_trace)
    END TRY
END FUNCTION

// Mistake: SQL error messages in API responses
FUNCTION get_user(user_id):
    TRY:
        RETURN database.query("SELECT * FROM users WHERE id = ?", [user_id])
    CATCH SQLException as e:
        // Attacker learns: MySQL 8.0.35, table 'users', column names
        RETURN {"error": "MySQL Error 1054: Unknown column 'passwrd' in 'users'"}
    END TRY
END FUNCTION

// ========================================
// GOOD: Generic external errors, detailed internal logging
// ========================================

FUNCTION handle_request(request):
    request_id = generate_request_id()

    TRY:
        result = process_request(request)
        RETURN success_response(result)

    CATCH DatabaseError as e:
        // Log full details internally with request ID for debugging
        log.error("Database error", {
            request_id: request_id,
            error: e.full_message,
            query: e.query,
            stack: e.stack_trace
        })

        // Return generic message with reference ID
        RETURN error_response({
            message: "A database error occurred",
            reference_id: request_id,
            status: 500
        })

    CATCH ValidationError as e:
        // Validation errors can be specific (user input related)
        RETURN error_response({
            message: e.user_message,  // Pre-sanitized user-facing message
            field: e.field,
            status: 400
        })

    CATCH AuthenticationError as e:
        // Never reveal which part failed (user vs password)
        log.warning("Auth failure", {request_id: request_id, reason: e.reason})

        RETURN error_response({
            message: "Invalid credentials",
            status: 401
        })

    CATCH Exception as e:
        // Catch-all for unexpected errors
        log.error("Unexpected error", {
            request_id: request_id,
            type: e.type,
            message: e.message,
            stack: e.stack_trace
        })

        RETURN error_response({
            message: "An unexpected error occurred",
            reference_id: request_id,
            status: 500
        })
    END TRY
END FUNCTION

// Configure error handling at application level
FUNCTION configure_error_handling():
    IF environment == "production":
        // Disable automatic stack trace exposure
        app.config.propagate_exceptions = FALSE
        app.config.show_exception_details = FALSE

        // Custom error pages without technical details
        app.set_error_handler(404, generic_not_found_page)
        app.set_error_handler(500, generic_error_page)
    END IF
END FUNCTION
```
