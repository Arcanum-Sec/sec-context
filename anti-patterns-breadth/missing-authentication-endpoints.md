# Missing Authentication on Endpoints


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Unprotected API endpoints
// ========================================

// No authentication - anyone can access
@route("/api/users")
FUNCTION get_all_users():
    RETURN database.query("SELECT * FROM users")
END FUNCTION

// Admin functionality without auth check
@route("/api/admin/delete-user/{id}")
FUNCTION admin_delete_user(id):
    database.execute("DELETE FROM users WHERE id = ?", [id])
    RETURN {status: "deleted"}
END FUNCTION

// Sensitive data exposed without auth
@route("/api/orders/{order_id}")
FUNCTION get_order(order_id):
    RETURN database.get_order(order_id)
END FUNCTION

// "Security through obscurity" - hidden endpoint still accessible
@route("/api/internal/debug-info")
FUNCTION get_debug_info():
    RETURN {
        database_connection: DB_STRING,
        api_keys: LOADED_KEYS,
        server_config: CONFIG
    }
END FUNCTION

// ========================================
// GOOD: Authentication on all protected endpoints
// ========================================

// Middleware to enforce authentication
FUNCTION require_auth(handler):
    RETURN FUNCTION wrapped(request):
        token = request.headers.get("Authorization")

        IF token IS NULL:
            RETURN response(401, {error: "Authentication required"})
        END IF

        user = verify_token(token)
        IF user IS NULL:
            RETURN response(401, {error: "Invalid or expired token"})
        END IF

        request.user = user
        RETURN handler(request)
    END FUNCTION
END FUNCTION

// Middleware for admin-only routes
FUNCTION require_admin(handler):
    RETURN require_auth(FUNCTION wrapped(request):
        IF request.user.role != "admin":
            log.security("Unauthorized admin access attempt", {
                user_id: request.user.id,
                endpoint: request.path
            })
            RETURN response(403, {error: "Admin access required"})
        END IF

        RETURN handler(request)
    END FUNCTION)
END FUNCTION

// Protected endpoints with proper auth
@route("/api/users")
@require_admin  // Only admins can list all users
FUNCTION get_all_users(request):
    // Return only non-sensitive fields
    users = database.query("SELECT id, name, email, created_at FROM users")
    RETURN response(200, {users: users})
END FUNCTION

// Admin endpoint with proper protection
@route("/api/admin/delete-user/{id}")
@require_admin
FUNCTION admin_delete_user(request, id):
    // Audit log before action
    log.audit("User deletion", {
        admin_id: request.user.id,
        target_user_id: id
    })

    database.soft_delete("users", id)  // Soft delete for audit trail
    RETURN response(200, {status: "deleted"})
END FUNCTION

// Never expose internal/debug endpoints in production
IF environment != "production":
    @route("/api/internal/debug-info")
    @require_admin
    FUNCTION get_debug_info(request):
        RETURN {config: get_safe_config()}  // Sanitized config only
    END FUNCTION
END IF

// Default deny - explicitly define allowed public endpoints
PUBLIC_ENDPOINTS = [
    "/api/auth/login",
    "/api/auth/register",
    "/api/public/status",
    "/api/public/docs"
]

FUNCTION global_auth_middleware(request):
    IF request.path IN PUBLIC_ENDPOINTS:
        RETURN next(request)
    END IF

    // All other routes require authentication by default
    RETURN require_auth(next)(request)
END FUNCTION
```
