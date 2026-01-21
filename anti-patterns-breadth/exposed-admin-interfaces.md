# Exposed Admin Interfaces


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Admin panel accessible without protection
// ========================================

// Mistake 1: Admin on predictable paths with no extra protection
app.route("/admin", admin_dashboard)
app.route("/admin/users", manage_users)
app.route("/wp-admin", wordpress_admin)     // Default paths are scanned
app.route("/phpmyadmin", database_admin)

// Mistake 2: Admin shares same authentication as user area
FUNCTION admin_dashboard(request):
    user = get_logged_in_user(request)

    IF user AND user.is_admin:
        RETURN render_admin_dashboard()
    END IF

    RETURN redirect("/login")
END FUNCTION

// Mistake 3: Admin interface exposed to internet
// No IP restrictions, no additional authentication factors

// ========================================
// GOOD: Defense in depth for admin interfaces
// ========================================

// Layer 1: Non-predictable path (security through obscurity as one layer, not the only layer)
CONSTANT ADMIN_PATH = get_environment_variable("ADMIN_PATH", "/manage-" + random_string(8))

// Layer 2: IP allowlist for admin access
CONSTANT ADMIN_IP_ALLOWLIST = [
    "10.0.0.0/8",       // Internal network
    "192.168.1.0/24",   // Office network
    // Or use VPN: require VPN connection to access admin
]

FUNCTION admin_ip_check_middleware(request, next):
    client_ip = get_client_ip(request)

    IF NOT ip_in_ranges(client_ip, ADMIN_IP_ALLOWLIST):
        log.warning("Admin access attempt from unauthorized IP", {
            ip: client_ip,
            path: request.path
        })
        RETURN forbidden_response("Access denied")
    END IF

    RETURN next()
END FUNCTION

// Layer 3: Require re-authentication for admin
FUNCTION admin_auth_middleware(request, next):
    user = get_logged_in_user(request)

    IF NOT user OR NOT user.is_admin:
        RETURN redirect("/login")
    END IF

    // Require recent authentication for admin actions
    session = get_session(request)
    IF current_time() - session.last_auth_time > 900:  // 15 minutes
        RETURN redirect("/admin/reauthenticate?next=" + request.path)
    END IF

    // Require MFA for admin access
    IF NOT session.mfa_verified:
        RETURN redirect("/admin/mfa-verify?next=" + request.path)
    END IF

    RETURN next()
END FUNCTION

// Layer 4: Additional security headers for admin
FUNCTION admin_security_headers(response):
    // More restrictive CSP for admin
    response.set_header("Content-Security-Policy",
        "default-src 'self'; script-src 'self'; frame-ancestors 'none'")

    // Prevent caching of admin pages
    response.set_header("Cache-Control", "no-store, no-cache, must-revalidate")
    response.set_header("Pragma", "no-cache")

    RETURN response
END FUNCTION

// Layer 5: Comprehensive audit logging
FUNCTION admin_audit_middleware(request, next):
    response = next()

    log.audit("admin_action", {
        user_id: request.user.id,
        username: request.user.username,
        action: request.method + " " + request.path,
        ip: get_client_ip(request),
        user_agent: request.get_header("User-Agent"),
        timestamp: current_timestamp(),
        status: response.status_code
    })

    RETURN response
END FUNCTION

// Register admin routes with all middleware
app.group(ADMIN_PATH, [
    admin_ip_check_middleware,
    admin_auth_middleware,
    admin_audit_middleware
], FUNCTION():
    app.route("/", admin_dashboard)
    app.route("/users", manage_users)
    app.route("/settings", admin_settings)
END FUNCTION)

// Consider separate admin application entirely
// Run admin on different port, internal network only
// admin-internal.example.com (not accessible from internet)
```
