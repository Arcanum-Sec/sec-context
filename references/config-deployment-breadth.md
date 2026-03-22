<!-- Source: Arcanum sec-context (https://github.com/arcanum-sec/sec-context), CC BY 4.0, Jason Haddix / Arcanum Information Security -->

## 7. Configuration and Deployment

**CWE References:** CWE-215 (Information Exposure Through Debug Information), CWE-209 (Error Message Exposure), CWE-16 (Configuration), CWE-346 (Origin Validation Error), CWE-1188 (Insecure Default Initialization)
**Severity:** High | **Related:** [[Configuration-Issues]]

> **Risk:** Misconfigured deployments expose sensitive information, enable attacks, and provide attackers with detailed system internals. Debug modes, verbose errors, and default credentials are among the most common causes of data breaches. AI-generated code often includes development-only settings unsuitable for production.

### 7.1 Debug Mode in Production

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Debug mode enabled in production
// ========================================

// Mistake 1: Hardcoded debug flag
CONSTANT DEBUG = TRUE  // Never changes between environments

FUNCTION start_application():
    app.config.debug = TRUE
    app.config.show_stack_traces = TRUE
    app.config.enable_profiler = TRUE

    // Exposes: full stack traces, variable values, file paths, database queries
    app.run()
END FUNCTION

// Mistake 2: Debug routes left enabled
app.route("/debug/env", show_environment_variables)
app.route("/debug/config", show_all_config)
app.route("/debug/sql", run_arbitrary_sql)  // Catastrophic!

// Mistake 3: Development tools in production bundle
// package.json or requirements with dev dependencies in production
// React DevTools, Vue DevTools, Django Debug Toolbar exposed

// ========================================
// GOOD: Environment-based configuration
// ========================================

FUNCTION start_application():
    environment = get_environment_variable("APP_ENV", "production")

    IF environment == "production":
        app.config.debug = FALSE
        app.config.show_stack_traces = FALSE
        app.config.enable_profiler = FALSE

        // Ensure debug routes are not registered
        disable_debug_routes()

    ELSE IF environment == "development":
        // Only enable debug in development
        app.config.debug = TRUE
        register_debug_routes()
    END IF

    app.run()
END FUNCTION

FUNCTION disable_debug_routes():
    // Explicitly remove or disable debug endpoints
    // Better: Don't register them in production at all

    debug_routes = ["/debug/*", "/test/*", "/__debug__/*", "/profiler/*"]
    FOR route IN debug_routes:
        app.remove_route(route)
    END FOR
END FUNCTION

// Build process should exclude dev dependencies
// package.json: use --production flag
// requirements.txt: separate dev-requirements.txt
// Dockerfile: multi-stage build without dev tools
```

### 7.2 Verbose Error Messages Exposing Internals

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

### 7.3 Default Credentials

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Default credentials in code or config
// ========================================

// Mistake 1: Hardcoded default admin account
FUNCTION initialize_database():
    IF NOT user_exists("admin"):
        create_user({
            username: "admin",
            password: "admin",      // First thing attackers try
            role: "administrator"
        })
    END IF
END FUNCTION

// Mistake 2: Default passwords in configuration
config = {
    database: {
        host: "localhost",
        user: "root",
        password: "root"           // Default MySQL credentials
    },
    redis: {
        password: ""               // No password = open to network
    },
    admin_panel: {
        secret_key: "change_me"    // Never changed
    }
}

// Mistake 3: API keys with placeholder values
CONSTANT API_KEY = "YOUR_API_KEY_HERE"  // Developers forget to change
CONSTANT WEBHOOK_SECRET = "test123"

// ========================================
// GOOD: Require explicit configuration, no defaults
// ========================================

FUNCTION initialize_application():
    // Require all sensitive config to be explicitly set
    required_config = [
        "DATABASE_PASSWORD",
        "REDIS_PASSWORD",
        "SECRET_KEY",
        "API_KEY"
    ]

    FOR config_name IN required_config:
        value = get_environment_variable(config_name)

        IF value IS NULL OR value == "":
            THROW ConfigurationError(
                config_name + " must be set in environment"
            )
        END IF

        // Check for common placeholder values
        placeholder_patterns = ["change_me", "your_", "test", "example", "xxx"]
        FOR pattern IN placeholder_patterns:
            IF value.lower().contains(pattern):
                THROW ConfigurationError(
                    config_name + " appears to contain a placeholder value"
                )
            END IF
        END FOR
    END FOR
END FUNCTION

FUNCTION initialize_database():
    // Never create default admin accounts automatically
    // Instead, require explicit admin creation with strong password

    IF NOT admin_exists():
        IF environment == "development":
            log.warning("No admin account exists. Run: create_admin_account command")
        ELSE:
            log.error("No admin account configured for production")
            THROW ConfigurationError("Admin account must be created before deployment")
        END IF
    END IF
END FUNCTION

// First-run setup requires strong credentials
FUNCTION create_initial_admin(username, password):
    // Validate password strength
    IF NOT is_strong_password(password):
        THROW ValidationError("Admin password must meet complexity requirements")
    END IF

    // Hash password properly
    hashed = bcrypt.hash(password, rounds=12)

    create_user({
        username: username,
        password_hash: hashed,
        role: "administrator",
        requires_password_change: TRUE  // Force change on first login
    })
END FUNCTION

// Service accounts should use key-based auth, not passwords
FUNCTION configure_service_connections():
    // Use certificate-based auth for databases where possible
    database.connect({
        ssl_cert: load_file(env.get("DB_CLIENT_CERT")),
        ssl_key: load_file(env.get("DB_CLIENT_KEY")),
        ssl_ca: load_file(env.get("DB_CA_CERT"))
    })
END FUNCTION
```

### 7.4 Insecure CORS Configuration

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Overly permissive CORS settings
// ========================================

// Mistake 1: Allow all origins
app.use_cors({
    origin: "*",                    // Any website can make requests!
    credentials: TRUE               // With user cookies!
})

// Mistake 2: Reflecting Origin header (same as allowing all)
FUNCTION handle_preflight(request):
    origin = request.get_header("Origin")

    response.set_header("Access-Control-Allow-Origin", origin)  // Reflects any origin
    response.set_header("Access-Control-Allow-Credentials", "true")
    RETURN response
END FUNCTION

// Mistake 3: Regex that's too broad
allowed_origin_pattern = /.*\.example\.com$/  // Matches evil-example.com too!
allowed_origin_pattern = /example\.com/        // Matches example.com.evil.com

// Mistake 4: Null origin allowed
IF origin == "null" OR origin IN allowed_origins:
    // "null" origin used by local files, data: URIs - exploitable!
    allow_cors(origin)
END IF

// ========================================
// GOOD: Strict origin allowlist
// ========================================

CONSTANT ALLOWED_ORIGINS = [
    "https://www.example.com",
    "https://app.example.com",
    "https://admin.example.com"
]

// Add development origins only in dev environment
FUNCTION get_allowed_origins():
    origins = ALLOWED_ORIGINS.copy()

    IF environment == "development":
        origins.append("http://localhost:3000")
        origins.append("http://127.0.0.1:3000")
    END IF

    RETURN origins
END FUNCTION

FUNCTION handle_cors(request, response):
    origin = request.get_header("Origin")

    // Strict allowlist check
    IF origin IN get_allowed_origins():
        response.set_header("Access-Control-Allow-Origin", origin)
        response.set_header("Access-Control-Allow-Credentials", "true")
        response.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
        response.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.set_header("Access-Control-Max-Age", "86400")  // Cache preflight
    END IF

    // Vary header for proper caching
    response.set_header("Vary", "Origin")

    RETURN response
END FUNCTION

// For APIs that don't need credentials (truly public)
FUNCTION configure_public_api_cors():
    app.use_cors({
        origin: "*",
        credentials: FALSE,  // No cookies, no problem with wildcard
        methods: ["GET"],    // Read-only
        max_age: 86400
    })
END FUNCTION

// Subdomain matching done safely
FUNCTION is_allowed_subdomain(origin):
    TRY:
        parsed = parse_url(origin)
        host = parsed.hostname.lower()

        // Must use HTTPS in production
        IF environment == "production" AND parsed.scheme != "https":
            RETURN FALSE
        END IF

        // Exact match for apex domain
        IF host == "example.com":
            RETURN TRUE
        END IF

        // Subdomain check - must END with .example.com (not just contain)
        IF host.ends_with(".example.com"):
            // Additional: validate it's a known/expected subdomain
            subdomain = host.replace(".example.com", "")
            IF subdomain IN ["www", "app", "api", "admin"]:
                RETURN TRUE
            END IF
        END IF

        RETURN FALSE
    CATCH:
        RETURN FALSE
    END TRY
END FUNCTION
```

### 7.5 Missing Security Headers

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No security headers configured
// ========================================

FUNCTION send_response(content):
    response = new Response()
    response.body = content
    // No security headers set - browser uses permissive defaults
    RETURN response
END FUNCTION

// Missing headers leave users vulnerable to:
// - Clickjacking (no X-Frame-Options)
// - XSS (no CSP)
// - MIME sniffing attacks (no X-Content-Type-Options)
// - Protocol downgrade (no HSTS)
// - Information leakage (no Referrer-Policy)

// ========================================
// GOOD: Comprehensive security headers
// ========================================

FUNCTION apply_security_headers(response):
    // Prevent clickjacking - page cannot be embedded in frames
    response.set_header("X-Frame-Options", "DENY")
    // Or allow same-origin only: "SAMEORIGIN"

    // Prevent MIME type sniffing
    response.set_header("X-Content-Type-Options", "nosniff")

    // XSS filter (legacy, but still useful for older browsers)
    response.set_header("X-XSS-Protection", "1; mode=block")

    // Control referrer information
    response.set_header("Referrer-Policy", "strict-origin-when-cross-origin")

    // HTTP Strict Transport Security - force HTTPS
    IF environment == "production":
        response.set_header(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload"
        )
    END IF

    // Permissions Policy - disable unnecessary browser features
    response.set_header(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), payment=()"
    )

    // Content Security Policy
    response.set_header(
        "Content-Security-Policy",
        build_csp_header()
    )

    RETURN response
END FUNCTION

FUNCTION build_csp_header():
    // Start restrictive, loosen as needed
    csp_directives = {
        "default-src": "'self'",
        "script-src": "'self'",           // Add 'nonce-xxx' for inline scripts
        "style-src": "'self'",            // Add 'unsafe-inline' only if necessary
        "img-src": "'self' data: https:",
        "font-src": "'self'",
        "connect-src": "'self'",          // API endpoints
        "frame-ancestors": "'none'",       // Prevents framing (like X-Frame-Options)
        "form-action": "'self'",           // Form submissions
        "base-uri": "'self'",              // Prevent base tag injection
        "object-src": "'none'",            // No Flash/Java plugins
        "upgrade-insecure-requests": ""    // Auto-upgrade HTTP to HTTPS
    }

    // For production, add reporting
    IF environment == "production":
        csp_directives["report-uri"] = "/csp-violation-report"
        csp_directives["report-to"] = "csp-endpoint"
    END IF

    // Build header string
    parts = []
    FOR directive, value IN csp_directives:
        IF value != "":
            parts.append(directive + " " + value)
        ELSE:
            parts.append(directive)
        END IF
    END FOR

    RETURN parts.join("; ")
END FUNCTION

// Apply to all responses via middleware
app.use_middleware(FUNCTION(request, response, next):
    next()
    apply_security_headers(response)
END FUNCTION)

// For APIs, simpler headers may suffice
FUNCTION apply_api_security_headers(response):
    response.set_header("X-Content-Type-Options", "nosniff")
    response.set_header("X-Frame-Options", "DENY")
    response.set_header("Cache-Control", "no-store")  // Don't cache sensitive data

    IF environment == "production":
        response.set_header(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains"
        )
    END IF

    RETURN response
END FUNCTION
```

### 7.6 Exposed Admin Interfaces

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

### 7.7 Unnecessary Open Ports and Services

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Unnecessary services and ports exposed
// ========================================

// Mistake 1: Debug/development ports left open in production
app.listen(3000)                    // Main app
debug_server.listen(9229)           // Node.js debugger - remote code execution!
profiler.listen(8888)               // Profiler endpoint
metrics_internal.listen(9090)       // Prometheus metrics with sensitive data

// Mistake 2: Database ports exposed to network
// MongoDB on 27017, MySQL on 3306, PostgreSQL on 5432
// Without authentication or bound to 0.0.0.0

// Mistake 3: Management interfaces on public ports
redis.config.bind = "0.0.0.0"       // Redis exposed to network
elasticsearch_http = TRUE            // ES HTTP API exposed

// Mistake 4: All services in one container/server without isolation

// ========================================
// GOOD: Minimal attack surface
// ========================================

// Principle: Only expose what's necessary for the service to function

FUNCTION configure_server():
    // Main application - public facing
    app.listen({
        port: 443,
        host: "0.0.0.0"  // Must be accessible
    })

    // Health check - internal only
    health_server.listen({
        port: 8080,
        host: "127.0.0.1"  // Only accessible from localhost/internal
    })

    // Metrics - internal only, with authentication
    metrics_server.listen({
        port: 9090,
        host: "127.0.0.1",
        middleware: [basic_auth_middleware]
    })

    // NEVER start debug servers in production
    IF environment == "production":
        // Debug features should not exist in production code
        // Or be explicitly disabled
        disable_debug_endpoints()
    END IF
END FUNCTION

// Database configuration - never expose to network
FUNCTION configure_database():
    // Option 1: Unix socket (local only)
    database.connect({
        socket: "/var/run/postgresql/.s.PGSQL.5432"
    })

    // Option 2: Localhost binding
    database.connect({
        host: "127.0.0.1",
        port: 5432
    })

    // Option 3: Private network with firewall rules
    database.connect({
        host: "10.0.1.50",  // Internal IP, firewalled from internet
        port: 5432,
        ssl: TRUE
    })
END FUNCTION

// Container/service isolation
// Dockerfile example (pseudocode):
// EXPOSE 443           # Only expose necessary port
// USER nonroot         # Don't run as root
// Don't include: debuggers, profilers, shells, package managers

FUNCTION verify_minimal_ports():
    // Startup check - fail if unexpected ports are listening

    expected_ports = {
        443: "application",
        8080: "health_check"
    }

    listening_ports = get_listening_ports()

    FOR port IN listening_ports:
        IF port NOT IN expected_ports:
            log.error("Unexpected port listening", {port: port})

            IF environment == "production":
                THROW SecurityError("Unexpected port " + port + " listening")
            END IF
        END IF
    END FOR
END FUNCTION

// Firewall configuration (pseudocode for iptables/security groups)
firewall_rules = {
    inbound: [
        {port: 443, source: "0.0.0.0/0", description: "HTTPS"},
        {port: 80, source: "0.0.0.0/0", description: "HTTP (redirect to HTTPS)"},
        {port: 22, source: "10.0.0.0/8", description: "SSH from internal only"}
    ],
    outbound: [
        {port: 443, dest: "0.0.0.0/0", description: "HTTPS APIs"},
        {port: 53, dest: "10.0.0.1", description: "DNS to internal resolver"}
    ],
    default: "deny"
}

// Service mesh / network policies for Kubernetes
network_policy = {
    ingress: [
        {from: "ingress-controller", ports: [8080]}
    ],
    egress: [
        {to: "database", ports: [5432]},
        {to: "cache", ports: [6379]}
    ]
}
```

---
