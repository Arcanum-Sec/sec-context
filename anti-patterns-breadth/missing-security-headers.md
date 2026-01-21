# Missing Security Headers


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
