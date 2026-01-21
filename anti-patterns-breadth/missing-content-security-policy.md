# Missing Content-Security-Policy


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No CSP headers configured
// ========================================
FUNCTION configure_server():
    // No security headers set - browser allows any scripts
    server.start()
END FUNCTION

// Without CSP, even if XSS exists, attackers can:
// - Load scripts from any domain
// - Execute inline scripts
// - Use eval() and similar dangerous functions

// ========================================
// GOOD: Strict CSP implementation
// ========================================
FUNCTION configure_server():
    // Set comprehensive security headers
    server.set_header("Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; " +
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self'"
    )

    // Additional security headers
    server.set_header("X-Content-Type-Options", "nosniff")
    server.set_header("X-Frame-Options", "DENY")
    server.set_header("X-XSS-Protection", "1; mode=block")

    server.start()
END FUNCTION

// For applications needing inline scripts, use nonces
FUNCTION render_page_with_csp_nonce():
    // Generate cryptographically random nonce per request
    nonce = crypto.random_bytes(16).to_base64()

    // Set CSP with nonce
    response.set_header("Content-Security-Policy",
        "script-src 'self' 'nonce-" + nonce + "'"
    )

    // Include nonce in legitimate inline scripts
    html = "<html><body>"
    html += "<script nonce='" + nonce + "'>"
    html += "// This script will execute"
    html += "</script>"
    html += "</body></html>"

    // Attacker-injected scripts without nonce will be blocked
    RETURN html
END FUNCTION

// CSP report-only mode for testing
FUNCTION configure_csp_reporting():
    server.set_header("Content-Security-Policy-Report-Only",
        "default-src 'self'; report-uri /csp-report"
    )
END FUNCTION
```
