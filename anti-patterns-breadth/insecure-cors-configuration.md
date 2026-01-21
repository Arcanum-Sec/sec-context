# Insecure CORS Configuration


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
