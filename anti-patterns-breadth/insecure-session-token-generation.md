# Insecure Session Token Generation


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Predictable session tokens
// ========================================
FUNCTION create_session_weak(user_id):
    // Vulnerable: Predictable token based on user ID
    token = "session_" + user_id + "_" + current_timestamp()
    RETURN token
END FUNCTION

FUNCTION create_session_sequential():
    // Vulnerable: Sequential/incremental tokens
    GLOBAL session_counter
    session_counter = session_counter + 1
    RETURN "session_" + session_counter
END FUNCTION

FUNCTION create_session_weak_random():
    // Vulnerable: Using Math.random() or similar weak PRNG
    token = ""
    FOR i = 1 TO 32:
        token = token + random_char()  // Math.random() based
    END FOR
    RETURN token
END FUNCTION

// Attack: Attacker can predict/enumerate session tokens
// - Timestamp-based: Try tokens from recent timestamps
// - Sequential: Try nearby session IDs
// - Weak random: Seed prediction or insufficient entropy

// ========================================
// GOOD: Cryptographically secure session tokens
// ========================================
FUNCTION create_session(user_id):
    // Generate cryptographically secure random token
    // Use 256 bits (32 bytes) minimum for security
    token_bytes = crypto.secure_random_bytes(32)
    token = base64_url_encode(token_bytes)  // URL-safe encoding

    // Store session with metadata
    session_data = {
        user_id: user_id,
        created_at: current_timestamp(),
        expires_at: current_timestamp() + SESSION_LIFETIME,
        ip_address: request.get_client_ip(),
        user_agent: request.get_user_agent()
    }

    // Store hashed token (protect against database leaks)
    token_hash = sha256(token)
    session_store.set(token_hash, session_data)

    RETURN token
END FUNCTION

FUNCTION validate_session(token):
    IF token IS NULL OR token.length < 32:
        RETURN NULL
    END IF

    token_hash = sha256(token)
    session = session_store.get(token_hash)

    IF session IS NULL:
        RETURN NULL
    END IF

    // Check expiration
    IF current_timestamp() > session.expires_at:
        session_store.delete(token_hash)
        RETURN NULL
    END IF

    // Optional: Validate IP/User-Agent consistency
    IF session.ip_address != request.get_client_ip():
        log.warning("Session IP mismatch", {
            expected: session.ip_address,
            actual: request.get_client_ip()
        })
        // Decide whether to invalidate or just log
    END IF

    RETURN session
END FUNCTION

// Secure cookie configuration
FUNCTION set_session_cookie(response, token):
    response.set_cookie("session", token, {
        httponly: TRUE,      // Prevent JavaScript access
        secure: TRUE,        // HTTPS only
        samesite: "Strict",  // Prevent CSRF
        max_age: SESSION_LIFETIME,
        path: "/"
    })
END FUNCTION
```
