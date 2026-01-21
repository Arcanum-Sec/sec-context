# Insecure Password Reset Flows


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Insecure password reset implementations
// ========================================

// Mistake 1: Predictable reset tokens
FUNCTION create_reset_token_weak(user_id):
    // Vulnerable: MD5 of user_id + timestamp is guessable
    token = md5(user_id + current_timestamp())
    database.save_reset_token(user_id, token)
    RETURN token
END FUNCTION

// Mistake 2: Token never expires
FUNCTION request_password_reset_no_expiry(email):
    user = database.find_user_by_email(email)
    token = generate_token()
    // Vulnerable: No expiration set
    database.save_reset_token(user.id, token)
    send_email(email, "Reset: " + BASE_URL + "/reset?token=" + token)
END FUNCTION

// Mistake 3: Token not invalidated after use
FUNCTION reset_password_reusable(token, new_password):
    user_id = database.get_user_by_reset_token(token)
    user = database.get_user(user_id)
    user.password_hash = hash(new_password)
    database.save(user)
    // Vulnerable: Token still valid, can be reused!
END FUNCTION

// Mistake 4: User enumeration via different responses
FUNCTION request_reset_enumeration(email):
    user = database.find_user_by_email(email)
    IF user IS NULL:
        RETURN {error: "No account found with this email"}  // Reveals info!
    END IF
    // ... send reset email
    RETURN {success: TRUE, message: "Reset email sent"}
END FUNCTION

// Mistake 5: Sending password in email
FUNCTION reset_password_insecure(email):
    user = database.find_user_by_email(email)
    new_password = generate_random_password()
    user.password_hash = hash(new_password)
    // Vulnerable: Password in plaintext email
    send_email(email, "Your new password is: " + new_password)
END FUNCTION

// ========================================
// GOOD: Secure password reset flow
// ========================================
FUNCTION request_password_reset(email):
    // Always return same response to prevent enumeration
    user = database.find_user_by_email(email)

    IF user IS NOT NULL:
        // Invalidate any existing reset tokens
        database.delete_reset_tokens(user.id)

        // Generate cryptographically secure token
        token_bytes = crypto.secure_random_bytes(32)
        token = base64_url_encode(token_bytes)

        // Store hashed token with expiration
        token_hash = sha256(token)
        database.save_reset_token({
            user_id: user.id,
            token_hash: token_hash,
            expires_at: current_time() + 3600,  // 1 hour expiration
            created_at: current_time()
        })

        // Send reset email
        reset_url = BASE_URL + "/reset-password?token=" + token
        send_email(user.email, "password_reset", {reset_url: reset_url})

        log.info("Password reset requested", {user_id: user.id})
    END IF

    // Same response whether user exists or not
    RETURN {
        success: TRUE,
        message: "If an account exists, a reset email has been sent"
    }
END FUNCTION

FUNCTION validate_reset_token(token):
    IF token IS NULL OR token.length < 32:
        RETURN NULL
    END IF

    token_hash = sha256(token)
    reset_record = database.find_reset_token(token_hash)

    IF reset_record IS NULL:
        log.warning("Invalid reset token attempted")
        RETURN NULL
    END IF

    // Check expiration
    IF current_time() > reset_record.expires_at:
        database.delete_reset_token(token_hash)
        RETURN NULL
    END IF

    RETURN reset_record
END FUNCTION

FUNCTION reset_password(token, new_password):
    reset_record = validate_reset_token(token)

    IF reset_record IS NULL:
        RETURN {success: FALSE, error: "Invalid or expired reset link"}
    END IF

    // Validate new password strength
    validation = validate_password_strength(new_password)
    IF NOT validation.is_valid:
        RETURN {success: FALSE, error: validation.message}
    END IF

    user = database.get_user(reset_record.user_id)

    // Check if new password is same as old
    IF bcrypt.verify(new_password, user.password_hash):
        RETURN {success: FALSE, error: "New password must be different"}
    END IF

    // Update password
    user.password_hash = bcrypt.hash(new_password, rounds=12)
    database.save(user)

    // CRITICAL: Invalidate the reset token
    database.delete_reset_token(sha256(token))

    // Invalidate all existing sessions (force re-login)
    session_store.delete_all_user_sessions(user.id)

    // Send confirmation email
    send_email(user.email, "password_changed", {
        timestamp: current_time(),
        ip_address: request.get_client_ip()
    })

    log.info("Password reset completed", {user_id: user.id})

    RETURN {success: TRUE, message: "Password reset successfully"}
END FUNCTION

// Additional security: Limit reset requests
FUNCTION rate_limit_reset_requests(email):
    key = "password_reset:" + sha256(email)
    attempts = rate_limiter.get(key, default=0)

    IF attempts >= 3:
        // Max 3 reset requests per hour
        RETURN FALSE
    END IF

    rate_limiter.increment(key, ttl=3600)
    RETURN TRUE
END FUNCTION
```

---
