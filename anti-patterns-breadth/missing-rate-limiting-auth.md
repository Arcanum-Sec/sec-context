# Missing Rate Limiting on Auth Endpoints


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No rate limiting on authentication
// ========================================
FUNCTION login(username, password):
    // Vulnerable: No limit on login attempts
    user = database.find_user(username)

    IF user IS NULL:
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF

    IF bcrypt.verify(password, user.password_hash):
        RETURN {success: TRUE, token: generate_token(user)}
    ELSE:
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF
END FUNCTION

// Problems:
// - Allows unlimited password guessing (brute force)
// - Allows credential stuffing attacks
// - No account lockout protection

// ========================================
// GOOD: Rate limiting with progressive delays
// ========================================
FUNCTION login(username, password):
    client_ip = request.get_client_ip()

    // Check IP-based rate limit (protects against distributed attacks)
    IF is_ip_rate_limited(client_ip):
        log.warning("Rate limited IP attempted login", {ip: client_ip})
        RETURN {success: FALSE, error: "Too many attempts, try again later"}
    END IF

    // Check account-based rate limit (protects specific accounts)
    IF is_account_rate_limited(username):
        log.warning("Rate limited account attempted login", {username: username})
        RETURN {success: FALSE, error: "Account temporarily locked"}
    END IF

    user = database.find_user(username)

    // Use constant-time comparison to prevent timing attacks
    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        record_failed_attempt(username, client_ip)
        // Generic error message (don't reveal if user exists)
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF

    // Successful login - reset counters
    clear_failed_attempts(username, client_ip)

    RETURN {success: TRUE, token: generate_token(user)}
END FUNCTION

// IP-based rate limiting
FUNCTION is_ip_rate_limited(ip):
    key = "login_attempts:ip:" + ip
    attempts = rate_limiter.get(key, default=0)

    // Allow 10 attempts per 15 minutes per IP
    RETURN attempts >= 10
END FUNCTION

// Account-based rate limiting with progressive lockout
FUNCTION is_account_rate_limited(username):
    key = "login_attempts:user:" + username
    attempts = rate_limiter.get(key, default=0)

    // Progressive lockout:
    // 5 attempts: 1 minute lockout
    // 10 attempts: 5 minute lockout
    // 15 attempts: 15 minute lockout
    // 20+ attempts: 1 hour lockout

    IF attempts >= 20:
        lockout_time = 3600  // 1 hour
    ELSE IF attempts >= 15:
        lockout_time = 900   // 15 minutes
    ELSE IF attempts >= 10:
        lockout_time = 300   // 5 minutes
    ELSE IF attempts >= 5:
        lockout_time = 60    // 1 minute
    ELSE:
        RETURN FALSE
    END IF

    last_attempt = rate_limiter.get_timestamp(key)
    RETURN (current_time() - last_attempt) < lockout_time
END FUNCTION

FUNCTION record_failed_attempt(username, ip):
    // Increment both counters with TTL
    rate_limiter.increment("login_attempts:ip:" + ip, ttl=900)
    rate_limiter.increment("login_attempts:user:" + username, ttl=3600)

    // Alert on suspicious patterns
    ip_attempts = rate_limiter.get("login_attempts:ip:" + ip)
    IF ip_attempts >= 50:
        security_alert("Possible brute force attack from IP: " + ip)
    END IF
END FUNCTION
```
