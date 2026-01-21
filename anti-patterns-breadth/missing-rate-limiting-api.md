# Missing Rate Limiting


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No rate limiting
// ========================================

// Login endpoint vulnerable to brute force
@route("/api/auth/login")
FUNCTION login(request):
    user = database.find_by_email(request.body.email)

    IF user IS NULL OR NOT verify_password(request.body.password, user.password_hash):
        RETURN response(401, {error: "Invalid credentials"})
    END IF

    RETURN response(200, {token: create_token(user)})
END FUNCTION

// Expensive operation with no limits
@route("/api/reports/generate")
@require_auth
FUNCTION generate_report(request):
    // CPU-intensive, no limits - easy DoS
    report = generate_complex_report(request.body.params)
    RETURN response(200, report)
END FUNCTION

// SMS/email sending without limits
@route("/api/auth/send-verification")
FUNCTION send_verification(request):
    // Attacker can spam any phone/email
    send_sms(request.body.phone, generate_code())
    RETURN response(200, {status: "sent"})
END FUNCTION

// ========================================
// GOOD: Comprehensive rate limiting
// ========================================

// Rate limiter configuration
rate_limits = {
    // Per IP limits
    "ip:global": {limit: 1000, window: "1 hour"},
    "ip:auth": {limit: 10, window: "15 minutes"},
    "ip:sensitive": {limit: 5, window: "1 minute"},

    // Per user limits
    "user:global": {limit: 5000, window: "1 hour"},
    "user:write": {limit: 100, window: "1 hour"},

    // Per resource limits
    "resource:reports": {limit: 10, window: "1 hour"}
}

FUNCTION rate_limit(key_type, key_suffix=""):
    RETURN FUNCTION decorator(handler):
        RETURN FUNCTION wrapped(request):
            config = rate_limits[key_type]

            // Build rate limit key
            IF key_type.starts_with("ip:"):
                key = key_type + ":" + request.client_ip + key_suffix
            ELSE IF key_type.starts_with("user:"):
                IF request.user IS NULL:
                    RETURN response(401, {error: "Authentication required"})
                END IF
                key = key_type + ":" + request.user.id + key_suffix
            ELSE:
                key = key_type + key_suffix
            END IF

            // Check rate limit
            current = redis.incr(key)
            IF current == 1:
                redis.expire(key, config.window)
            END IF

            IF current > config.limit:
                retry_after = redis.ttl(key)
                log.security("Rate limit exceeded", {
                    key: key,
                    ip: request.client_ip,
                    user_id: request.user.id IF request.user ELSE NULL
                })
                RETURN response(429, {
                    error: "Too many requests",
                    retry_after: retry_after
                }, headers={"Retry-After": retry_after})
            END IF

            // Add rate limit headers
            response = handler(request)
            response.headers["X-RateLimit-Limit"] = config.limit
            response.headers["X-RateLimit-Remaining"] = config.limit - current
            response.headers["X-RateLimit-Reset"] = redis.ttl(key)

            RETURN response
        END FUNCTION
    END FUNCTION
END FUNCTION

// Login with rate limiting
@route("/api/auth/login")
@rate_limit("ip:auth")
FUNCTION login_protected(request):
    email = request.body.email

    // Additional per-account rate limiting
    account_key = "auth:account:" + sha256(email)
    attempts = redis.incr(account_key)
    IF attempts == 1:
        redis.expire(account_key, 3600)  // 1 hour
    END IF

    IF attempts > 5:
        // Lock account temporarily
        log.security("Account locked due to failed attempts", {email: email})
        RETURN response(423, {
            error: "Account temporarily locked",
            retry_after: redis.ttl(account_key)
        })
    END IF

    user = database.find_by_email(email)

    IF user IS NULL OR NOT verify_password(request.body.password, user.password_hash):
        // Don't reset counter on failure
        RETURN response(401, {error: "Invalid credentials"})
    END IF

    // Reset counter on successful login
    redis.delete(account_key)

    RETURN response(200, {token: create_token(user)})
END FUNCTION

// Expensive operations with strict limits
@route("/api/reports/generate")
@require_auth
@rate_limit("user:write")
@rate_limit("resource:reports")
FUNCTION generate_report_limited(request):
    // Queue for async processing if over capacity
    active_reports = get_active_report_count(request.user.id)

    IF active_reports > 3:
        RETURN response(429, {error: "Too many reports in progress"})
    END IF

    job_id = queue_report_generation(request.user.id, request.body.params)

    RETURN response(202, {
        job_id: job_id,
        status: "queued",
        estimated_time: estimate_completion_time()
    })
END FUNCTION

// SMS/email with phone/email-specific limits
@route("/api/auth/send-verification")
@rate_limit("ip:sensitive")
FUNCTION send_verification_limited(request):
    phone = request.body.phone

    // Rate limit per phone number
    phone_key = "verify:phone:" + sha256(phone)
    count = redis.incr(phone_key)
    IF count == 1:
        redis.expire(phone_key, 3600)  // 1 hour
    END IF

    IF count > 3:
        RETURN response(429, {
            error: "Too many verification requests for this number"
        })
    END IF

    // Verify phone format before sending
    IF NOT is_valid_phone(phone):
        RETURN response(400, {error: "Invalid phone number"})
    END IF

    code = generate_secure_code()
    redis.setex("verify:code:" + sha256(phone), 600, code)  // 10 min expiry

    send_sms(phone, "Your code: " + code)

    RETURN response(200, {status: "sent"})
END FUNCTION

// Sliding window rate limiter for more precise control
FUNCTION sliding_window_limit(key, limit, window_seconds):
    now = current_timestamp()
    window_start = now - window_seconds

    // Remove old entries
    redis.zremrangebyscore(key, "-inf", window_start)

    // Count current window
    count = redis.zcard(key)

    IF count >= limit:
        RETURN FALSE
    END IF

    // Add current request
    redis.zadd(key, now, generate_uuid())
    redis.expire(key, window_seconds)

    RETURN TRUE
END FUNCTION
```
