<!-- Source: Arcanum sec-context (https://github.com/arcanum-sec/sec-context), CC BY 4.0, Jason Haddix / Arcanum Information Security -->

## 4. Authentication and Session Management

**CWE References:** CWE-287 (Improper Authentication), CWE-384 (Session Fixation), CWE-521 (Weak Password Requirements), CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-613 (Insufficient Session Expiration)
**Severity:** Critical | **Related:** [[Authentication-Failures]]

> **Risk:** Authentication failures are a leading cause of data breaches. AI-generated code often implements weak password policies, insecure session handling, and vulnerable JWT patterns learned from outdated tutorials. Proper authentication requires defense in depth: strong credentials, secure sessions, rate limiting, and multi-factor authentication.

### 4.1 Weak Password Requirements

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No or weak password validation
// ========================================
FUNCTION register_user(username, password):
    // Vulnerable: No password strength requirements
    IF password.length < 4:
        THROW Error("Password too short")
    END IF

    // No checks for complexity, common passwords, or breaches
    hash = simple_hash(password)  // Often MD5 or SHA1
    database.insert("users", {username: username, password_hash: hash})
END FUNCTION

FUNCTION validate_password_weak(password):
    // Vulnerable: Only checks length
    RETURN password.length >= 6
END FUNCTION

// Problems:
// - Allows "123456", "password", "qwerty"
// - No complexity requirements
// - No check against breached password lists

// ========================================
// GOOD: Strong password policy with multiple checks
// ========================================
FUNCTION register_user(username, password):
    validation_result = validate_password_strength(password)

    IF NOT validation_result.is_valid:
        THROW Error(validation_result.message)
    END IF

    // Use strong hashing algorithm with salt
    hash = bcrypt.hash(password, rounds=12)
    database.insert("users", {username: username, password_hash: hash})
END FUNCTION

FUNCTION validate_password_strength(password):
    errors = []

    // Minimum length (NIST recommends 8+, many use 12+)
    IF password.length < 12:
        errors.append("Password must be at least 12 characters")
    END IF

    // Maximum length (prevent DoS via very long passwords)
    IF password.length > 128:
        errors.append("Password must not exceed 128 characters")
    END IF

    // Check character diversity
    has_upper = regex.search("[A-Z]", password)
    has_lower = regex.search("[a-z]", password)
    has_digit = regex.search("[0-9]", password)
    has_special = regex.search("[!@#$%^&*(),.?\":{}|<>]", password)

    IF NOT (has_upper AND has_lower AND has_digit):
        errors.append("Password must contain uppercase, lowercase, and numbers")
    END IF

    // Check against common passwords list
    IF is_common_password(password):
        errors.append("Password is too common, choose a unique password")
    END IF

    // Check against breached passwords (via k-Anonymity API)
    IF is_breached_password(password):
        errors.append("Password found in data breach, choose another")
    END IF

    // Check for username in password
    IF password.lower().contains(username.lower()):
        errors.append("Password cannot contain username")
    END IF

    RETURN {
        is_valid: errors.length == 0,
        message: errors.join("; ")
    }
END FUNCTION

// Check breached passwords using k-Anonymity (e.g., HaveIBeenPwned API)
FUNCTION is_breached_password(password):
    hash = sha1(password).upper()
    prefix = hash.substring(0, 5)
    suffix = hash.substring(5)

    // Only send hash prefix to API (privacy-preserving)
    response = http.get("https://api.pwnedpasswords.com/range/" + prefix)
    hashes = parse_pwned_response(response)

    RETURN suffix IN hashes
END FUNCTION
```

### 4.2 Missing Rate Limiting on Auth Endpoints

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

### 4.3 Insecure Session Token Generation

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

### 4.4 Session Fixation Vulnerabilities

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Session ID not regenerated on login
// ========================================
FUNCTION login_vulnerable(username, password):
    // Session ID was set when user first visited (before login)
    session_id = request.get_cookie("session_id")

    user = authenticate(username, password)
    IF user IS NULL:
        RETURN {success: FALSE}
    END IF

    // Vulnerable: Reusing pre-authentication session ID
    session_store.set(session_id, {user_id: user.id, authenticated: TRUE})
    RETURN {success: TRUE}
END FUNCTION

// Attack scenario:
// 1. Attacker visits site, gets session_id=ABC123
// 2. Attacker sends victim link: https://site.com?session_id=ABC123
// 3. Victim logs in with attacker's session ID
// 4. Attacker uses session_id=ABC123 to access victim's account

// ========================================
// GOOD: Regenerate session on authentication changes
// ========================================
FUNCTION login_secure(username, password):
    user = authenticate(username, password)
    IF user IS NULL:
        RETURN {success: FALSE}
    END IF

    // CRITICAL: Invalidate old session and create new one
    old_session_id = request.get_cookie("session_id")
    IF old_session_id IS NOT NULL:
        session_store.delete(old_session_id)
    END IF

    // Generate completely new session ID
    new_session = create_session(user.id)

    // Set new session cookie
    response.set_cookie("session_id", new_session.token, {
        httponly: TRUE,
        secure: TRUE,
        samesite: "Strict"
    })

    RETURN {success: TRUE}
END FUNCTION

// Also regenerate session on privilege escalation
FUNCTION elevate_privileges(user, new_role):
    // Invalidate current session
    old_session_id = request.get_cookie("session_id")
    session_store.delete(old_session_id)

    // Create new session with elevated privileges
    new_session = create_session(user.id)
    new_session.role = new_role

    response.set_cookie("session_id", new_session.token, {
        httponly: TRUE,
        secure: TRUE,
        samesite: "Strict"
    })

    RETURN new_session
END FUNCTION

// Regenerate session periodically for long-lived sessions
FUNCTION check_session_rotation(session):
    // Rotate session every 15 minutes for active users
    IF current_timestamp() - session.created_at > 900:
        new_session = create_session(session.user_id)
        new_session.data = session.data  // Preserve session data

        session_store.delete(session.id)

        response.set_cookie("session_id", new_session.token, {
            httponly: TRUE,
            secure: TRUE,
            samesite: "Strict"
        })

        RETURN new_session
    END IF

    RETURN session
END FUNCTION
```

### 4.5 JWT Misuse (None Algorithm, Weak Secrets, Sensitive Data)

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Common JWT security mistakes
// ========================================

// Mistake 1: Not verifying algorithm (none algorithm attack)
FUNCTION verify_jwt_vulnerable(token):
    // Vulnerable: Accepts whatever algorithm is in the header
    decoded = jwt.decode(token, SECRET_KEY)  // Attacker sets alg: "none"
    RETURN decoded
END FUNCTION

// Mistake 2: Weak or short secret key
CONSTANT JWT_SECRET = "secret123"  // Easily brute-forced

FUNCTION create_jwt_weak(user_id):
    payload = {user_id: user_id, exp: current_time() + 86400}
    RETURN jwt.encode(payload, JWT_SECRET, algorithm="HS256")
END FUNCTION

// Mistake 3: Sensitive data in payload (JWTs are base64, not encrypted!)
FUNCTION create_jwt_exposed(user):
    payload = {
        user_id: user.id,
        email: user.email,
        ssn: user.social_security_number,  // PII in token!
        credit_card: user.card_number,      // Sensitive data exposed!
        password_hash: user.password_hash,  // Never put this in JWT!
        exp: current_time() + 86400
    }
    RETURN jwt.encode(payload, SECRET_KEY)
END FUNCTION

// Mistake 4: No expiration or very long expiration
FUNCTION create_jwt_no_expiry(user_id):
    payload = {user_id: user_id}  // No exp claim!
    RETURN jwt.encode(payload, SECRET_KEY)
END FUNCTION

// ========================================
// GOOD: Secure JWT implementation
// ========================================

// Use a strong secret (256+ bits for HS256)
CONSTANT JWT_SECRET = environment.get("JWT_SECRET")  // From secret manager

FUNCTION initialize_jwt():
    // Validate secret strength at startup
    IF JWT_SECRET IS NULL OR JWT_SECRET.length < 32:
        THROW Error("JWT_SECRET must be at least 256 bits")
    END IF
END FUNCTION

FUNCTION create_jwt_secure(user_id):
    now = current_time()

    payload = {
        // Standard claims
        sub: user_id,           // Subject
        iat: now,               // Issued at
        exp: now + 3600,        // Expiration (1 hour max for access tokens)
        nbf: now,               // Not before

        // Custom claims (non-sensitive only!)
        role: user.role         // Roles are OK
        // Never include: passwords, PII, payment info
    }

    // Explicitly specify algorithm
    RETURN jwt.encode(payload, JWT_SECRET, algorithm="HS256")
END FUNCTION

FUNCTION verify_jwt_secure(token):
    TRY:
        // CRITICAL: Explicitly specify allowed algorithms
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

        // Additional validation
        IF decoded.exp < current_time():
            THROW Error("Token expired")
        END IF

        IF decoded.nbf > current_time():
            THROW Error("Token not yet valid")
        END IF

        RETURN decoded

    CATCH JWTError as e:
        log.warning("JWT verification failed", {error: e.message})
        RETURN NULL
    END TRY
END FUNCTION

// For sensitive applications, use asymmetric keys (RS256)
FUNCTION create_jwt_asymmetric(user_id):
    private_key = load_private_key("jwt_private.pem")

    payload = {
        sub: user_id,
        iat: current_time(),
        exp: current_time() + 3600
    }

    // Sign with private key
    RETURN jwt.encode(payload, private_key, algorithm="RS256")
END FUNCTION

FUNCTION verify_jwt_asymmetric(token):
    public_key = load_public_key("jwt_public.pem")

    // Verify with public key (can be shared safely)
    RETURN jwt.decode(token, public_key, algorithms=["RS256"])
END FUNCTION

// Implement refresh token pattern for long-lived sessions
FUNCTION create_token_pair(user_id):
    // Short-lived access token (15 minutes)
    access_token = create_jwt_secure(user_id, expiry=900)

    // Long-lived refresh token (7 days) - store in DB for revocation
    refresh_token = crypto.secure_random_bytes(32).to_base64()
    database.insert("refresh_tokens", {
        token_hash: sha256(refresh_token),
        user_id: user_id,
        expires_at: current_time() + 604800
    })

    RETURN {
        access_token: access_token,
        refresh_token: refresh_token
    }
END FUNCTION
```

### 4.6 Missing MFA Considerations

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Single-factor authentication only
// ========================================
FUNCTION login_single_factor(username, password):
    user = database.find_user(username)

    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF

    // Immediately grant full access after password verification
    token = create_session(user.id)
    RETURN {success: TRUE, token: token}
END FUNCTION

// Problems:
// - Compromised password = full account takeover
// - No protection against credential stuffing
// - Phishing attacks succeed completely
// - No step-up authentication for sensitive operations

// ========================================
// GOOD: MFA-aware authentication flow
// ========================================
FUNCTION login_with_mfa(username, password):
    user = database.find_user(username)

    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF

    // Check if MFA is enabled
    IF user.mfa_enabled:
        // Create partial session (not fully authenticated)
        partial_token = create_partial_session(user.id)

        RETURN {
            success: FALSE,
            mfa_required: TRUE,
            partial_token: partial_token,
            mfa_methods: get_user_mfa_methods(user.id)
        }
    END IF

    // If MFA not enabled, encourage setup
    token = create_session(user.id)
    RETURN {
        success: TRUE,
        token: token,
        mfa_suggestion: user.is_admin  // Strongly suggest MFA for admins
    }
END FUNCTION

FUNCTION verify_mfa(partial_token, mfa_code, mfa_method):
    session = get_partial_session(partial_token)

    IF session IS NULL OR session.expires_at < current_time():
        RETURN {success: FALSE, error: "Session expired, please login again"}
    END IF

    user = database.get_user(session.user_id)

    // Verify MFA code based on method
    is_valid = FALSE

    IF mfa_method == "totp":
        is_valid = verify_totp(user.totp_secret, mfa_code)
    ELSE IF mfa_method == "sms":
        is_valid = verify_sms_code(user.id, mfa_code)
    ELSE IF mfa_method == "backup":
        is_valid = verify_backup_code(user.id, mfa_code)
    END IF

    IF NOT is_valid:
        record_failed_mfa_attempt(user.id)
        RETURN {success: FALSE, error: "Invalid verification code"}
    END IF

    // MFA verified - create full session
    delete_partial_session(partial_token)
    token = create_session(user.id)

    RETURN {success: TRUE, token: token}
END FUNCTION

// TOTP verification with time window
FUNCTION verify_totp(secret, code):
    // Allow 1 step before and after for clock drift (30 second windows)
    FOR step IN [-1, 0, 1]:
        expected = generate_totp(secret, time_step=step)
        IF constant_time_compare(code, expected):
            RETURN TRUE
        END IF
    END FOR
    RETURN FALSE
END FUNCTION

// Step-up authentication for sensitive operations
FUNCTION require_recent_auth(user_session, max_age_seconds):
    IF current_time() - user_session.authenticated_at > max_age_seconds:
        RETURN {
            requires_reauth: TRUE,
            message: "Please re-enter your password for this action"
        }
    END IF
    RETURN {requires_reauth: FALSE}
END FUNCTION

FUNCTION perform_sensitive_action(session, action, password):
    // Require recent password entry for sensitive actions
    user = database.get_user(session.user_id)

    IF NOT bcrypt.verify(password, user.password_hash):
        RETURN {success: FALSE, error: "Invalid password"}
    END IF

    // Update authentication timestamp
    session.authenticated_at = current_time()

    // Perform the sensitive action
    RETURN execute_action(action)
END FUNCTION
```

### 4.7 Insecure Password Reset Flows

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
