# JWT Misuse (None Algorithm, Weak Secrets, Sensitive Data)


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
