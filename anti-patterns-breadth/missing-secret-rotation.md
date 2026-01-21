# Missing Secret Rotation Considerations


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Static secrets with no rotation capability
// ========================================
CONSTANT JWT_SECRET = "static_jwt_secret_forever"

FUNCTION create_token(user_id):
    // No way to rotate without breaking all existing tokens
    RETURN jwt.encode({user: user_id}, JWT_SECRET, algorithm="HS256")
END FUNCTION

// ========================================
// GOOD: Versioned secrets supporting rotation
// ========================================
FUNCTION get_jwt_secret(version=NULL):
    IF version IS NULL:
        version = environment.get("JWT_SECRET_VERSION", "v1")
    END IF

    // Fetch versioned secret from manager
    RETURN secret_manager.get("JWT_SECRET_" + version)
END FUNCTION

FUNCTION create_token(user_id):
    current_version = environment.get("JWT_SECRET_VERSION")
    secret = get_jwt_secret(current_version)

    payload = {
        user: user_id,
        secret_version: current_version,  // Include version for validation
        exp: current_timestamp() + 3600
    }
    RETURN jwt.encode(payload, secret, algorithm="HS256")
END FUNCTION

FUNCTION verify_token(token):
    // Decode header to get version
    unverified = jwt.decode(token, verify=FALSE)
    version = unverified.get("secret_version", "v1")

    secret = get_jwt_secret(version)
    RETURN jwt.decode(token, secret, algorithms=["HS256"])
END FUNCTION
```

---
