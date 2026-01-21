# Weak Password Requirements


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
