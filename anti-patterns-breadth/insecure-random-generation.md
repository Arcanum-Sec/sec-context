# Insecure Random Number Generation


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Non-cryptographic RNG for security
// ========================================
FUNCTION generate_session_id_weak():
    // Vulnerable: Math.random() / random.random() is predictable
    RETURN random.randint(0, 999999999)
END FUNCTION

FUNCTION generate_token_weak():
    // Vulnerable: Using random module for security tokens
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    token = ""
    FOR i = 0 TO 32:
        token += chars[random.randint(0, chars.length - 1)]
    END FOR
    RETURN token
END FUNCTION

FUNCTION generate_key_weak():
    // Vulnerable: Time-based seeding
    random.seed(current_timestamp())
    key = random.randbytes(32)
    RETURN key
END FUNCTION

// Problems:
// - Math.random(): Uses predictable PRNG (Mersenne Twister)
// - Time seed: Attacker can guess seed from approximate time
// - Internal state: Can be recovered from ~624 outputs

// ========================================
// GOOD: Cryptographically secure randomness
// ========================================
FUNCTION generate_session_id_secure():
    // Use cryptographically secure random
    RETURN secrets.token_urlsafe(32)  // 256 bits of entropy
END FUNCTION

FUNCTION generate_token_secure():
    // Use secrets module (Python) or crypto.randomBytes (Node)
    RETURN secrets.token_hex(32)  // 256 bits as hex string
END FUNCTION

FUNCTION generate_key_secure():
    // Use OS entropy source
    RETURN os.urandom(32)  // 256 bits from /dev/urandom or equivalent
END FUNCTION

FUNCTION generate_password_secure(length):
    // Secure password generation
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    password = ""
    FOR i = 0 TO length - 1:
        password += alphabet[secrets.randbelow(alphabet.length)]
    END FOR
    RETURN password
END FUNCTION

// Language-specific secure random:
// Python: secrets module, os.urandom
// Node.js: crypto.randomBytes, crypto.randomUUID
// Java: SecureRandom
// Go: crypto/rand
// Ruby: SecureRandom
// PHP: random_bytes, random_int
```
