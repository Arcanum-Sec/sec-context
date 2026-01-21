# Improper Key Derivation


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Weak key derivation methods
// ========================================
FUNCTION derive_key_weak(password):
    // Vulnerable: Direct hash of password
    RETURN sha256(password)
END FUNCTION

FUNCTION derive_key_truncated(password):
    // Vulnerable: Password truncation
    RETURN password.bytes()[0:32]  // Loses entropy!
END FUNCTION

FUNCTION derive_key_md5(password, salt):
    // Vulnerable: MD5 with low iteration count
    RETURN md5(salt + password)
END FUNCTION

FUNCTION derive_key_fast(password, salt):
    // Vulnerable: Single SHA iteration (too fast to brute-force resist)
    RETURN sha256(salt + password)
END FUNCTION

// Problems:
// - Direct hash: No salt, no iterations, vulnerable to rainbow tables
// - Truncation: Reduces entropy, predictable patterns
// - Fast hash: GPU can compute billions per second

// ========================================
// GOOD: Proper key derivation functions
// ========================================
FUNCTION derive_key_pbkdf2(password, salt):
    // PBKDF2 with high iteration count
    IF salt IS NULL:
        salt = crypto.secure_random_bytes(32)
    END IF

    key = pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode(),
        salt=salt,
        iterations=600000,  // OWASP recommends 600,000+ for SHA-256
        key_length=32
    )
    RETURN {key: key, salt: salt}
END FUNCTION

FUNCTION derive_key_argon2(password, salt):
    // Argon2id - memory-hard, recommended for passwords
    IF salt IS NULL:
        salt = crypto.secure_random_bytes(16)
    END IF

    key = argon2id.hash(
        password=password,
        salt=salt,
        time_cost=3,         // Iterations
        memory_cost=65536,   // 64MB memory
        parallelism=4,       // 4 threads
        hash_len=32          // Output length
    )
    RETURN {key: key, salt: salt}
END FUNCTION

FUNCTION derive_key_scrypt(password, salt):
    // scrypt - memory-hard alternative
    IF salt IS NULL:
        salt = crypto.secure_random_bytes(32)
    END IF

    key = scrypt(
        password=password.encode(),
        salt=salt,
        n=2^17,       // CPU/memory cost (131072)
        r=8,          // Block size
        p=1,          // Parallelism
        key_length=32
    )
    RETURN {key: key, salt: salt}
END FUNCTION

// For deriving multiple keys from one password
FUNCTION derive_multiple_keys(password, salt):
    // Use HKDF to derive multiple keys from master key
    master_key = derive_key_argon2(password, salt).key

    encryption_key = hkdf_expand(
        master_key,
        info="encryption",
        length=32
    )

    mac_key = hkdf_expand(
        master_key,
        info="mac",
        length=32
    )

    RETURN {
        encryption_key: encryption_key,
        mac_key: mac_key
    }
END FUNCTION
```

---
