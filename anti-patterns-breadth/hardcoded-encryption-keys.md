# Hardcoded Encryption Keys


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Hardcoded encryption keys in source
// ========================================
CONSTANT ENCRYPTION_KEY = "MySecretKey12345"  // Committed to repo!
CONSTANT AES_KEY = bytes([0x2b, 0x7e, 0x15, 0x16, ...])  // Still hardcoded

FUNCTION encrypt_user_data(data):
    cipher = AES.new(ENCRYPTION_KEY, mode=GCM)
    RETURN cipher.encrypt(data)
END FUNCTION

// Problems:
// - Keys in version control are exposed forever
// - Cannot rotate keys without code changes
// - All environments share same key

// ========================================
// GOOD: External key management
// ========================================
FUNCTION get_encryption_key():
    // Option 1: Environment variable
    key = environment.get("ENCRYPTION_KEY")

    IF key IS NULL:
        THROW Error("ENCRYPTION_KEY environment variable required")
    END IF

    // Validate key length for AES-256
    key_bytes = base64_decode(key)
    IF key_bytes.length != 32:
        THROW Error("ENCRYPTION_KEY must be 256 bits")
    END IF

    RETURN key_bytes
END FUNCTION

FUNCTION encrypt_user_data(data):
    key = get_encryption_key()
    nonce = crypto.secure_random_bytes(12)
    cipher = AES_GCM.new(key, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    RETURN nonce + tag + ciphertext
END FUNCTION

// Better: Use a secret manager for production
FUNCTION get_encryption_key_from_manager():
    TRY:
        // AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, etc.
        secret = secret_manager.get_secret("encryption-key")
        RETURN base64_decode(secret.value)
    CATCH Error as e:
        log.error("Failed to retrieve encryption key", {error: e.message})
        THROW Error("Encryption key unavailable")
    END TRY
END FUNCTION
```
