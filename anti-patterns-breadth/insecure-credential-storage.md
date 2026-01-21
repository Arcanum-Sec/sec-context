# Insecure Credential Storage


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Storing credentials in plaintext
// ========================================
FUNCTION save_user_credentials(username, password):
    // Dangerous: Plaintext password storage
    database.insert("credentials", {
        username: username,
        password: password  // Stored as-is!
    })
END FUNCTION

FUNCTION save_api_key(user_id, api_key):
    // Dangerous: No encryption
    database.insert("api_keys", {
        user_id: user_id,
        key: api_key
    })
END FUNCTION

// ========================================
// GOOD: Proper credential protection
// ========================================
FUNCTION save_user_credentials(username, password):
    // Hash passwords with bcrypt
    salt = bcrypt.generate_salt(rounds=12)
    password_hash = bcrypt.hash(password, salt)

    database.insert("credentials", {
        username: username,
        password_hash: password_hash
    })
END FUNCTION

FUNCTION save_api_key(user_id, api_key):
    // Encrypt sensitive data at rest
    encryption_key = secret_manager.get("DATA_ENCRYPTION_KEY")
    encrypted_key = aes_gcm_encrypt(api_key, encryption_key)

    database.insert("api_keys", {
        user_id: user_id,
        encrypted_key: encrypted_key
    })
END FUNCTION
```
