# ECB Mode Usage


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: ECB mode reveals patterns in data
// ========================================
FUNCTION encrypt_ecb(plaintext, key):
    // Vulnerable: ECB encrypts identical blocks identically
    cipher = AES.new(key, mode=ECB)
    RETURN cipher.encrypt(pad(plaintext))
END FUNCTION

// Problem demonstration:
// Encrypting an image with ECB mode preserves visual patterns
// because identical 16-byte blocks produce identical ciphertext
// This reveals structure of the original data!

// Identical plaintexts produce identical ciphertexts:
// plaintext_block_1 = "AAAAAAAAAAAAAAAA"
// plaintext_block_2 = "AAAAAAAAAAAAAAAA"
// ciphertext_1 == ciphertext_2  // Information leaked!

// ========================================
// GOOD: Use authenticated encryption modes
// ========================================
FUNCTION encrypt_gcm(plaintext, key):
    // GCM mode: Each encryption is unique even for same plaintext
    nonce = crypto.secure_random_bytes(12)  // 96-bit nonce for GCM

    cipher = AES_GCM.new(key, nonce)
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)

    // Return nonce + tag + ciphertext (all needed for decryption)
    RETURN nonce + auth_tag + ciphertext
END FUNCTION

FUNCTION decrypt_gcm(encrypted_data, key):
    // Extract components
    nonce = encrypted_data[0:12]
    auth_tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]

    cipher = AES_GCM.new(key, nonce)

    TRY:
        plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)
        RETURN plaintext
    CATCH AuthenticationError:
        // Tampering detected!
        log.warning("Decryption failed: authentication tag mismatch")
        THROW Error("Data integrity check failed")
    END TRY
END FUNCTION

// Alternative: CBC mode (if GCM not available)
FUNCTION encrypt_cbc(plaintext, key):
    // CBC requires random IV for each encryption
    iv = crypto.secure_random_bytes(16)

    cipher = AES_CBC.new(key, iv)
    padded = pkcs7_pad(plaintext, block_size=16)
    ciphertext = cipher.encrypt(padded)

    // Must also add HMAC for authentication (encrypt-then-MAC)
    mac = hmac_sha256(key, iv + ciphertext)

    RETURN iv + ciphertext + mac
END FUNCTION
```
