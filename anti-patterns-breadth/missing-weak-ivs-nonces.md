# Missing or Weak IVs/Nonces


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Predictable or reused IVs/nonces
// ========================================
FUNCTION encrypt_static_iv(plaintext, key):
    // Vulnerable: Static IV - identical plaintexts have identical ciphertexts
    iv = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    cipher = AES_CBC.new(key, iv)
    RETURN cipher.encrypt(pad(plaintext))
END FUNCTION

FUNCTION encrypt_counter_nonce(plaintext, key, message_counter):
    // Vulnerable: Predictable counter-based nonce
    nonce = int_to_bytes(message_counter, length=12)
    cipher = AES_GCM.new(key, nonce)
    RETURN cipher.encrypt(plaintext)
END FUNCTION

FUNCTION encrypt_truncated_nonce(plaintext, key):
    // Vulnerable: Nonce too short
    nonce = crypto.secure_random_bytes(4)  // Only 32 bits!
    cipher = AES_GCM.new(key, nonce)
    RETURN cipher.encrypt(plaintext)
END FUNCTION

// Problems:
// - Static IV: Same plaintext → same ciphertext (pattern leakage)
// - Predictable nonce: Allows chosen-plaintext attacks
// - Short nonce: Birthday collision after ~2^16 messages
// - GCM with repeated nonce: CATASTROPHIC - authentication key recovered!

// ========================================
// GOOD: Cryptographically random IVs/nonces
// ========================================
FUNCTION encrypt_with_random_iv(plaintext, key):
    // Generate random IV for each encryption
    iv = crypto.secure_random_bytes(16)  // 128 bits for AES-CBC

    cipher = AES_CBC.new(key, iv)
    padded = pkcs7_pad(plaintext, block_size=16)
    ciphertext = cipher.encrypt(padded)

    // Prepend IV (it's not secret, just must be unique)
    RETURN iv + ciphertext
END FUNCTION

FUNCTION encrypt_with_random_nonce(plaintext, key):
    // Generate random nonce for each encryption
    nonce = crypto.secure_random_bytes(12)  // 96 bits for AES-GCM

    cipher = AES_GCM.new(key, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    RETURN nonce + tag + ciphertext
END FUNCTION

// For high-volume encryption: Use key+nonce management
FUNCTION encrypt_with_derived_nonce(plaintext, key, message_id):
    // Derive unique nonce from random key-specific prefix + message ID
    // This prevents nonce reuse across different encryption contexts

    nonce_key = derive_key(key, "nonce-derivation")
    nonce = hmac_sha256(nonce_key, message_id)[0:12]

    cipher = AES_GCM.new(key, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    RETURN message_id + tag + ciphertext  // Include message_id for decryption
END FUNCTION
```
