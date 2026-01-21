# Using Deprecated Algorithms (MD5, SHA1 for Security, DES)


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Deprecated hash algorithms for security
// ========================================
FUNCTION hash_password_weak(password):
    // Vulnerable: MD5 is cryptographically broken
    RETURN md5(password)
END FUNCTION

FUNCTION verify_integrity_weak(data):
    // Vulnerable: SHA-1 has known collision attacks
    RETURN sha1(data)
END FUNCTION

FUNCTION encrypt_data_weak(plaintext, key):
    // Vulnerable: DES uses 56-bit keys (trivially breakable)
    cipher = DES.new(key, mode=ECB)
    RETURN cipher.encrypt(plaintext)
END FUNCTION

// Problems:
// - MD5: Collisions found in seconds, rainbow tables widely available
// - SHA-1: Collision attacks demonstrated (SHAttered, 2017)
// - DES: Brute-forceable in hours with modern hardware

// ========================================
// GOOD: Modern cryptographic algorithms
// ========================================
FUNCTION hash_password_secure(password):
    // Use bcrypt, Argon2, or scrypt for passwords
    salt = bcrypt.generate_salt(rounds=12)
    RETURN bcrypt.hash(password, salt)
END FUNCTION

FUNCTION verify_integrity_secure(data):
    // Use SHA-256, SHA-3, or BLAKE2 for integrity
    RETURN sha256(data)
END FUNCTION

FUNCTION encrypt_data_secure(plaintext, key):
    // Use AES-256-GCM or ChaCha20-Poly1305
    nonce = crypto.secure_random_bytes(12)
    cipher = AES_GCM.new(key, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    RETURN nonce + tag + ciphertext  // Include nonce and auth tag
END FUNCTION

// Algorithm selection guide:
// - Password hashing: bcrypt, Argon2id, scrypt (NOT SHA-256 alone)
// - Symmetric encryption: AES-256-GCM, ChaCha20-Poly1305
// - Integrity/checksums: SHA-256, SHA-3, BLAKE2
// - Signatures: Ed25519, ECDSA with P-256, RSA-2048+
```
