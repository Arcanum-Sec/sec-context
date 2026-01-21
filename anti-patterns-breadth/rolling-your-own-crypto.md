# Rolling Your Own Crypto


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Custom cryptographic implementations
// ========================================
FUNCTION my_encrypt(plaintext, key):
    // Vulnerable: XOR "encryption" is trivially broken
    result = ""
    FOR i = 0 TO plaintext.length - 1:
        result += char(plaintext[i] XOR key[i % key.length])
    END FOR
    RETURN result
END FUNCTION

FUNCTION my_hash(data):
    // Vulnerable: Custom hash is not collision-resistant
    result = 0
    FOR byte IN data:
        result = (result * 31 + byte) % 2147483647
    END FOR
    RETURN result
END FUNCTION

FUNCTION my_random(seed):
    // Vulnerable: Linear congruential generator
    RETURN (seed * 1103515245 + 12345) % (2^31)
END FUNCTION

// Problems:
// - XOR cipher: Trivially broken with known-plaintext
// - Custom hash: Collisions easily found
// - LCG random: Completely predictable sequence

// ========================================
// GOOD: Use established cryptographic libraries
// ========================================
FUNCTION encrypt_properly(plaintext, key):
    // Use vetted library implementations
    // Python: cryptography library
    // Node.js: crypto module
    // Java: javax.crypto
    // Go: crypto/* packages

    // AES-GCM from standard library
    nonce = crypto.secure_random_bytes(12)
    cipher = crypto.createCipheriv("aes-256-gcm", key, nonce)

    ciphertext = cipher.update(plaintext) + cipher.final()
    auth_tag = cipher.getAuthTag()

    RETURN nonce + auth_tag + ciphertext
END FUNCTION

FUNCTION hash_properly(data):
    // Use standard library hash functions
    RETURN crypto.sha256(data)
END FUNCTION

FUNCTION random_properly(num_bytes):
    // Use OS-provided cryptographic randomness
    RETURN crypto.secure_random_bytes(num_bytes)
END FUNCTION

// Rule: Never implement cryptographic primitives yourself
// - Encryption: Use library AES-GCM, ChaCha20-Poly1305
// - Hashing: Use library SHA-256, SHA-3, BLAKE2
// - Signatures: Use library Ed25519, ECDSA
// - Random: Use library secrets module or os.urandom
```
