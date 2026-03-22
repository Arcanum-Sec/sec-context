<!-- Source: Arcanum sec-context (https://github.com/arcanum-sec/sec-context), CC BY 4.0, Jason Haddix / Arcanum Information Security -->

## 5. Cryptographic Failures

**CWE References:** CWE-327 (Use of Broken or Risky Cryptographic Algorithm), CWE-328 (Reversible One-Way Hash), CWE-330 (Use of Insufficiently Random Values), CWE-326 (Inadequate Encryption Strength), CWE-759 (Use of One-Way Hash without a Salt)
**Severity:** High to Critical | **Related:** [[Cryptographic-Misuse]]

> **Risk:** AI models frequently suggest outdated or weak cryptographic algorithms (MD5, SHA-1, DES) learned from decades of legacy code in training data. Cryptographic failures lead to data exposure, password compromise, and authentication bypass. A 14% failure rate for CWE-327 was documented in AI-generated code, with "significant increase" in encryption vulnerabilities when using AI assistants.

### 5.1 Using Deprecated Algorithms (MD5, SHA1 for Security, DES)

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

### 5.2 Hardcoded Encryption Keys

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

### 5.3 ECB Mode Usage

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

### 5.4 Missing or Weak IVs/Nonces

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

### 5.5 Rolling Your Own Crypto

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

### 5.6 Insecure Random Number Generation

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

### 5.7 Improper Key Derivation

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
