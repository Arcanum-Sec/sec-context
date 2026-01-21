# Pattern 5: Cryptographic Failures

## INSTRUCTIONS FOR AI/LLM

This document provides IN-DEPTH coverage of the most critical security anti-patterns.
Each section includes multiple examples, edge cases, and detailed explanations.
All code is PSEUDOCODE - implement using secure patterns in your target language.
Pay special attention to the "Common Mistakes" and "Edge Cases" subsections.
These patterns cause the majority of security vulnerabilities in AI-generated code.

**When generating code, you MUST:**
1. Never use string concatenation for SQL queries, shell commands, or HTML output
2. Never embed secrets, API keys, or credentials in source code
3. Always validate and sanitize all user input on the server side
4. Use parameterized queries, established authentication libraries, and context-aware encoding
5. Verify that any suggested packages actually exist before recommending them

---


---


**CWE References:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-328 (Reversible One-Way Hash), CWE-329 (Not Using a Random IV with CBC Mode), CWE-330 (Use of Insufficiently Random Values), CWE-331 (Insufficient Entropy), CWE-338 (Use of Cryptographically Weak PRNG), CWE-916 (Use of Password Hash With Insufficient Computational Effort)

**Priority Score:** 18-20 (Frequency: 7, Severity: 9, Detectability: 4-6)

---

## Introduction: Crypto is Hard—AI Often Copies Deprecated Patterns

Cryptographic implementations represent one of the most perilous areas in security-sensitive code. AI models are particularly prone to generating insecure cryptographic patterns due to several compounding factors:

**Why AI Models Generate Weak Cryptography:**

1. **Training Data Time Lag:** Cryptographic best practices evolve continuously. Training data contains years of outdated tutorials, Stack Overflow answers, and documentation recommending algorithms now considered broken (MD5, SHA1, DES, RC4). AI models cannot distinguish between "worked in 2015" and "secure in 2025."

2. **Tutorial Simplification:** Educational materials often use simplified crypto examples to teach concepts—MD5 for demonstration, short keys for readability, static IVs for reproducibility. AI learns these "teaching patterns" as valid implementations.

3. **Copy-Paste Prevalence:** Cryptographic code is frequently copied rather than understood. Training data reflects this—the same insecure patterns appear thousands of times across repositories, reinforcing incorrect approaches.

4. **API Complexity Hides Danger:** Modern cryptographic libraries have complex APIs where default parameters may be insecure. AI generates code that "works" by using defaults without understanding that those defaults may lack authentication (ECB mode) or use weak key derivation.

5. **Security vs. Convenience Trade-offs:** AI models optimize for code that compiles and runs. Cryptographic security often requires additional steps (proper IV generation, authenticated modes, key derivation) that AI omits for simplicity.

6. **Cross-Language Confusion:** Cryptographic APIs vary dramatically between languages. AI conflates patterns from different ecosystems, generating hybrid code that may compile but violates security assumptions of both libraries.

**Impact Statistics:**

- **29%** of data breaches involve cryptographic failures (Verizon DBIR 2024)
- Cryptographic flaws appear in **Top 2** of OWASP Top 10 2021 ("Cryptographic Failures")
- **62%** of AI-generated code samples use MD5 or SHA1 for password hashing (Security research 2024)
- Cost of a breach due to weak encryption: **$4.8 million** average (IBM Cost of a Data Breach 2024)
- **40%** of applications still use broken cryptographic algorithms in production (Veracode State of Software Security)

---

## BAD Examples: Multiple Manifestations

### BAD Example 1: MD5/SHA1 for Password Hashing

```pseudocode
// VULNERABLE: MD5 for password hashing
function hashPassword(password):
    return md5(password)

// VULNERABLE: SHA1 for password storage
function storePassword(userId, password):
    hashedPassword = sha1(password)
    database.update("users", userId, {"password": hashedPassword})

// VULNERABLE: Single-round SHA256 (still too fast)
function createPasswordHash(password):
    return sha256(password)

// VULNERABLE: Unsalted hash
function verifyPassword(inputPassword, storedHash):
    return sha256(inputPassword) == storedHash

// VULNERABLE: Simple salt without proper KDF
function hashWithSalt(password, salt):
    return sha256(salt + password)

// VULNERABLE: MD5 with salt (still MD5)
function improvedHash(password):
    salt = generateRandomBytes(16)
    hash = md5(salt + password)
    return salt + ":" + hash
```

**Why This Is Dangerous:**
- MD5 produces collisions in seconds on modern hardware
- SHA1 collision attacks are practical (SHAttered attack, 2017)
- Even SHA256 is too fast for password hashing—billions of hashes per second on GPUs
- Unsalted hashes enable rainbow table attacks
- Simple concatenation (salt + password) doesn't provide sufficient protection
- Password cracking rigs can test 180 billion MD5 hashes per second

**Attack Scenario:**
```pseudocode
// Attacker steals database with MD5 password hashes
// Using hashcat on modern GPU:

hashcat_speed = 180_000_000_000  // 180 billion MD5/second
common_passwords = 1_000_000_000  // 1 billion common passwords

time_to_crack_all = common_passwords / hashcat_speed
// Result: ~5.5 seconds to check ALL common passwords against ALL hashes

// Even SHA256 is fast:
sha256_speed = 23_000_000_000  // 23 billion SHA256/second
// Still under a minute for billion password list
```

---

### BAD Example 2: ECB Mode Encryption

```pseudocode
// VULNERABLE: ECB mode reveals patterns
function encryptData(plaintext, key):
    cipher = createCipher("AES", key, mode = "ECB")
    return cipher.encrypt(plaintext)

// VULNERABLE: Default mode may be ECB in some libraries
function simpleEncrypt(data, key):
    cipher = AES.new(key)  // Some libraries default to ECB!
    return cipher.encrypt(padData(data))

// VULNERABLE: Explicit ECB for "simplicity"
function encryptUserData(userData, encryptionKey):
    algorithm = "AES/ECB/PKCS5Padding"  // Java-style
    cipher = Cipher.getInstance(algorithm)
    cipher.init(ENCRYPT_MODE, encryptionKey)
    return cipher.doFinal(userData)

// VULNERABLE: Assuming any AES is secure
function protectSensitiveData(data, key):
    // "AES is strong encryption" - but ECB mode is not
    encryptor = AESEncryptor(key, mode = "ECB")
    return encryptor.encrypt(data)
```

**Why This Is Dangerous:**
- ECB encrypts identical plaintext blocks to identical ciphertext blocks
- Patterns in plaintext are preserved in ciphertext
- Famous example: ECB-encrypted images show the original image outline
- No semantic security—attacker learns information about plaintext structure
- Block manipulation attacks possible (swap, delete, duplicate blocks)

**Visual Demonstration:**
```pseudocode
// Original image (bitmap of a penguin):
// ████████████████
// ██    ████    ██
// ██  ██████  ██
// ██████████████
// ████    ████████
// ████████████████

// After ECB encryption:
// ????????????????   ← Still shows penguin shape!
// ??    ????    ??   ← Identical colors → identical ciphertext
// ??  ??????  ??
// ??????????????
// ????    ????????
// ????????????????

// After CBC/GCM encryption:
// ????????????????   ← Random appearance
// ????????????????   ← No pattern visible
// ????????????????
// ????????????????
// ????????????????
// ????????????????
```

---

### BAD Example 3: Static IVs / Nonces

```pseudocode
// VULNERABLE: Hardcoded IV
STATIC_IV = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

function encryptMessage(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv = STATIC_IV)
    return cipher.encrypt(padData(plaintext))

// VULNERABLE: Same IV for all encryptions
class Encryptor:
    IV = generateRandomBytes(16)  // Generated ONCE at startup

    function encrypt(data, key):
        cipher = createCipher("AES-CBC", key, this.IV)
        return cipher.encrypt(data)

// VULNERABLE: Predictable IV (counter without random start)
nonce_counter = 0
function encryptWithNonce(plaintext, key):
    nonce_counter = nonce_counter + 1
    nonce = intToBytes(nonce_counter, 12)  // Predictable!
    return AES_GCM_encrypt(key, nonce, plaintext)

// VULNERABLE: IV derived from predictable data
function encryptRecord(userId, data, key):
    iv = sha256(toString(userId))[:16]  // Same IV for same user!
    return AES_CBC_encrypt(key, iv, data)

// VULNERABLE: Timestamp-based IV
function timeBasedEncrypt(data, key):
    iv = sha256(toString(getCurrentTimestamp()))[:16]
    return AES_CBC_encrypt(key, iv, data)
    // Problem: Collisions if encrypted in same second
```

**Why This Is Dangerous:**
- Same IV + same key = identical ciphertext for identical plaintext (breaks semantic security)
- In CBC mode: enables plaintext recovery through XOR analysis across messages
- In CTR mode: key stream reuse → XOR of plaintexts recoverable
- In GCM mode: nonce reuse is catastrophic—key recovery possible
- Predictable IVs enable chosen-plaintext attacks

**GCM Nonce Reuse Attack:**
```pseudocode
// If same nonce used twice with same key in GCM:
// Message 1: plaintext1, ciphertext1, tag1
// Message 2: plaintext2, ciphertext2, tag2

// Attacker can compute:
// - XOR of plaintext1 and plaintext2
// - Eventually recover the authentication key H
// - Forge arbitrary messages with valid tags

// This is a CATASTROPHIC failure of GCM mode
// "Nonce misuse resistance" modes exist (GCM-SIV) for this reason
```

---

### BAD Example 4: Math.random() for Security

```pseudocode
// VULNERABLE: Math.random for token generation
function generateResetToken():
    token = ""
    for i in range(32):
        token = token + toString(floor(random() * 16), base = 16)
    return token

// VULNERABLE: Math.random for session ID
function createSessionId():
    return "session_" + toString(random() * 1000000000)

// VULNERABLE: Seeded random with predictable seed
function generateApiKey(userId):
    setSeed(userId * getCurrentTimestamp())
    key = ""
    for i in range(32):
        key = key + randomChoice(ALPHANUMERIC_CHARS)
    return key

// VULNERABLE: Using non-crypto random for encryption IV
function quickEncrypt(data, key):
    iv = []
    for i in range(16):
        iv.append(floor(random() * 256))
    return AES_CBC_encrypt(key, iv, data)

// VULNERABLE: JavaScript Math.random() is NOT cryptographic
function generateToken():
    return btoa(String.fromCharCode.apply(null,
        Array.from({length: 32}, () => Math.floor(Math.random() * 256))
    ))
```

**Why This Is Dangerous:**
- Math.random() uses predictable pseudo-random number generators (PRNG)
- Internal state can be recovered from ~600 outputs (in V8 engine)
- Once state is known, all past and future values are predictable
- Session tokens, API keys, and reset tokens become guessable
- Many PRNG implementations have short periods or weak seeding

**State Recovery Attack:**
```pseudocode
// Attacker collects multiple password reset tokens
tokens_observed = [
    "a3f7c2e9b1d4...",  // Token 1
    "8e2a5f1c9b3d...",  // Token 2
    // ... collect ~30-50 tokens
]

// Using z3 SMT solver or custom reversing:
function recoverMathRandomState(observed_outputs):
    // V8's xorshift128+ can be reversed
    // Once state recovered, predict next token
    state = reverseEngineerState(observed_outputs)
    next_token = predictNextOutput(state)
    return next_token

// Attacker generates password reset for victim
// Then predicts the token value
// Completes password reset without email access
```

---

### BAD Example 5: Hardcoded Symmetric Keys

```pseudocode
// VULNERABLE: Key in source code
ENCRYPTION_KEY = "MySecretKey12345"

function encryptUserData(data):
    return AES_encrypt(ENCRYPTION_KEY, data)

// VULNERABLE: Key derived from application constant
function getEncryptionKey():
    return sha256(APPLICATION_NAME + ENVIRONMENT + "secret")

// VULNERABLE: Same key for all users
MASTER_KEY = bytes.fromhex("0123456789abcdef0123456789abcdef")

function encryptForUser(userId, data):
    return AES_encrypt(MASTER_KEY, data)

// VULNERABLE: Key in configuration file (committed to git)
// config.py:
CRYPTO_CONFIG = {
    "encryption_key": "dGhpcyBpcyBhIHNlY3JldCBrZXk=",  // Base64 encoded
    "hmac_key": "another_secret_key_here"
}

// VULNERABLE: Weak key (too short)
function quickEncrypt(data):
    key = "short"  // 5 bytes, not 16/24/32
    return AES_encrypt(pad(key, 16), data)  // Padded with zeros!
```

**Why This Is Dangerous:**
- Keys in source code are exposed in version control history forever
- Hardcoded keys cannot be rotated without code deployment
- Compilation/decompilation exposes keys in binaries
- Single key compromise affects all encrypted data
- Weak/short keys can be brute-forced
- Key derivation from predictable inputs allows reconstruction

---

### BAD Example 6: Weak Key Derivation

```pseudocode
// VULNERABLE: Direct use of password as key
function deriveKey(password):
    return password.encode()[:32]  // Truncate or pad to key size

// VULNERABLE: Simple hash as key derivation
function passwordToKey(password):
    return sha256(password)  // Single round, no salt

// VULNERABLE: MD5-based key derivation
function getKeyFromPassword(password, salt):
    return md5(password + salt)

// VULNERABLE: Insufficient iterations
function deriveKeyPBKDF2(password, salt):
    return PBKDF2(password, salt, iterations = 1000)
    // 2025 recommendation: minimum 600,000 for SHA256

// VULNERABLE: Using key derivation output directly for multiple purposes
function setupCrypto(password, salt):
    derived = PBKDF2(password, salt, iterations = 100000, keyLength = 64)
    encryptionKey = derived[:32]   // First half
    hmacKey = derived[32:]         // Second half
    // Problem: related keys, should use separate derivations

// VULNERABLE: Weak salt (too short, predictable, or reused)
function deriveKeyWithWeakSalt(password):
    salt = "salt"  // Static salt defeats purpose
    return PBKDF2(password, salt, iterations = 100000)
```

**Why This Is Dangerous:**
- Direct password use gives attackers dictionary attack advantage
- Single-hash derivation enables GPU-accelerated brute force
- Low iteration counts make PBKDF2/bcrypt fast to attack
- MD5 key derivation inherits all MD5 weaknesses
- Static/weak salt enables precomputation attacks
- Related key derivation can expose cryptographic weaknesses

**Iteration Count Guidance (2025):**
```pseudocode
// PBKDF2-SHA256 minimum iterations by use case:
// - Interactive login (100ms budget): 600,000 iterations
// - Background/async (1s budget): 2,000,000 iterations
// - High-security (offline storage): 10,000,000 iterations

// bcrypt cost factor:
// - Minimum 2025: cost = 12 (about 250ms)
// - Recommended: cost = 13-14
// - High-security: cost = 15+

// Argon2id parameters (2025):
// - Memory: 64 MB minimum, 256 MB recommended
// - Iterations: 3 minimum
// - Parallelism: match available cores
// - Argon2id recommended over Argon2i or Argon2d
```

---

## GOOD Examples: Secure Cryptographic Patterns

### GOOD Example 1: Proper Password Hashing with bcrypt/Argon2

```pseudocode
// SECURE: bcrypt with appropriate cost factor
function hashPassword(password):
    // Cost factor 12 = ~250ms on modern hardware
    // Increase cost factor annually as hardware improves
    cost = 12
    return bcrypt.hash(password, cost)

function verifyPassword(password, storedHash):
    // bcrypt.verify handles timing-safe comparison internally
    return bcrypt.verify(password, storedHash)

// SECURE: Argon2id (recommended for new applications)
function hashPasswordArgon2(password):
    // Argon2id: hybrid resistant to both side-channel and GPU attacks
    options = {
        type: ARGON2ID,
        memoryCost: 65536,    // 64 MB
        timeCost: 3,          // 3 iterations
        parallelism: 4,       // 4 parallel threads
        hashLength: 32        // 256-bit output
    }
    return argon2.hash(password, options)

function verifyPasswordArgon2(password, storedHash):
    return argon2.verify(storedHash, password)

// SECURE: scrypt for memory-hard hashing
function hashPasswordScrypt(password):
    // N = CPU/memory cost (power of 2)
    // r = block size
    // p = parallelization parameter
    salt = generateSecureRandom(16)
    hash = scrypt(password, salt, N = 2^17, r = 8, p = 1, keyLen = 32)
    return encodeSaltAndHash(salt, hash)

// SECURE: Migrating from weak to strong hashing
function upgradePasswordHash(userId, password, currentHash):
    // Verify against old hash
    if legacyVerify(password, currentHash):
        // Re-hash with modern algorithm
        newHash = hashPasswordArgon2(password)
        database.update("users", userId, {"password_hash": newHash})
        return true
    return false
```

**Why This Is Secure:**
- bcrypt/argon2/scrypt are deliberately slow (memory-hard)
- Built-in salt generation and storage
- Timing-safe comparison built into verify functions
- Configurable work factors allow future-proofing
- Argon2id is resistant to both GPU attacks and side-channel attacks

---

### GOOD Example 2: Authenticated Encryption (GCM Mode)

```pseudocode
// SECURE: AES-256-GCM with proper nonce handling
function encryptAESGCM(plaintext, key):
    // Generate cryptographically random 96-bit nonce
    nonce = generateSecureRandom(12)

    cipher = createCipher("AES-256-GCM", key)
    cipher.setNonce(nonce)

    // Optional: Add authenticated additional data (AAD)
    // AAD is authenticated but NOT encrypted
    aad = "context:user_data:v1"
    cipher.setAAD(aad)

    ciphertext = cipher.encrypt(plaintext)
    authTag = cipher.getAuthTag()  // 128-bit tag

    // Return nonce + tag + ciphertext (all needed for decryption)
    return nonce + authTag + ciphertext

function decryptAESGCM(encryptedData, key):
    // Extract components
    nonce = encryptedData[:12]
    authTag = encryptedData[12:28]
    ciphertext = encryptedData[28:]

    cipher = createCipher("AES-256-GCM", key)
    cipher.setNonce(nonce)
    cipher.setAAD("context:user_data:v1")  // Must match encryption
    cipher.setAuthTag(authTag)

    try:
        plaintext = cipher.decrypt(ciphertext)
        return plaintext
    catch AuthenticationError:
        // Tag verification failed - data tampered or wrong key
        log.warn("Decryption authentication failed - possible tampering")
        return null

// SECURE: XChaCha20-Poly1305 (extended nonce variant)
function encryptXChaCha(plaintext, key):
    // 192-bit nonce - safe for random generation
    nonce = generateSecureRandom(24)

    ciphertext, tag = xchachapoly.encrypt(key, nonce, plaintext)

    return nonce + tag + ciphertext
```

**Why This Is Secure:**
- GCM provides both confidentiality AND integrity
- Authentication tag detects any tampering
- 96-bit nonces are safe for random generation up to ~2^32 messages per key
- XChaCha20 has 192-bit nonce, safe for effectively unlimited messages
- AAD allows binding ciphertext to context (prevents cross-context attacks)

---

### GOOD Example 3: Proper IV/Nonce Generation

```pseudocode
// SECURE: Random IV for CBC mode
function encryptCBC(plaintext, key):
    // 128-bit random IV for AES
    iv = generateSecureRandom(16)

    cipher = createCipher("AES-256-CBC", key)
    ciphertext = cipher.encrypt(plaintext, iv)

    // Prepend IV to ciphertext (IV doesn't need to be secret)
    return iv + ciphertext

function decryptCBC(encryptedData, key):
    iv = encryptedData[:16]
    ciphertext = encryptedData[16:]

    cipher = createCipher("AES-256-CBC", key)
    return cipher.decrypt(ciphertext, iv)

// SECURE: Counter-based nonce with random prefix (for GCM)
class SecureNonceGenerator:
    // Random 32-bit prefix + 64-bit counter
    // Safe for 2^64 messages with same key

    function __init__():
        this.prefix = generateSecureRandom(4)  // 32-bit random
        this.counter = 0
        this.lock = Mutex()

    function generate():
        this.lock.acquire()
        this.counter = this.counter + 1
        if this.counter >= 2^64:
            throw Error("Nonce counter exhausted - rotate key")
        nonce = this.prefix + intToBytes(this.counter, 8)
        this.lock.release()
        return nonce

// SECURE: Synthetic IV (SIV) for nonce-misuse resistance
function encryptSIV(plaintext, key):
    // AES-GCM-SIV: Safe even if nonce is accidentally repeated
    nonce = generateSecureRandom(12)
    ciphertext = AES_GCM_SIV_encrypt(key, nonce, plaintext)
    return nonce + ciphertext
    // Note: Repeated nonce only leaks if same plaintext encrypted
```

**Why This Is Secure:**
- Random IVs prevent pattern analysis across messages
- Prepending IV to ciphertext ensures IV is always available for decryption
- Counter with random prefix prevents nonce collision across instances
- SIV modes provide safety net against accidental nonce reuse

---

### GOOD Example 4: Cryptographically Secure Random

```pseudocode
// SECURE: Using OS/platform CSPRNG

// Node.js
function generateSecureRandom(length):
    return crypto.randomBytes(length)

// Python
function generateSecureRandom(length):
    return secrets.token_bytes(length)

// Java
function generateSecureRandom(length):
    random = SecureRandom.getInstanceStrong()
    bytes = new byte[length]
    random.nextBytes(bytes)
    return bytes

// Go
function generateSecureRandom(length):
    bytes = make([]byte, length)
    _, err = crypto_rand.Read(bytes)
    if err != nil:
        panic("CSPRNG failure")
    return bytes

// SECURE: Token generation for URLs/APIs
function generateUrlSafeToken(length):
    // Generate random bytes, encode to URL-safe base64
    randomBytes = generateSecureRandom(length)
    return base64UrlEncode(randomBytes)

function generateResetToken():
    // 256 bits of entropy for password reset token
    return generateUrlSafeToken(32)

function generateApiKey():
    // Prefix for identification + random component
    prefix = "sk_live_"
    randomPart = generateUrlSafeToken(24)
    return prefix + randomPart

// SECURE: Random number in range
function secureRandomInt(min, max):
    range = max - min + 1
    bytesNeeded = ceil(log2(range) / 8)

    // Rejection sampling to avoid modulo bias
    while true:
        randomBytes = generateSecureRandom(bytesNeeded)
        value = bytesToInt(randomBytes)
        if value < (2^(bytesNeeded*8) / range) * range:
            return min + (value % range)
```

**Why This Is Secure:**
- CSPRNG (Cryptographically Secure PRNG) uses OS entropy sources
- Cannot be predicted even with complete knowledge of outputs
- Proper rejection sampling avoids modulo bias
- Standard libraries provide secure defaults when used correctly

---

### GOOD Example 5: Key Derivation Functions

```pseudocode
// SECURE: PBKDF2 with sufficient iterations
function deriveKeyPBKDF2(password, purpose):
    // Generate unique salt per derivation
    salt = generateSecureRandom(16)

    // 600,000 iterations minimum for SHA-256 (2025)
    iterations = 600000

    // Derive key of required length
    derivedKey = PBKDF2(
        password = password,
        salt = salt,
        iterations = iterations,
        keyLength = 32,  // 256 bits
        hashFunction = SHA256
    )

    // Store salt with derived key for later verification
    return {salt: salt, key: derivedKey}

// SECURE: HKDF for deriving multiple keys from one secret
function deriveMultipleKeys(masterSecret, purpose):
    // HKDF-Extract: Create pseudorandom key from input
    salt = generateSecureRandom(32)
    prk = HKDF_Extract(salt, masterSecret)

    // HKDF-Expand: Derive purpose-specific keys
    encryptionKey = HKDF_Expand(prk, info = "encryption", length = 32)
    hmacKey = HKDF_Expand(prk, info = "authentication", length = 32)
    searchKey = HKDF_Expand(prk, info = "search-index", length = 32)

    return {
        encryption: encryptionKey,
        hmac: hmacKey,
        search: searchKey,
        salt: salt  // Store for re-derivation
    }

// SECURE: Argon2 for password-based key derivation
function deriveKeyFromPassword(password, salt = null):
    if salt == null:
        salt = generateSecureRandom(16)

    derivedKey = argon2id(
        password = password,
        salt = salt,
        memoryCost = 65536,    // 64 MB
        timeCost = 3,
        parallelism = 4,
        outputLength = 32
    )

    return {key: derivedKey, salt: salt}

// SECURE: Key derivation with domain separation
function deriveKeyWithContext(masterKey, context, subkeyId):
    // Context prevents cross-purpose key use
    info = context + ":" + subkeyId
    return HKDF_Expand(masterKey, info, 32)

// Example: Derive per-user encryption keys
function getUserEncryptionKey(masterKey, userId):
    return deriveKeyWithContext(masterKey, "user-data-encryption", userId)
```

**Why This Is Secure:**
- High iteration counts make brute-force impractical
- HKDF properly separates multiple keys from one source
- Domain separation prevents keys derived for one purpose being used for another
- Argon2 provides memory-hard protection against GPU attacks
- Unique salt per derivation prevents precomputation attacks

---

### GOOD Example 6: Key Rotation Patterns

```pseudocode
// SECURE: Key versioning for rotation
class KeyManager:
    function __init__(keyStore):
        this.keyStore = keyStore
        this.currentKeyVersion = keyStore.getCurrentVersion()

    function encrypt(plaintext):
        key = this.keyStore.getKey(this.currentKeyVersion)
        nonce = generateSecureRandom(12)

        ciphertext = AES_GCM_encrypt(key, nonce, plaintext)

        // Include key version in output for decryption
        return encodeVersionedCiphertext(
            version = this.currentKeyVersion,
            nonce = nonce,
            ciphertext = ciphertext
        )

    function decrypt(encryptedData):
        version, nonce, ciphertext = decodeVersionedCiphertext(encryptedData)

        // Fetch correct key version (may be old version)
        key = this.keyStore.getKey(version)
        if key == null:
            throw KeyNotFoundError("Key version " + version + " not available")

        return AES_GCM_decrypt(key, nonce, ciphertext)

    function rotateKey():
        newVersion = this.currentKeyVersion + 1
        newKey = generateSecureRandom(32)
        this.keyStore.storeKey(newVersion, newKey)
        this.currentKeyVersion = newVersion

        // Schedule background re-encryption of old data
        scheduleReEncryption(newVersion - 1, newVersion)

// SECURE: Re-encryption during key rotation
function reEncryptData(dataId, oldVersion, newVersion, keyManager):
    // Fetch encrypted data
    encryptedData = database.get("encrypted_data", dataId)

    // Verify it uses old key version
    currentVersion = extractKeyVersion(encryptedData)
    if currentVersion >= newVersion:
        return  // Already using new or newer key

    // Decrypt with old key, re-encrypt with new
    plaintext = keyManager.decrypt(encryptedData)
    newEncryptedData = keyManager.encrypt(plaintext)

    // Atomic update
    database.update("encrypted_data", dataId, {
        "data": newEncryptedData,
        "key_version": newVersion,
        "rotated_at": getCurrentTimestamp()
    })

// SECURE: Key wrapping for storage
function storeEncryptionKey(keyToStore, masterKey):
    // Wrap (encrypt) the key with master key
    nonce = generateSecureRandom(12)
    wrappedKey = AES_GCM_encrypt(masterKey, nonce, keyToStore)

    return {
        wrapped_key: wrappedKey,
        nonce: nonce,
        algorithm: "AES-256-GCM",
        created_at: getCurrentTimestamp()
    }

function retrieveEncryptionKey(wrappedKeyData, masterKey):
    return AES_GCM_decrypt(
        masterKey,
        wrappedKeyData.nonce,
        wrappedKeyData.wrapped_key
    )
```

**Why This Is Secure:**
- Key versioning allows old data to remain decryptable during rotation
- Background re-encryption gradually migrates all data to new key
- Key wrapping protects stored keys at rest
- Gradual rotation minimizes operational risk

---

## Edge Cases Section

### Edge Case 1: Padding Oracle Vulnerabilities

```pseudocode
// VULNERABLE: Revealing padding validity in error messages
function decryptCBC_vulnerable(ciphertext, key, iv):
    try:
        plaintext = AES_CBC_decrypt(key, iv, ciphertext)
        unpadded = removePKCS7Padding(plaintext)
        return {success: true, data: unpadded}
    catch PaddingError:
        return {success: false, error: "Invalid padding"}  // ORACLE!
    catch DecryptionError:
        return {success: false, error: "Decryption failed"}

// Attack: Padding oracle allows full plaintext recovery
// Attacker modifies ciphertext bytes, observes padding errors
// ~128 requests per byte to recover plaintext (on average)

// SECURE: Use authenticated encryption (GCM) or constant-time handling
function decryptCBC_secure(ciphertext, key, iv):
    try:
        // First verify HMAC before any decryption
        providedHmac = ciphertext[-32:]
        ciphertextData = ciphertext[:-32]

        expectedHmac = HMAC_SHA256(key, iv + ciphertextData)
        if not constantTimeEquals(providedHmac, expectedHmac):
            return {success: false, error: "Decryption failed"}  // Generic error

        plaintext = AES_CBC_decrypt(key, iv, ciphertextData)
        unpadded = removePKCS7Padding(plaintext)
        return {success: true, data: unpadded}
    catch:
        return {success: false, error: "Decryption failed"}  // Same error always

// BEST: Just use GCM which prevents this class of attack entirely
```

**Lesson Learned:**
- Never reveal whether padding was valid or invalid
- Always use authenticated encryption (encrypt-then-MAC or GCM)
- Return identical errors for all decryption failures

---

### Edge Case 2: Length Extension Attacks

```pseudocode
// VULNERABLE: Using hash(secret + message) for authentication
function createAuthToken(secretKey, message):
    return sha256(secretKey + message)  // Length extension vulnerable!

function verifyAuthToken(secretKey, message, token):
    expected = sha256(secretKey + message)
    return token == expected

// Attack: Attacker knows hash(secret + message) and length of secret
// Can compute hash(secret + message + padding + attacker_data)
// Without knowing the secret!

// Example attack:
// Original: hash(secret + "amount=100") = abc123...
// Attacker computes: hash(secret + "amount=100" + padding + "&amount=999")
// Server verifies this as valid!

// SECURE: Use HMAC
function createAuthTokenSecure(secretKey, message):
    return HMAC_SHA256(secretKey, message)

function verifyAuthTokenSecure(secretKey, message, token):
    expected = HMAC_SHA256(secretKey, message)
    return constantTimeEquals(token, expected)

// SECURE: Use hash(message + secret) - prevents extension but HMAC preferred
// SECURE: Use SHA-3/SHA-512/256 (resistant to length extension)
function alternativeAuth(secretKey, message):
    return SHA3_256(secretKey + message)  // SHA-3 is resistant
```

**Lesson Learned:**
- Never use hash(key + message) for authentication
- HMAC is specifically designed to prevent length extension
- SHA-3 family is resistant but HMAC is still recommended for consistency

---

### Edge Case 3: Timing Attacks on Comparison

```pseudocode
// VULNERABLE: Early-exit string comparison
function verifyToken(providedToken, expectedToken):
    if length(providedToken) != length(expectedToken):
        return false
    for i in range(length(providedToken)):
        if providedToken[i] != expectedToken[i]:
            return false  // Early exit reveals position of first difference
    return true

// Attack: Timing differences reveal correct characters
// Correct first char: ~1μs longer than wrong first char
// Attacker can brute-force character-by-character

// VULNERABLE: Using == operator (language-dependent timing)
function checkHmac(provided, expected):
    return provided == expected  // May have variable-time implementation

// SECURE: Constant-time comparison
function constantTimeEquals(a, b):
    if length(a) != length(b):
        // Still constant-time for the comparison
        // Length difference may leak - consider padding
        return false

    result = 0
    for i in range(length(a)):
        // XOR and OR accumulate differences without early exit
        result = result | (a[i] XOR b[i])
    return result == 0

// SECURE: Using crypto library comparison
function verifyHmacSecure(message, providedHmac, key):
    expectedHmac = HMAC_SHA256(key, message)
    return crypto.timingSafeEqual(providedHmac, expectedHmac)

// SECURE: Double-HMAC comparison (timing-safe by design)
function verifyWithDoubleHmac(message, providedMac, key):
    expectedMac = HMAC_SHA256(key, message)
    // Compare HMACs of the MACs - timing doesn't leak original MAC
    return HMAC_SHA256(key, providedMac) == HMAC_SHA256(key, expectedMac)
```

**Lesson Learned:**
- Use constant-time comparison for all secret-dependent operations
- Most languages have crypto libraries with timing-safe functions
- Double-HMAC trick works when constant-time compare isn't available

---

### Edge Case 4: Key Reuse Across Contexts

```pseudocode
// VULNERABLE: Same key for encryption and authentication
SHARED_KEY = loadKey("master")

function encryptData(data):
    return AES_GCM_encrypt(SHARED_KEY, generateNonce(), data)

function signData(data):
    return HMAC_SHA256(SHARED_KEY, data)  // Same key!

// Problem: Cryptographic interactions between uses
// Some attacks become possible when key is used in multiple algorithms

// VULNERABLE: Same key for different users/tenants
function encryptForTenant(tenantId, data):
    return AES_GCM_encrypt(MASTER_KEY, generateNonce(), data)
    // All tenants share encryption key - one compromise = all compromised

// SECURE: Derive separate keys for each purpose
MASTER_KEY = loadKey("master")

function getEncryptionKey():
    return HKDF_Expand(MASTER_KEY, "encryption-aes-256-gcm", 32)

function getAuthenticationKey():
    return HKDF_Expand(MASTER_KEY, "authentication-hmac-sha256", 32)

function getSearchKey():
    return HKDF_Expand(MASTER_KEY, "searchable-encryption", 32)

// SECURE: Per-tenant key derivation
function getTenantEncryptionKey(tenantId):
    // Each tenant gets unique derived key
    info = "tenant-encryption:" + tenantId
    return HKDF_Expand(MASTER_KEY, info, 32)

function encryptForTenantSecure(tenantId, data):
    tenantKey = getTenantEncryptionKey(tenantId)
    return AES_GCM_encrypt(tenantKey, generateNonce(), data)
```

**Lesson Learned:**
- Always derive separate keys for different cryptographic operations
- Use domain separation (different "info" parameters) in HKDF
- Per-tenant/per-user key derivation limits blast radius of compromise

---

## Common Mistakes Section

### Common Mistake 1: Using Encryption Without Authentication

```pseudocode
// COMMON MISTAKE: CBC encryption without HMAC
function encryptDataWrong(data, key):
    iv = generateSecureRandom(16)
    ciphertext = AES_CBC_encrypt(key, iv, data)
    return iv + ciphertext
    // Missing: No way to detect tampering!

// Attack: Bit-flipping in CBC mode
// Flipping bit N in ciphertext block C[i] flips bit N in plaintext block P[i+1]
// Attacker can modify data without detection

// Example: Encrypted JSON {"admin": false, "amount": 100}
// Attacker can flip bits to change "false" to "true" or modify amount

// CORRECT: Encrypt-then-MAC
function encryptDataCorrect(data, encKey, macKey):
    iv = generateSecureRandom(16)
    ciphertext = AES_CBC_encrypt(encKey, iv, data)

    // MAC covers IV and ciphertext
    mac = HMAC_SHA256(macKey, iv + ciphertext)

    return iv + ciphertext + mac

function decryptDataCorrect(encrypted, encKey, macKey):
    iv = encrypted[:16]
    mac = encrypted[-32:]
    ciphertext = encrypted[16:-32]

    // Verify MAC FIRST, before any decryption
    expectedMac = HMAC_SHA256(macKey, iv + ciphertext)
    if not constantTimeEquals(mac, expectedMac):
        throw IntegrityError("Data has been tampered with")

    return AES_CBC_decrypt(encKey, iv, ciphertext)

// BETTER: Just use GCM which includes authentication
function encryptDataBest(data, key):
    nonce = generateSecureRandom(12)
    ciphertext, tag = AES_GCM_encrypt(key, nonce, data)
    return nonce + ciphertext + tag
```

**Solution:**
- Always use authenticated encryption (GCM, ChaCha20-Poly1305)
- If using CBC, add HMAC with encrypt-then-MAC pattern
- Verify authentication tag BEFORE decryption

---

### Common Mistake 2: Confusing Encoding with Encryption

```pseudocode
// COMMON MISTAKE: Base64 as "encryption"
function "encrypt"Data(sensitiveData):
    return base64Encode(sensitiveData)  // NOT ENCRYPTION!

function "decrypt"Data(encodedData):
    return base64Decode(encodedData)

// COMMON MISTAKE: XOR with short key as encryption
function "encrypt"WithXor(data, password):
    key = password.repeat(ceil(length(data) / length(password)))
    return xor(data, key)  // Trivially broken with frequency analysis

// COMMON MISTAKE: ROT13 or character substitution
function "encrypt"Text(text):
    return rot13(text)  // No security at all

// COMMON MISTAKE: Obfuscation ≠ encryption
function storeApiKey(apiKey):
    obfuscated = ""
    for char in apiKey:
        obfuscated += chr(ord(char) + 5)  // Just shifted characters
    return obfuscated

// COMMON MISTAKE: Custom "encryption" algorithm
function myEncrypt(data, key):
    result = ""
    for i, char in enumerate(data):
        newChar = chr((ord(char) + ord(key[i % len(key)]) * 7) % 256)
        result += newChar
    return result  // Easily broken - don't invent crypto!
```

**Reality Check:**
| Method | Security Level | Use Case |
|--------|----------------|----------|
| Base64 | 0 (None) | Binary-to-text encoding only |
| ROT13 | 0 (None) | Jokes, spoiler hiding |
| XOR with repeated key | Trivially broken | Never use |
| Homegrown "encryption" | Unknown, likely broken | Never use |
| AES-GCM with random key | Strong | Actual encryption |

**Solution:**
- Use standard algorithms: AES-GCM, ChaCha20-Poly1305
- Never invent cryptographic algorithms
- Encoding (Base64, hex) is for representation, not security

---

### Common Mistake 3: Improper Key Storage After Generation

```pseudocode
// COMMON MISTAKE: Logging the key
function generateAndStoreKey():
    key = generateSecureRandom(32)
    log.info("Generated new encryption key: " + hexEncode(key))  // LOGGED!
    return key

// COMMON MISTAKE: Key in config file committed to git
// config.json:
{
    "database_url": "...",
    "encryption_key": "a1b2c3d4e5f6..."  // Will be in git history forever
}

// COMMON MISTAKE: Key in environment variable visible in process list
// Launching: ENCRYPTION_KEY=secret123 ./myapp
// `ps aux` shows: myapp ENCRYPTION_KEY=secret123

// COMMON MISTAKE: Key stored in database alongside encrypted data
function storeEncryptedData(userId, sensitiveData):
    key = generateSecureRandom(32)
    encrypted = AES_GCM_encrypt(key, generateNonce(), sensitiveData)
    database.insert("user_data", {
        user_id: userId,
        encrypted_data: encrypted,
        encryption_key: key  // KEY NEXT TO DATA = pointless encryption
    })

// COMMON MISTAKE: Key derivation material stored insecurely
function setupEncryption(password):
    salt = generateSecureRandom(16)
    key = deriveKey(password, salt)

    // Storing in easily accessible location
    localStorage.setItem("encryption_salt", salt)
    localStorage.setItem("derived_key", key)  // KEY IN BROWSER STORAGE!
```

**Secure Key Storage Patterns:**
```pseudocode
// SECURE: Using a key management service (KMS)
function storeKeySecurely(keyId, keyMaterial):
    // AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault
    kms.storeKey(keyId, keyMaterial, {
        rotation_period: "90 days",
        deletion_protection: true,
        access_policy: restrictedPolicy
    })

// SECURE: Key wrapped with hardware security module (HSM)
function wrapKeyForStorage(dataKey):
    wrappingKey = hsm.getWrappingKey()  // Never leaves HSM
    wrappedKey = hsm.wrapKey(dataKey, wrappingKey)
    return wrappedKey  // Safe to store - can only unwrap with HSM

// SECURE: Envelope encryption pattern
function envelopeEncrypt(data):
    // Generate data encryption key (DEK)
    dek = generateSecureRandom(32)

    // Encrypt data with DEK
    encryptedData = AES_GCM_encrypt(dek, generateNonce(), data)

    // Encrypt DEK with key encryption key (KEK) from KMS
    encryptedDek = kms.encrypt(dek)

    // Store encrypted DEK with encrypted data
    return {
        encrypted_data: encryptedData,
        encrypted_key: encryptedDek,  // DEK is encrypted, safe to store
        kms_key_id: kms.getCurrentKeyId()
    }
```

---

## Algorithm Selection Guidance

### Symmetric Encryption

| Algorithm | Key Size | Use Case | Notes |
|-----------|----------|----------|-------|
| **AES-256-GCM** | 256 bits | General purpose | Recommended default, 96-bit nonce |
| **ChaCha20-Poly1305** | 256 bits | Performance-sensitive, mobile | Faster without AES-NI hardware |
| **XChaCha20-Poly1305** | 256 bits | High-volume encryption | 192-bit nonce, safe for random generation |
| **AES-256-GCM-SIV** | 256 bits | Nonce-misuse resistant | Slightly slower, safer with accidental reuse |

**Avoid:** DES, 3DES, RC4, Blowfish, AES-ECB, AES-CBC without HMAC

### Password Hashing

| Algorithm | Memory | Use Case | Notes |
|-----------|--------|----------|-------|
| **Argon2id** | 64+ MB | New applications | Best protection, memory-hard |
| **bcrypt** | N/A | Legacy compatibility | Widely supported, cost 12+ |
| **scrypt** | 64+ MB | When Argon2 unavailable | Good alternative |

**Avoid:** MD5, SHA1, SHA256 (single round), PBKDF2 with <600k iterations

### Key Derivation

| Algorithm | Use Case | Notes |
|-----------|----------|-------|
| **Argon2id** | Password-based | Best for password → key |
| **HKDF** | Key expansion | Deriving multiple keys from one |
| **PBKDF2-SHA256** | Compatibility | 600k+ iterations required |

**Avoid:** MD5-based KDF, single-hash derivation, low iteration counts

### Message Authentication

| Algorithm | Output | Use Case | Notes |
|-----------|--------|----------|-------|
| **HMAC-SHA256** | 256 bits | General purpose | Standard choice |
| **HMAC-SHA512** | 512 bits | Extra security margin | Faster on 64-bit |
| **Poly1305** | 128 bits | With ChaCha20 | Part of AEAD |

**Avoid:** MD5, SHA1, plain hash without HMAC construction

### Digital Signatures

| Algorithm | Use Case | Notes |
|-----------|----------|-------|
| **Ed25519** | General purpose | Fast, secure, simple API |
| **ECDSA P-256** | Compatibility | Widely supported |
| **RSA-PSS** | Legacy systems | 2048+ bit key required |

**Avoid:** RSA PKCS#1 v1.5, DSA, ECDSA with weak curves

---

## Detection Hints: How to Spot Cryptographic Issues

### Code Review Patterns

```pseudocode
// RED FLAGS in cryptographic code:

// 1. Weak hash functions
md5(               // Search for: md5\s*\(
sha1(              // Search for: sha1\s*\(
SHA1.Create()      // Search for: SHA1

// 2. ECB mode
mode = "ECB"       // Search for: ECB
AES/ECB/           // Search for: /ECB/
mode_ECB           // Search for: ECB

// 3. Static or weak IVs
iv = [0, 0, 0, ...   // Search for: iv\s*=\s*\[0
IV = "0000           // Search for: IV\s*=\s*["']0
static IV            // Search for: static.*[Ii][Vv]

// 4. Math.random for security
Math.random()        // Search for: Math\.random
random.randint(      // Search for: randint\( (context matters)

// 5. Weak secrets
= "secret"           // Search for: =\s*["']secret
SECRET = "           // Search for: SECRET\s*=\s*["']
= "password"         // Search for: =\s*["']password

// 6. Direct password use as key
key = password       // Search for: key\s*=\s*password
AES(password)        // Search for: AES\s*\(\s*password

// 7. Low iteration counts
iterations: 1000     // Search for: iterations.*\d{1,4}[^0-9]
rounds = 100         // Search for: rounds\s*=\s*\d{1,3}[^0-9]

// GREP patterns for security review:
// [Mm][Dd]5\s*\(
// [Ss][Hh][Aa]1\s*\(
// ECB
// [Ii][Vv]\s*=\s*\[0
// Math\.random
// iterations.*[0-9]{1,4}[^0-9]
// (password|secret)\s*=\s*["']
```

### Security Testing Checklist

```pseudocode
// Cryptographic security test cases:

// 1. Algorithm verification
- [ ] No MD5 or SHA1 for password hashing
- [ ] No ECB mode encryption
- [ ] AES key size is 256 bits (not 128)
- [ ] Authenticated encryption used (GCM, ChaCha20-Poly1305)

// 2. Randomness verification
- [ ] IVs/nonces are cryptographically random
- [ ] Session tokens use CSPRNG
- [ ] No predictable seeds for random generation

// 3. Key management
- [ ] Keys not hardcoded in source
- [ ] Keys not logged or exposed in errors
- [ ] Key derivation uses appropriate KDF
- [ ] Key rotation mechanism exists

// 4. Password hashing
- [ ] bcrypt cost ≥ 12 or Argon2 with appropriate params
- [ ] Unique salt per password
- [ ] Timing-safe comparison used

// 5. Implementation details
- [ ] Constant-time comparison for secrets
- [ ] No padding oracle vulnerabilities
- [ ] HMAC used (not hash(key+message))
- [ ] Authenticated encryption or encrypt-then-MAC
```

---

## Security Checklist

- [ ] Password hashing uses Argon2id, bcrypt (cost 12+), or scrypt
- [ ] All passwords have unique, random salts (automatically handled by bcrypt/Argon2)
- [ ] No MD5, SHA1, or single-round SHA256 for security-sensitive hashing
- [ ] Encryption uses authenticated modes (AES-GCM, ChaCha20-Poly1305)
- [ ] No ECB mode encryption
- [ ] IVs/nonces generated with cryptographically secure random
- [ ] Each encryption operation uses unique IV/nonce
- [ ] GCM nonces tracked to prevent reuse (or use SIV modes)
- [ ] All random values for security use CSPRNG (crypto.randomBytes, secrets module)
- [ ] No Math.random() or similar PRNGs for security
- [ ] Encryption keys are 256 bits and properly random
- [ ] No hardcoded keys in source code
- [ ] Keys derived with HKDF, PBKDF2 (600k+ iterations), or Argon2
- [ ] Separate keys derived for different cryptographic operations
- [ ] Key rotation mechanism implemented
- [ ] Keys stored in KMS, HSM, or encrypted at rest
- [ ] Timing-safe comparison used for all secret comparisons
- [ ] HMAC used instead of hash(key+message)
- [ ] Error messages don't reveal cryptographic details (padding validity, etc.)
- [ ] No custom cryptographic algorithms—only standard, vetted primitives

---
