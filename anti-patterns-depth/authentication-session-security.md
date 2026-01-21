# Pattern 4: Authentication and Session Security

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


**CWE References:** CWE-287 (Improper Authentication), CWE-384 (Session Fixation), CWE-613 (Insufficient Session Expiration), CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-308 (Use of Single-factor Authentication), CWE-640 (Weak Password Recovery Mechanism), CWE-1275 (Sensitive Cookie with Improper SameSite Attribute)

**Priority Score:** 22 (Frequency: 8, Severity: 9, Detectability: 5)

---

## Introduction: High Complexity Leads to High AI Error Rate

Authentication and session management represent one of the most complex security domains in application development. AI models struggle particularly with these patterns for several interconnected reasons:

**Why AI Models Generate Insecure Authentication Code:**

1. **Complexity Breeds Shortcuts:** Authentication requires coordinating multiple components—password storage, session management, token generation, cookie handling, and logout procedures. AI models often generate "working" code that skips essential security layers for simplicity.

2. **Tutorial Syndrome:** Training data is saturated with simplified authentication tutorials designed to teach concepts, not build production systems. These tutorials often omit rate limiting, secure token generation, proper session invalidation, and timing attack prevention.

3. **JWT Misunderstandings:** JSON Web Tokens have become the default recommendation, but AI models frequently generate JWT implementations with critical flaws—the "none" algorithm vulnerability, weak secrets, improper validation, and insecure storage.

4. **Framework Diversity:** Authentication patterns vary dramatically across frameworks (Passport.js, Spring Security, Django, Rails Devise, etc.). AI models conflate patterns between frameworks, generating hybrid code that's neither correct for any framework nor secure.

5. **Stateless vs. Stateful Confusion:** The shift toward stateless authentication (JWTs) has created mixed patterns in training data. AI often combines stateless token concepts with stateful session assumptions, creating logical gaps in security.

6. **Edge Case Blindness:** Authentication edge cases—concurrent sessions, password reset flows, account recovery, MFA, and OAuth state management—require deep security thinking that AI models cannot reliably produce.

**Impact Statistics:**

- **75.8%** of developers believe AI-generated authentication code is secure (Snyk State of AI Security Survey 2024)
- **63%** of data breaches involve weak, default, or stolen credentials (Verizon DBIR 2024)
- Authentication bypasses represent **41%** of critical vulnerabilities in web applications (HackerOne Report)
- Average cost of a credential-stuffing breach: **$4.3 million** (Ponemon Institute)
- Only **23%** of AI-generated authentication code properly implements session invalidation on logout

---

## BAD Examples: Multiple Manifestations

### BAD Example 1: Weak Password Validation

```pseudocode
// VULNERABLE: Minimal password requirements
function validatePassword(password):
    if length(password) < 6:
        return false
    return true

// VULNERABLE: Only checks length, no complexity
function registerUser(email, password):
    if length(password) >= 8:  // "Strong enough"
        hashedPassword = hashPassword(password)
        createUser(email, hashedPassword)
        return success
    return error("Password too short")

// VULNERABLE: Pattern allows easy-to-guess passwords
function isValidPassword(password):
    // Only requires one of each - easily satisfied by "Password1!"
    hasUpper = containsUppercase(password)
    hasLower = containsLowercase(password)
    hasNumber = containsNumber(password)
    hasSpecial = containsSpecialChar(password)

    if hasUpper and hasLower and hasNumber and hasSpecial:
        return true
    return false
    // Missing: dictionary check, common password check, breach check
```

**Why This Is Dangerous:**
- Allows passwords like "123456", "password", or "qwerty123"
- No protection against common password lists
- No check against known breached passwords (Have I Been Pwned)
- Pattern requirements are easily satisfied by predictable passwords ("Password1!")
- Attackers can crack weak passwords in seconds with modern hardware

---

### BAD Example 2: Predictable Session Tokens

```pseudocode
// VULNERABLE: Sequential session IDs
sessionCounter = 1000

function generateSessionId():
    sessionCounter = sessionCounter + 1
    return "session_" + toString(sessionCounter)

// VULNERABLE: Time-based session generation
function createSessionToken():
    timestamp = getCurrentTimestamp()
    return "sess_" + toString(timestamp)

// VULNERABLE: Weak random source
function generateToken():
    return "token_" + toString(randomInteger(0, 999999))

// VULNERABLE: MD5 of predictable data
function createAuthToken(userId):
    timestamp = getCurrentTimestamp()
    return md5(toString(userId) + toString(timestamp))

// VULNERABLE: User-controlled seed
function generateSessionId(userId, email):
    seed = userId + email + getCurrentDate()
    return sha256(seed)  // Deterministic - same inputs = same output
```

**Why This Is Dangerous:**
- Sequential IDs allow session enumeration—attacker can guess valid sessions
- Timestamp-based tokens can be predicted if attacker knows approximate creation time
- Weak random (Math.random, random.randint) is predictable with statistical analysis
- MD5 is fast to compute, enabling brute-force attacks
- User-controlled inputs in token generation allow attackers to predict tokens

---

### BAD Example 3: Session Fixation Vulnerabilities

```pseudocode
// VULNERABLE: Session ID not regenerated after login
function login(request):
    email = request.body.email
    password = request.body.password

    user = findUserByEmail(email)
    if user and verifyPassword(password, user.hashedPassword):
        // Using the SAME session ID from before authentication
        request.session.userId = user.id
        request.session.authenticated = true
        return redirect("/dashboard")
    return error("Invalid credentials")

// VULNERABLE: Accepting session ID from URL parameter
function handleRequest(request):
    sessionId = request.query.sessionId or request.cookies.sessionId
    // Attacker can send victim: https://app.com/login?sessionId=attacker_controlled_session
    session = loadSession(sessionId)

// VULNERABLE: Not invalidating session on privilege change
function promoteToAdmin(request):
    user = getCurrentUser(request)
    user.role = "admin"
    user.save()
    // Same session continues - if session was compromised before,
    // attacker now has admin access
    return success("You are now an admin")
```

**Why This Is Dangerous:**
- Attacker sets session ID → victim logs in → attacker uses same session ID with victim's authenticated session
- URL-based session IDs can be logged in server logs, browser history, referrer headers
- Privilege escalation without session regeneration means compromised sessions gain elevated access

---

### BAD Example 4: JWT "none" Algorithm Acceptance

```pseudocode
// VULNERABLE: Decoding JWT without algorithm verification
function verifyJwt(token):
    parts = token.split(".")
    header = base64Decode(parts[0])
    payload = base64Decode(parts[1])

    // Trusting the algorithm from the token header itself!
    algorithm = header.alg

    if algorithm == "none":
        return payload  // No signature check!

    signature = parts[2]
    if verifySignature(payload, signature, algorithm):
        return payload
    return null

// VULNERABLE: Using jwt library without specifying expected algorithm
function validateToken(token):
    try:
        // Library may accept 'none' algorithm if token specifies it
        decoded = jwt.decode(token, secretKey)
        return decoded
    catch:
        return null

// VULNERABLE: Allowing multiple algorithms including none
function verifyToken(token, secret):
    options = {
        algorithms: ["HS256", "HS384", "HS512", "none"]  // DANGEROUS
    }
    return jwt.verify(token, secret, options)
```

**Why This Is Dangerous:**
- Attacker modifies JWT header to specify `alg: "none"` and removes signature
- Server accepts unsigned token as valid
- This vulnerability has affected major JWT libraries across multiple languages
- Complete authentication bypass—attacker can impersonate any user

**Exploit Example:**
```pseudocode
// Original legitimate token:
// Header: {"alg":"HS256","typ":"JWT"}
// Payload: {"sub":"1234","role":"user"}
// Signature: valid_signature_here

// Attacker-modified token:
// Header: {"alg":"none","typ":"JWT"}  ← Changed to "none"
// Payload: {"sub":"1234","role":"admin"}  ← Changed to admin
// Signature: (empty)  ← Removed

// If server trusts header.alg, this forged token is accepted as valid
```

---

### BAD Example 5: Weak JWT Secrets

```pseudocode
// VULNERABLE: Short/guessable secret
JWT_SECRET = "secret"

// VULNERABLE: Common secrets from tutorials
JWT_SECRET = "your-256-bit-secret"
JWT_SECRET = "supersecretkey"
JWT_SECRET = "jwt-secret-key"

// VULNERABLE: Empty or null secret
function createToken(payload):
    secret = getConfig("JWT_SECRET") or ""  // Falls back to empty string
    return jwt.sign(payload, secret, {algorithm: "HS256"})

// VULNERABLE: Secret derived from predictable data
function getJwtSecret():
    return sha256(APPLICATION_NAME + "-" + ENVIRONMENT)
    // If attacker knows app name and environment, they can derive the secret

// VULNERABLE: Same secret for signing and encryption
JWT_SECRET = "shared_secret_for_everything"
function signToken(payload):
    return jwt.sign(payload, JWT_SECRET)
function encryptData(data):
    return aesEncrypt(data, JWT_SECRET)  // Key reuse vulnerability
```

**Why This Is Dangerous:**
- Weak secrets can be brute-forced or found in wordlists
- Common tutorial secrets are in public databases of JWT secrets
- Empty secrets may be accepted by some JWT libraries
- Secret compromise allows forging any JWT—complete authentication bypass
- Key reuse across different cryptographic operations violates security principles

---

### BAD Example 6: Token Storage in localStorage

```pseudocode
// VULNERABLE: Storing JWT in localStorage
function handleLoginResponse(response):
    accessToken = response.data.accessToken
    refreshToken = response.data.refreshToken

    // localStorage is accessible to ANY JavaScript on the page
    localStorage.setItem("access_token", accessToken)
    localStorage.setItem("refresh_token", refreshToken)

    // Also stored user data in localStorage
    localStorage.setItem("user", JSON.stringify(response.data.user))

// VULNERABLE: Retrieving token for API calls
function apiRequest(endpoint, data):
    token = localStorage.getItem("access_token")
    return fetch(endpoint, {
        headers: {
            "Authorization": "Bearer " + token
        },
        body: JSON.stringify(data)
    })

// VULNERABLE: Token in sessionStorage (same problem)
function storeToken(token):
    sessionStorage.setItem("jwt", token)
```

**Why This Is Dangerous:**
- localStorage is accessible to any JavaScript running on the page
- XSS vulnerability = complete authentication compromise
- Tokens persist across browser sessions (localStorage)
- No protection against browser extensions reading storage
- Refresh tokens in localStorage allow long-term account takeover

---

### BAD Example 7: Missing Token Expiration

```pseudocode
// VULNERABLE: JWT without expiration
function createUserToken(user):
    payload = {
        userId: user.id,
        email: user.email,
        role: user.role
        // No "exp" claim!
    }
    return jwt.sign(payload, JWT_SECRET)

// VULNERABLE: Extremely long expiration
function generateToken(user):
    payload = {
        sub: user.id,
        iat: now(),
        exp: now() + (365 * 24 * 60 * 60)  // 1 year expiration
    }
    return jwt.sign(payload, JWT_SECRET)

// VULNERABLE: Trusting token-provided expiration without server check
function validateToken(token):
    decoded = jwt.verify(token, JWT_SECRET)
    // JWT library checks exp, but server has no session to revoke
    // Compromised tokens valid until natural expiration
    return decoded

// VULNERABLE: No mechanism to invalidate tokens
function logout(request):
    response.clearCookie("token")
    return success("Logged out")
    // Token is still valid! Anyone with the token can still use it
```

**Why This Is Dangerous:**
- Tokens without expiration are valid forever if secret isn't changed
- Long-lived tokens give attackers extended exploitation windows
- No server-side invalidation means compromised tokens can't be revoked
- Logout only removes token from client but doesn't invalidate it
- Stolen tokens remain valid even after password change

---

## GOOD Examples: Secure Authentication Patterns

### GOOD Example 1: Strong Password Requirements Pattern

```pseudocode
// SECURE: Comprehensive password validation
import commonPasswordList from "common-passwords-database"
import breachedPasswordApi from "haveibeenpwned-api"

function validatePasswordStrength(password):
    errors = []

    // Minimum length (NIST recommends 8+, many orgs use 12+)
    if length(password) < 12:
        errors.push("Password must be at least 12 characters")

    // Maximum length (prevent DoS from hashing extremely long passwords)
    if length(password) > 128:
        errors.push("Password cannot exceed 128 characters")

    // Check against common password list (10,000+ passwords)
    if password.toLowerCase() in commonPasswordList:
        errors.push("This password is too common")

    // Check against user-specific data (optional but recommended)
    // - Don't allow email prefix as password
    // - Don't allow username as password

    // Check against breached passwords (Have I Been Pwned API)
    if await checkBreachedPassword(password):
        errors.push("This password has appeared in a data breach")

    if length(errors) > 0:
        return { valid: false, errors: errors }

    return { valid: true, errors: [] }

// SECURE: Check breached passwords using k-anonymity (no password exposure)
async function checkBreachedPassword(password):
    // Hash password with SHA-1 (HIBP API requirement)
    hash = sha1(password).toUpperCase()
    prefix = hash.substring(0, 5)
    suffix = hash.substring(5)

    // Only send first 5 characters - k-anonymity preserves privacy
    response = await fetch("https://api.pwnedpasswords.com/range/" + prefix)
    hashes = response.text()

    // Check if our suffix appears in the returned hashes
    for line in hashes.split("\n"):
        parts = line.split(":")
        if parts[0] == suffix:
            return true  // Password has been breached

    return false

// SECURE: Password hashing with proper algorithm
function hashPassword(password):
    // bcrypt with cost factor of 12 (adjust based on hardware)
    // Alternatively: argon2id with recommended parameters
    return bcrypt.hash(password, 12)

function verifyPassword(password, hash):
    return bcrypt.compare(password, hash)
```

**Why This Is Secure:**
- Length requirements block trivially short passwords
- Common password checking blocks dictionary attacks
- Breach checking prevents credential stuffing from known breaches
- k-anonymity ensures password isn't exposed during breach check
- bcrypt/argon2 provides proper password hashing with work factor

---

### GOOD Example 2: Secure Session Generation

```pseudocode
// SECURE: Cryptographically random session IDs
import cryptoRandom from "secure-random-library"

function generateSessionId():
    // 256 bits of cryptographically secure randomness
    // Represented as 64 hex characters
    randomBytes = cryptoRandom.getRandomBytes(32)
    return bytesToHex(randomBytes)

// SECURE: Session creation with proper attributes
function createSession(userId):
    sessionId = generateSessionId()

    sessionData = {
        id: sessionId,
        userId: userId,
        createdAt: now(),
        expiresAt: now() + SESSION_DURATION,  // e.g., 24 hours
        lastActivityAt: now(),
        ipAddress: getClientIP(),
        userAgent: getUserAgent()
    }

    // Store in server-side session store (Redis, database, etc.)
    sessionStore.save(sessionId, sessionData)

    return sessionId

// SECURE: Session ID regeneration after authentication
function login(request):
    email = request.body.email
    password = request.body.password

    user = findUserByEmail(email)
    if not user:
        return error("Invalid credentials")  // Don't reveal if email exists

    if not verifyPassword(password, user.hashedPassword):
        recordFailedLogin(user.id, getClientIP())
        return error("Invalid credentials")

    // CRITICAL: Destroy old session and create new one
    if request.session.id:
        sessionStore.delete(request.session.id)

    // Generate completely new session ID after authentication
    newSessionId = createSession(user.id)

    // Set session cookie with secure attributes
    response.setCookie("session_id", newSessionId, {
        httpOnly: true,      // Prevent XSS access
        secure: true,        // HTTPS only
        sameSite: "Strict",  // CSRF protection
        path: "/",
        maxAge: SESSION_DURATION
    })

    return redirect("/dashboard")

// SECURE: Session regeneration on privilege change
function changeUserRole(request, newRole):
    user = getCurrentUser(request)

    // Change the role
    user.role = newRole
    user.save()

    // Regenerate session to bind new privileges to fresh session
    oldSessionId = request.cookies.session_id
    sessionStore.delete(oldSessionId)

    newSessionId = createSession(user.id)

    response.setCookie("session_id", newSessionId, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict"
    })

    return success("Role updated")
```

**Why This Is Secure:**
- Cryptographically random session IDs prevent prediction/enumeration
- Session regeneration after login prevents session fixation
- Privilege changes trigger session regeneration
- Secure cookie attributes prevent common attack vectors
- Server-side session storage allows proper invalidation

---

### GOOD Example 3: Proper JWT Validation

```pseudocode
// SECURE: JWT configuration with strict settings
JWT_CONFIG = {
    secret: getEnv("JWT_SECRET"),  // 256+ bit secret from environment
    algorithms: ["HS256"],          // Single allowed algorithm - explicit!
    issuer: "myapp.example.com",
    audience: "myapp-users",
    expiresIn: "15m"                // Short-lived access tokens
}

// SECURE: Token creation with explicit claims
function createAccessToken(user):
    payload = {
        sub: toString(user.id),
        email: user.email,
        role: user.role,
        iss: JWT_CONFIG.issuer,
        aud: JWT_CONFIG.audience,
        iat: now(),
        exp: now() + (15 * 60),     // 15 minutes
        jti: generateUUID()          // Unique token ID for revocation
    }

    return jwt.sign(payload, JWT_CONFIG.secret, {
        algorithm: "HS256"           // Explicit algorithm
    })

// SECURE: Token verification with all claims checked
function verifyAccessToken(token):
    try:
        decoded = jwt.verify(token, JWT_CONFIG.secret, {
            algorithms: ["HS256"],   // ONLY accept HS256
            issuer: JWT_CONFIG.issuer,
            audience: JWT_CONFIG.audience,
            complete: true           // Return header + payload
        })

        // Additional validation
        if not decoded.payload.sub:
            return { valid: false, error: "Missing subject" }

        if not decoded.payload.role:
            return { valid: false, error: "Missing role" }

        // Check against token blacklist (for logout/revocation)
        if await isTokenRevoked(decoded.payload.jti):
            return { valid: false, error: "Token revoked" }

        return { valid: true, payload: decoded.payload }

    catch JwtExpiredError:
        return { valid: false, error: "Token expired" }
    catch JwtInvalidError as e:
        return { valid: false, error: "Invalid token: " + e.message }

// SECURE: Refresh token handling
function createRefreshToken(user, sessionId):
    payload = {
        sub: toString(user.id),
        sid: sessionId,              // Bind to session for revocation
        type: "refresh",
        iat: now(),
        exp: now() + (7 * 24 * 60 * 60)  // 7 days
    }

    token = jwt.sign(payload, JWT_CONFIG.secret + "_refresh", {
        algorithm: "HS256"
    })

    // Store refresh token hash in database for revocation
    tokenHash = sha256(token)
    storeRefreshToken(user.id, sessionId, tokenHash, payload.exp)

    return token

// SECURE: Refresh flow with rotation
function refreshAccessToken(refreshToken):
    try:
        decoded = jwt.verify(refreshToken, JWT_CONFIG.secret + "_refresh", {
            algorithms: ["HS256"]
        })

        // Verify refresh token is still valid in database
        tokenHash = sha256(refreshToken)
        storedToken = getRefreshToken(decoded.sub, tokenHash)

        if not storedToken or storedToken.revoked:
            return { error: "Refresh token invalid or revoked" }

        // Rotate refresh token (issue new one, revoke old)
        revokeRefreshToken(tokenHash)

        user = findUserById(decoded.sub)
        newAccessToken = createAccessToken(user)
        newRefreshToken = createRefreshToken(user, decoded.sid)

        return {
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        }

    catch:
        return { error: "Invalid refresh token" }
```

**Why This Is Secure:**
- Explicit algorithm specification prevents algorithm confusion attacks
- Short-lived access tokens minimize exposure window
- JTI (JWT ID) enables token revocation
- Refresh token rotation limits reuse attacks
- Complete claim validation (iss, aud, exp, sub)
- Separate secrets for access and refresh tokens

---

### GOOD Example 4: HttpOnly Secure Cookie Usage

```pseudocode
// SECURE: Cookie-based session with proper attributes
function setSessionCookie(response, sessionId):
    response.setCookie("session_id", sessionId, {
        httpOnly: true,      // Cannot be accessed via JavaScript
        secure: true,        // Only sent over HTTPS
        sameSite: "Strict",  // Not sent with cross-site requests
        path: "/",           // Available for all paths
        domain: ".myapp.com", // Scoped to main domain and subdomains
        maxAge: 24 * 60 * 60  // 24 hours in seconds
    })

// SECURE: JWT in cookie (not localStorage)
function setAuthCookies(response, accessToken, refreshToken):
    // Access token - short lived, same-site strict
    response.setCookie("access_token", accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        path: "/",
        maxAge: 15 * 60       // 15 minutes
    })

    // Refresh token - limited path to reduce exposure
    response.setCookie("refresh_token", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        path: "/auth/refresh",  // Only sent to refresh endpoint
        maxAge: 7 * 24 * 60 * 60  // 7 days
    })

// SECURE: Cookie cleanup on logout
function clearAuthCookies(response):
    // Set cookies with immediate expiration
    response.setCookie("access_token", "", {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        path: "/",
        maxAge: 0             // Immediate expiration
    })

    response.setCookie("refresh_token", "", {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        path: "/auth/refresh",
        maxAge: 0
    })

// SECURE: SameSite considerations for cross-origin needs
function setCookieForOAuth(response, stateToken):
    // OAuth requires cookies to work across redirects
    // Use Lax instead of Strict when necessary
    response.setCookie("oauth_state", stateToken, {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",      // Allows top-level navigation
        path: "/auth/callback",
        maxAge: 10 * 60       // 10 minutes for OAuth flow
    })
```

**Why This Is Secure:**
- HttpOnly prevents XSS from stealing tokens
- Secure flag ensures HTTPS-only transmission
- SameSite prevents CSRF attacks
- Path restriction limits which requests include the cookie
- Short maxAge limits exposure window
- Proper domain scoping prevents subdomain attacks

---

### GOOD Example 5: Token Refresh Patterns

```pseudocode
// SECURE: Complete token refresh implementation
class AuthenticationService:

    ACCESS_TOKEN_DURATION = 15 * 60          // 15 minutes
    REFRESH_TOKEN_DURATION = 7 * 24 * 60 * 60  // 7 days
    REFRESH_TOKEN_REUSE_WINDOW = 60           // 1 minute grace period

    function login(email, password):
        user = validateCredentials(email, password)
        if not user:
            return { error: "Invalid credentials" }

        // Create session for tracking
        session = createSession(user.id)

        // Generate token pair
        accessToken = createAccessToken(user)
        refreshToken = createRefreshToken(user, session.id)

        return {
            accessToken: accessToken,
            refreshToken: refreshToken,
            expiresIn: ACCESS_TOKEN_DURATION
        }

    function refresh(refreshToken):
        // Validate refresh token
        decoded = verifyRefreshToken(refreshToken)
        if not decoded.valid:
            return { error: decoded.error }

        // Check token in database
        tokenRecord = getRefreshTokenRecord(decoded.jti)

        if not tokenRecord:
            // Token doesn't exist - possible theft, invalidate session
            invalidateSessionTokens(decoded.sid)
            return { error: "Invalid refresh token" }

        if tokenRecord.revoked:
            // Reuse of revoked token - likely theft
            // Revoke ALL tokens for this session
            invalidateSessionTokens(decoded.sid)
            logSecurityEvent("Refresh token reuse detected", decoded.sub)
            return { error: "Security violation detected" }

        if tokenRecord.usedAt:
            // Token was already used - check if within grace period
            if now() - tokenRecord.usedAt > REFRESH_TOKEN_REUSE_WINDOW:
                // Outside grace period - potential theft
                invalidateSessionTokens(decoded.sid)
                return { error: "Refresh token already used" }
            // Within grace period - return same tokens (replay protection)
            return tokenRecord.lastIssuedTokens

        // Mark token as used
        tokenRecord.usedAt = now()
        tokenRecord.save()

        // Generate new token pair (rotation)
        user = findUserById(decoded.sub)
        newAccessToken = createAccessToken(user)
        newRefreshToken = createRefreshToken(user, decoded.sid)

        // Store new tokens for replay protection
        tokenRecord.lastIssuedTokens = {
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        }
        tokenRecord.save()

        // Revoke old refresh token (after grace period, it's invalid)
        scheduleTokenRevocation(decoded.jti, REFRESH_TOKEN_REUSE_WINDOW)

        return {
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
            expiresIn: ACCESS_TOKEN_DURATION
        }

    function logout(accessToken, refreshToken):
        // Revoke access token (add to blacklist until expiry)
        decoded = decodeToken(accessToken)
        if decoded:
            blacklistToken(decoded.jti, decoded.exp)

        // Revoke refresh token immediately
        refreshDecoded = decodeToken(refreshToken)
        if refreshDecoded:
            revokeRefreshToken(refreshDecoded.jti)

        // Optionally invalidate entire session
        if refreshDecoded and refreshDecoded.sid:
            invalidateSession(refreshDecoded.sid)

        return { success: true }

    function logoutAll(userId):
        // Invalidate all sessions for user (password change, security concern)
        sessions = getSessionsForUser(userId)
        for session in sessions:
            invalidateSessionTokens(session.id)
            deleteSession(session.id)

        return { success: true, sessionsInvalidated: length(sessions) }
```

**Why This Is Secure:**
- Refresh token rotation limits reuse attacks
- Token reuse detection identifies potential theft
- Grace period prevents legitimate concurrent request issues
- Complete logout invalidates tokens server-side
- Session binding allows "logout from all devices"

---

### GOOD Example 6: Proper Logout (Token Invalidation)

```pseudocode
// SECURE: Complete logout implementation
function logout(request):
    // Get current session/tokens
    accessToken = request.cookies.access_token
    refreshToken = request.cookies.refresh_token
    sessionId = request.session.id

    // Revoke access token (add to blacklist)
    if accessToken:
        decoded = decodeToken(accessToken)
        if decoded:
            // Add to Redis/cache blacklist with TTL matching token expiry
            blacklistToken(decoded.jti, decoded.exp - now())

    // Revoke refresh token in database
    if refreshToken:
        refreshDecoded = decodeToken(refreshToken)
        if refreshDecoded:
            markRefreshTokenRevoked(refreshDecoded.jti)

    // Delete server-side session
    if sessionId:
        sessionStore.delete(sessionId)

    // Clear client cookies
    response = new Response()
    clearAuthCookies(response)

    return response.redirect("/login")

// SECURE: Token blacklist with automatic expiry
class TokenBlacklist:
    // Use Redis or similar with TTL support

    function add(tokenId, ttlSeconds):
        redis.setex("blacklist:" + tokenId, ttlSeconds, "revoked")

    function isBlacklisted(tokenId):
        return redis.exists("blacklist:" + tokenId)

// SECURE: Middleware to check token validity
function authMiddleware(request, next):
    accessToken = request.cookies.access_token

    if not accessToken:
        return redirect("/login")

    decoded = verifyAccessToken(accessToken)

    if not decoded.valid:
        return redirect("/login")

    // Check blacklist
    if tokenBlacklist.isBlacklisted(decoded.payload.jti):
        return redirect("/login")

    // Token is valid and not revoked
    request.user = decoded.payload
    return next(request)

// SECURE: Logout from all sessions
function logoutAllSessions(request):
    userId = request.user.sub

    // Get all active sessions for user
    sessions = sessionStore.findByUserId(userId)

    // Revoke all refresh tokens
    refreshTokens = getRefreshTokensForUser(userId)
    for token in refreshTokens:
        markRefreshTokenRevoked(token.jti)

    // Delete all sessions
    for session in sessions:
        sessionStore.delete(session.id)

    // Add all user's recent access tokens to blacklist
    // This requires tracking issued tokens or using short expiry
    invalidateAllAccessTokensForUser(userId)

    return success("Logged out from all devices")
```

**Why This Is Secure:**
- Server-side revocation makes logout effective immediately
- Blacklist prevents continued use of revoked tokens
- Automatic TTL cleanup prevents blacklist bloat
- "Logout from all devices" handles session compromise
- Cookie clearing removes client-side references

---

## Edge Cases Section

### Edge Case 1: Race Conditions in Authentication

```pseudocode
// VULNERABLE: Race condition in login attempts
function login(email, password):
    user = findUserByEmail(email)
    failedAttempts = getFailedAttempts(email)

    if failedAttempts >= MAX_ATTEMPTS:
        return error("Account locked")

    // Race condition: two requests check simultaneously,
    // both see failedAttempts = 4, both proceed
    if not verifyPassword(password, user.hashedPassword):
        incrementFailedAttempts(email)  // Not atomic!
        return error("Invalid credentials")

    resetFailedAttempts(email)
    return success()

// SECURE: Atomic rate limiting
function loginWithAtomicRateLimit(email, password):
    // Atomic increment and check in single operation
    result = redis.eval(`
        local attempts = redis.call('INCR', KEYS[1])
        if attempts == 1 then
            redis.call('EXPIRE', KEYS[1], 900)  -- 15 minute window
        end
        return attempts
    `, ["login_attempts:" + email])

    if result > MAX_ATTEMPTS:
        return error("Too many attempts. Try again later.")

    user = findUserByEmail(email)
    if not user or not verifyPassword(password, user.hashedPassword):
        return error("Invalid credentials")

    // Reset on success
    redis.del("login_attempts:" + email)
    return success()

// VULNERABLE: Race condition in concurrent session check
function login(email, password, request):
    user = authenticate(email, password)

    activeSessions = countActiveSessions(user.id)
    if activeSessions >= MAX_SESSIONS:
        return error("Too many active sessions")

    // Race: two logins pass the check simultaneously
    createSession(user.id)  // Now user has MAX_SESSIONS + 1
    return success()

// SECURE: Use database constraints or atomic operations
function loginWithSessionLimit(email, password, request):
    user = authenticate(email, password)

    // Use transaction with row lock
    transaction.start()
    try:
        activeSessions = countActiveSessionsForUpdate(user.id)  // SELECT FOR UPDATE
        if activeSessions >= MAX_SESSIONS:
            transaction.rollback()
            return error("Too many sessions")

        createSession(user.id)
        transaction.commit()
        return success()
    catch:
        transaction.rollback()
        throw
```

---

### Edge Case 2: Timing Attacks on Password Comparison

```pseudocode
// VULNERABLE: Early return reveals password length information
function verifyPassword_vulnerable(input, stored):
    if length(input) != length(stored):
        return false  // Fast return reveals length mismatch

    for i in range(length(input)):
        if input[i] != stored[i]:
            return false  // Fast return reveals first different character

    return true

// VULNERABLE: String comparison has timing differences
function checkPassword_vulnerable(password, hash):
    computedHash = sha256(password)
    return computedHash == hash  // == operator may short-circuit

// SECURE: Constant-time comparison
function constantTimeEquals(a, b):
    if length(a) != length(b):
        // Still need length check, but make it constant-time
        b = b + repeat("\0", max(0, length(a) - length(b)))
        a = a + repeat("\0", max(0, length(b) - length(a)))

    result = 0
    for i in range(length(a)):
        result = result | (charCode(a[i]) ^ charCode(b[i]))

    return result == 0

// SECURE: Use library-provided constant-time comparison
function verifyPassword_secure(password, hashedPassword):
    // bcrypt.compare is designed to be constant-time
    return bcrypt.compare(password, hashedPassword)

// SECURE: Use crypto library's timingSafeEqual
function verifyHash(input, expected):
    inputHash = sha256(input)
    return crypto.timingSafeEqual(
        Buffer.from(inputHash, 'hex'),
        Buffer.from(expected, 'hex')
    )
```

---

### Edge Case 3: Password Reset Token Issues

```pseudocode
// VULNERABLE: Predictable reset token
function createResetToken_vulnerable(userId):
    token = md5(toString(userId) + toString(now()))
    expiry = now() + (60 * 60)  // 1 hour
    saveResetToken(userId, token, expiry)
    return token

// VULNERABLE: Token doesn't expire on use
function resetPassword_vulnerable(token, newPassword):
    resetRecord = getResetToken(token)
    if resetRecord and resetRecord.expiry > now():
        user = findUserById(resetRecord.userId)
        user.hashedPassword = hashPassword(newPassword)
        user.save()
        // Token not invalidated! Can be reused
        return success()
    return error("Invalid token")

// VULNERABLE: Token not invalidated on password change
function changePassword(userId, oldPassword, newPassword):
    user = findUserById(userId)
    if verifyPassword(oldPassword, user.hashedPassword):
        user.hashedPassword = hashPassword(newPassword)
        user.save()
        // Existing reset tokens still valid!
        return success()
    return error("Wrong password")

// SECURE: Complete password reset implementation
function createResetToken_secure(userId):
    // Generate cryptographically random token
    token = generateSecureRandom(32)  // 256 bits
    tokenHash = sha256(token)  // Store hash, not token
    expiry = now() + (15 * 60)  // 15 minutes

    // Invalidate any existing reset tokens
    deleteResetTokensForUser(userId)

    // Store hashed token
    saveResetToken(userId, tokenHash, expiry)

    // Return plaintext token for email (store hash only)
    return token

function resetPassword_secure(token, newPassword):
    tokenHash = sha256(token)
    resetRecord = getResetTokenByHash(tokenHash)

    if not resetRecord:
        return error("Invalid token")

    if resetRecord.expiry < now():
        deleteResetToken(tokenHash)
        return error("Token expired")

    if resetRecord.used:
        return error("Token already used")

    // Validate new password strength
    validation = validatePasswordStrength(newPassword)
    if not validation.valid:
        return error(validation.errors)

    user = findUserById(resetRecord.userId)

    // Update password
    user.hashedPassword = hashPassword(newPassword)
    user.passwordChangedAt = now()
    user.save()

    // Mark token as used (or delete)
    resetRecord.used = true
    resetRecord.save()

    // Invalidate all existing sessions
    invalidateAllSessionsForUser(user.id)

    // Invalidate all refresh tokens
    revokeAllRefreshTokensForUser(user.id)

    // Send notification email
    sendPasswordChangedNotification(user.email)

    return success()
```

---

### Edge Case 4: OAuth State Parameter Issues

```pseudocode
// VULNERABLE: No state parameter - CSRF possible
function initiateOAuth_vulnerable():
    redirectUrl = OAUTH_PROVIDER_URL +
        "?client_id=" + CLIENT_ID +
        "&redirect_uri=" + CALLBACK_URL +
        "&scope=email profile"
    return redirect(redirectUrl)

// VULNERABLE: Predictable state
function initiateOAuth_weakState():
    state = toString(now())  // Predictable!
    storeState(state)
    redirectUrl = OAUTH_PROVIDER_URL +
        "?client_id=" + CLIENT_ID +
        "&state=" + state +
        "&redirect_uri=" + CALLBACK_URL
    return redirect(redirectUrl)

// VULNERABLE: State not validated on callback
function handleCallback_vulnerable(request):
    code = request.query.code
    // state parameter ignored!
    tokens = exchangeCodeForTokens(code)
    return loginWithTokens(tokens)

// VULNERABLE: State reuse possible
function handleCallback_reuseVulnerable(request):
    code = request.query.code
    state = request.query.state

    if isValidState(state):  // Just checks if it exists
        // Doesn't delete/invalidate state after use
        tokens = exchangeCodeForTokens(code)
        return loginWithTokens(tokens)

    return error("Invalid state")

// SECURE: Complete OAuth implementation
function initiateOAuth_secure(request):
    // Generate random state
    state = generateSecureRandom(32)

    // Bind state to user's session (CSRF protection)
    request.session.oauthState = state
    request.session.oauthStateCreatedAt = now()

    // Optional: include nonce for ID token validation
    nonce = generateSecureRandom(32)
    request.session.oauthNonce = nonce

    redirectUrl = OAUTH_PROVIDER_URL +
        "?client_id=" + CLIENT_ID +
        "&response_type=code" +
        "&redirect_uri=" + encodeURIComponent(CALLBACK_URL) +
        "&scope=" + encodeURIComponent("openid email profile") +
        "&state=" + state +
        "&nonce=" + nonce

    return redirect(redirectUrl)

function handleCallback_secure(request):
    code = request.query.code
    state = request.query.state
    error = request.query.error

    // Check for OAuth error
    if error:
        logOAuthError(error, request.query.error_description)
        return redirect("/login?error=oauth_failed")

    // Validate state
    if not state:
        return error("Missing state parameter")

    storedState = request.session.oauthState
    stateCreatedAt = request.session.oauthStateCreatedAt

    // Constant-time comparison
    if not constantTimeEquals(state, storedState):
        logSecurityEvent("OAuth state mismatch", request)
        return error("Invalid state")

    // Check state expiry (5 minutes)
    if now() - stateCreatedAt > 300:
        return error("OAuth session expired")

    // Clear state immediately (one-time use)
    delete request.session.oauthState
    delete request.session.oauthStateCreatedAt

    // Exchange code for tokens
    tokenResponse = await exchangeCodeForTokens(code, CALLBACK_URL)

    if not tokenResponse.id_token:
        return error("Missing ID token")

    // Validate ID token
    idToken = verifyIdToken(tokenResponse.id_token, {
        audience: CLIENT_ID,
        nonce: request.session.oauthNonce  // Verify nonce
    })

    delete request.session.oauthNonce

    if not idToken.valid:
        return error("Invalid ID token")

    // Create or update user
    user = findOrCreateUserFromOAuth(idToken.payload)

    // Create session with new session ID
    createAuthenticatedSession(request, user)

    return redirect("/dashboard")
```

---

## Common Mistakes Section

### Common Mistake 1: Checking User ID from Token Payload Without Verification

```pseudocode
// VULNERABLE: Trusting unverified token payload
function getUserFromToken_vulnerable(token):
    // Decodes token WITHOUT verification
    decoded = base64Decode(token.split(".")[1])
    payload = JSON.parse(decoded)

    // Trusting the user ID from unverified payload!
    return findUserById(payload.sub)

// VULNERABLE: Verifying signature but using wrong data source
function getUser_vulnerable(request):
    token = request.headers.authorization.replace("Bearer ", "")

    // Verify the token (good)
    isValid = jwt.verify(token, secret)

    if isValid:
        // But then extract user from request body (bad!)
        userId = request.body.userId
        return findUserById(userId)

// SECURE: Always use verified payload
function getUserFromToken_secure(token):
    try:
        // Verify and decode in one operation
        decoded = jwt.verify(token, secret, { algorithms: ["HS256"] })

        // Use the verified payload, not a separate data source
        return findUserById(decoded.sub)
    catch:
        return null

// SECURE: Middleware that sets verified user
function authMiddleware(request, next):
    token = extractTokenFromRequest(request)

    if not token:
        return unauthorized()

    try:
        verified = jwt.verify(token, secret, {
            algorithms: ["HS256"],
            issuer: "myapp"
        })

        // Set user from VERIFIED token only
        request.user = {
            id: verified.sub,
            email: verified.email,
            role: verified.role
        }

        return next()
    catch:
        return unauthorized()
```

---

### Common Mistake 2: Not Invalidating Old Sessions

```pseudocode
// VULNERABLE: Password change doesn't invalidate sessions
function changePassword_vulnerable(request, oldPassword, newPassword):
    user = request.user

    if verifyPassword(oldPassword, user.hashedPassword):
        user.hashedPassword = hashPassword(newPassword)
        user.save()
        return success("Password changed")

    return error("Wrong password")
    // Existing sessions remain valid! Attacker still logged in

// VULNERABLE: Role change doesn't update session
function demoteUser_vulnerable(userId):
    user = findUserById(userId)
    user.role = "basic"
    user.save()
    // User's existing sessions still have old role!
    return success()

// SECURE: Invalidate sessions on security-sensitive changes
function changePassword_secure(request, oldPassword, newPassword):
    user = request.user

    if not verifyPassword(oldPassword, user.hashedPassword):
        return error("Wrong password")

    // Update password
    user.hashedPassword = hashPassword(newPassword)
    user.passwordChangedAt = now()
    user.save()

    // Invalidate ALL sessions except current (or including current)
    currentSessionId = request.session.id
    sessions = getAllSessionsForUser(user.id)

    for session in sessions:
        if session.id != currentSessionId:  // Keep current or invalidate all
            deleteSession(session.id)

    // Revoke all refresh tokens
    revokeAllRefreshTokensForUser(user.id)

    // Optional: Force re-authentication
    regenerateSession(request)

    return success("Password changed. Other sessions logged out.")

// SECURE: Track password change timestamp in tokens
function validateToken_withPasswordCheck(token):
    decoded = jwt.verify(token, secret)

    user = findUserById(decoded.sub)

    // Check if token was issued before password change
    if decoded.iat < user.passwordChangedAt:
        return { valid: false, error: "Password changed since token issued" }

    return { valid: true, payload: decoded }
```

---

### Common Mistake 3: SameSite Cookie Misunderstanding

```pseudocode
// VULNERABLE: Using Lax when Strict is needed
function setSessionCookie_wrongSameSite(response, sessionId):
    response.setCookie("session_id", sessionId, {
        httpOnly: true,
        secure: true,
        sameSite: "Lax"  // Allows cookie on top-level navigation
        // Attacker can CSRF via: <a href="https://bank.com/transfer?to=attacker">
    })

// VULNERABLE: Omitting SameSite (defaults vary by browser)
function setSessionCookie_noSameSite(response, sessionId):
    response.setCookie("session_id", sessionId, {
        httpOnly: true,
        secure: true
        // SameSite not specified - browser-dependent behavior
    })

// VULNERABLE: Using None without understanding implications
function setSessionCookie_sameNone(response, sessionId):
    response.setCookie("session_id", sessionId, {
        httpOnly: true,
        secure: true,
        sameSite: "None"  // Sent on ALL cross-site requests - CSRF vulnerable!
    })

// GUIDE: When to use each SameSite value

// STRICT: Most secure, use for sensitive auth cookies
// - Cookie NOT sent on any cross-site request
// - User clicking link from email to your site won't be logged in
// - Best for: Banking, admin panels, security-critical apps
function setStrictCookie(response, sessionId):
    response.setCookie("session_id", sessionId, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict"
    })

// LAX: Balance of security and usability
// - Cookie sent on top-level navigation (clicking links)
// - NOT sent on cross-site POST, images, iframes
// - Good for: General user sessions where link-sharing matters
// - STILL NEED CSRF tokens for POST/PUT/DELETE endpoints!
function setLaxCookie(response, sessionId):
    response.setCookie("session_id", sessionId, {
        httpOnly: true,
        secure: true,
        sameSite: "Lax"
    })
    // Additional CSRF protection still recommended

// NONE: Only for cross-site embedding needs
// - Cookie sent on ALL requests including cross-site
// - REQUIRES Secure attribute (HTTPS only)
// - Only use for: OAuth flows, embedded widgets, intentional cross-site
function setNoneCookie_onlyWhenNeeded(response, oauthToken):
    response.setCookie("oauth_continuation", oauthToken, {
        httpOnly: true,
        secure: true,          // REQUIRED with SameSite=None
        sameSite: "None",
        maxAge: 300            // Short-lived for specific purpose
    })
```

---

## Security Header Configurations

```pseudocode
// SECURE: Complete security headers for authentication
function setSecurityHeaders(response):
    // Prevent clickjacking (don't allow embedding in frames)
    response.setHeader("X-Frame-Options", "DENY")

    // Modern clickjacking protection
    response.setHeader("Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "frame-ancestors 'none'; " +
        "form-action 'self'"
    )

    // Prevent MIME type sniffing
    response.setHeader("X-Content-Type-Options", "nosniff")

    // Enable browser XSS filter (legacy, CSP is better)
    response.setHeader("X-XSS-Protection", "1; mode=block")

    // Only allow HTTPS
    response.setHeader("Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload"
    )

    // Control referrer information
    response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin")

    // Disable feature policies for sensitive features
    response.setHeader("Permissions-Policy",
        "geolocation=(), camera=(), microphone=(), payment=()"
    )

    // Cache control for authenticated pages
    response.setHeader("Cache-Control",
        "no-store, no-cache, must-revalidate, private"
    )
    response.setHeader("Pragma", "no-cache")
    response.setHeader("Expires", "0")

// SECURE: Login page specific headers
function setLoginPageHeaders(response):
    setSecurityHeaders(response)

    // Additional login protection
    response.setHeader("Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self'; " +
        "form-action 'self'; " +        // Forms only submit to same origin
        "frame-ancestors 'none'; " +     // Prevent clickjacking
        "base-uri 'self'"               // Prevent base tag injection
    )

// SECURE: API endpoint headers
function setApiHeaders(response):
    // API responses shouldn't be cached
    response.setHeader("Cache-Control", "no-store")

    // Prevent embedding
    response.setHeader("X-Content-Type-Options", "nosniff")

    // CORS configuration (adjust based on needs)
    response.setHeader("Access-Control-Allow-Origin",
        getAllowedOrigin())  // Not "*" for authenticated APIs!
    response.setHeader("Access-Control-Allow-Credentials", "true")
    response.setHeader("Access-Control-Allow-Methods",
        "GET, POST, PUT, DELETE, OPTIONS")
    response.setHeader("Access-Control-Allow-Headers",
        "Content-Type, Authorization")
```

---

## Detection Hints: How to Spot Authentication Issues

### Code Review Patterns

```pseudocode
// RED FLAGS in authentication code:

// 1. Missing algorithm specification in JWT verification
jwt.verify(token, secret)  // BAD - should specify algorithms
jwt.decode(token)          // BAD - decode doesn't verify!

// 2. Session not regenerated after login
request.session.userId = user.id  // Search for: session assignment without regenerate

// 3. Tokens in localStorage
localStorage.setItem("token"  // Search for: localStorage.*token

// 4. No HttpOnly on session cookies
setCookie("session", id)  // Search for: setCookie without httpOnly

// 5. Weak secrets
JWT_SECRET = "secret"     // Search for: SECRET.*=.*["']

// 6. No expiration
jwt.sign(payload, secret)  // Without expiresIn

// 7. Password comparison without constant-time
if password == storedHash  // Direct comparison

// 8. No rate limiting on login
function login(email, password)  // Check for rate limit before auth logic

// GREP patterns for security review:
// localStorage\.setItem.*token
// sessionStorage\.setItem.*token
// jwt\.decode\s*\(
// jwt\.verify\s*\([^,]+,[^,]+\s*\)  (missing options)
// sameSite.*None
// password.*==
// \.secret\s*=\s*["']
```

### Security Testing Checklist

```pseudocode
// Authentication security test cases:

// 1. Token manipulation tests
- [ ] Change JWT algorithm to "none" and remove signature
- [ ] Modify JWT payload (role, user ID) and check if accepted
- [ ] Use expired token
- [ ] Use token with wrong issuer/audience

// 2. Session tests
- [ ] Check if session ID changes after login
- [ ] Attempt session fixation (set session ID before login)
- [ ] Check session timeout enforcement
- [ ] Verify logout actually invalidates session

// 3. Password tests
- [ ] Test common passwords (password123, qwerty, etc.)
- [ ] Test password length limits (very long passwords)
- [ ] Check password reset token predictability
- [ ] Verify password reset invalidates old tokens

// 4. Cookie tests
- [ ] Check HttpOnly flag on session cookies
- [ ] Check Secure flag on session cookies
- [ ] Test SameSite enforcement
- [ ] Verify cookie scope (path, domain)

// 5. Rate limiting tests
- [ ] Attempt rapid login failures
- [ ] Check for account lockout
- [ ] Test rate limit bypass (different IPs, headers)

// 6. OAuth tests
- [ ] Test with missing state parameter
- [ ] Test with reused state parameter
- [ ] Check redirect_uri validation
```

---

## Security Checklist

- [ ] Passwords validated against common password list and breach databases
- [ ] Password hashing uses bcrypt, argon2, or scrypt with appropriate work factor
- [ ] Session IDs generated with cryptographically secure random
- [ ] Session regenerated after authentication and privilege changes
- [ ] JWT algorithm explicitly specified (not derived from token)
- [ ] JWT "none" algorithm explicitly rejected
- [ ] JWT secrets are strong (256+ bits) and stored securely
- [ ] JWT expiration is short for access tokens (15-30 minutes)
- [ ] Refresh token rotation implemented
- [ ] Tokens can be revoked server-side (blacklist or session binding)
- [ ] Authentication cookies have HttpOnly, Secure, and appropriate SameSite
- [ ] Tokens stored in HttpOnly cookies, not localStorage/sessionStorage
- [ ] Rate limiting implemented on login endpoints
- [ ] Account lockout after repeated failures
- [ ] Constant-time comparison used for password/token verification
- [ ] Password reset tokens are cryptographically random and single-use
- [ ] Password change invalidates existing sessions
- [ ] OAuth state parameter is random and validated
- [ ] Security headers configured (HSTS, CSP, X-Frame-Options, etc.)
- [ ] Logout invalidates session/tokens server-side
- [ ] "Logout from all devices" functionality available

---
