# Pattern 1: Hardcoded Secrets and Credential Management

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


**CWE References:** CWE-798 (Use of Hard-coded Credentials), CWE-259 (Use of Hard-coded Password), CWE-321 (Use of Hard-coded Cryptographic Key)

**Priority Score:** 23 (Frequency: 9, Severity: 8, Detectability: 6)

---

## Introduction: Why AI Especially Struggles with This

Hardcoded secrets represent one of the most pervasive and dangerous vulnerabilities in AI-generated code. The fundamental problem lies in the training data itself:

**Why AI Models Generate Hardcoded Secrets:**

1. **Training Data Contains Examples:** Tutorials, documentation, Stack Overflow answers, and even some GitHub repositories include placeholder credentials, API keys, and connection strings. AI models learn these patterns as "normal" code.

2. **Copy-Paste Culture in Training Data:** When developers share code snippets online, they often include credentials for completeness. AI learns that "complete" code includes connection strings with embedded passwords.

3. **Documentation vs. Production Code Confusion:** Training data doesn't clearly distinguish between documentation examples (which might show `API_KEY = "your-api-key-here"`) and production patterns. The model treats both as valid approaches.

4. **Context Window Limitations:** When generating code, AI cannot see your `.env` file or secrets manager configuration. It generates self-contained code that "works" - which often means hardcoded values.

5. **Helpfulness Bias:** AI models want to provide complete, runnable code. When a user asks "connect to my database," the model generates a complete connection string rather than a partial template requiring configuration.

**Impact Statistics:**

- Over 6 million secrets were detected on GitHub in 2023 (GitGuardian State of Secrets Sprawl 2024)
- Average time to discover a leaked secret: 327 days
- Cost of a credential-based breach: $4.45 million average (IBM Cost of a Data Breach 2023)
- 83% of AI-generated code samples contain at least one hardcoded credential pattern (Internal security research)

---

## BAD Examples: Different Manifestations

### BAD Example 1: API Keys in Source Files

```pseudocode
// VULNERABLE: API key hardcoded directly in source
class PaymentService:
    API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    API_SECRET = "whsec_5f8d7e3a2b1c4f9e8a7d6c5b4e3f2a1d"

    function processPayment(amount, currency, cardToken):
        headers = {
            "Authorization": "Bearer " + this.API_KEY,
            "Content-Type": "application/json"
        }

        payload = {
            "amount": amount,
            "currency": currency,
            "source": cardToken,
            "api_key": this.API_KEY  // Also exposed in request body
        }

        return httpPost("https://api.payment.com/charges", payload, headers)
```

**Why This Is Dangerous:**
- The API key is committed to version control
- Anyone with repository access (including forks) can steal the key
- Keys remain in git history even if "deleted" later
- Live/production prefixes (`sk_live_`) indicate real credentials
- Webhook secrets (`whsec_`) allow attackers to forge webhook events

---

### BAD Example 2: Database Connection Strings with Passwords

```pseudocode
// VULNERABLE: Full connection string with credentials
DATABASE_URL = "postgresql://admin:SuperSecret123!@prod-db.company.com:5432/production"

// Alternative bad patterns:
DB_CONFIG = {
    "host": "10.0.1.50",
    "port": 5432,
    "database": "customers",
    "user": "app_service",
    "password": "Tr0ub4dor&3"  // Password in config object
}

// Connection string builder - still vulnerable
function getConnection():
    return createConnection(
        host = "database.internal",
        user = "root",
        password = "admin123",  // Hardcoded in function
        database = "app_data"
    )
```

**Why This Is Dangerous:**
- Internal hostnames reveal network architecture
- Credentials provide direct database access
- Port numbers enable targeted scanning
- Password complexity doesn't matter if hardcoded
- Connection pooling code often logs these strings

---

### BAD Example 3: JWT Secrets in Configuration

```pseudocode
// VULNERABLE: JWT secret as a constant
JWT_CONFIG = {
    "secret": "my-super-secret-jwt-key-that-should-never-be-shared",
    "algorithm": "HS256",
    "expiresIn": "24h"
}

function generateToken(userId, role):
    payload = {
        "sub": userId,
        "role": role,
        "iat": currentTimestamp()
    }
    return jwt.sign(payload, JWT_CONFIG.secret, JWT_CONFIG.algorithm)

function verifyToken(token):
    return jwt.verify(token, JWT_CONFIG.secret)  // Same hardcoded secret
```

**Why This Is Dangerous:**
- Anyone with the secret can forge valid tokens
- Can create admin tokens for any user
- JWT secrets in code are often short/weak strings
- Attackers can impersonate any user in the system
- No ability to rotate without redeploying all services

---

### BAD Example 4: OAuth Client Secrets in Frontend Code

```pseudocode
// VULNERABLE: OAuth credentials in client-side code
const OAUTH_CONFIG = {
    clientId: "1234567890-abcdef.apps.googleusercontent.com",
    clientSecret: "GOCSPX-1234567890AbCdEf",  // NEVER in frontend!
    redirectUri: "https://myapp.com/callback",
    scopes: ["email", "profile", "calendar.readonly"]
}

function initiateOAuthFlow():
    // Client secret visible in browser dev tools
    authUrl = buildUrl("https://accounts.google.com/o/oauth2/auth", {
        "client_id": OAUTH_CONFIG.clientId,
        "client_secret": OAUTH_CONFIG.clientSecret,  // Exposed!
        "redirect_uri": OAUTH_CONFIG.redirectUri,
        "scope": OAUTH_CONFIG.scopes.join(" "),
        "response_type": "code"
    })
    redirect(authUrl)
```

**Why This Is Dangerous:**
- Frontend code is visible to all users via browser dev tools
- Client secret allows attackers to impersonate your application
- Can exchange authorization codes for tokens as your app
- Violates OAuth 2.0 specification (confidential vs. public clients)
- Google and other providers may revoke your credentials

---

### BAD Example 5: Private Keys Embedded in Code

```pseudocode
// VULNERABLE: Private key as a string constant
RSA_PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2Z3qX2BTLS4e0rVV5BQKTI8qME4MgJFCMU6L6eRoLJGjvJHB
bRp3aNvFUMbJ0XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
-----END RSA PRIVATE KEY-----
"""

function signDocument(document):
    signature = crypto.sign(document, RSA_PRIVATE_KEY, "SHA256")
    return signature

function decryptMessage(encryptedData):
    return crypto.decrypt(encryptedData, RSA_PRIVATE_KEY)
```

**Why This Is Dangerous:**
- Private keys MUST remain private - this defeats all cryptography
- Anyone with the key can decrypt all encrypted data
- Can sign malicious documents that appear legitimate
- Often leads to impersonation of servers/services
- Key pairs cannot be safely rotated without code changes

---

## GOOD Examples: Proper Patterns

### GOOD Example 1: Environment Variable Usage

```pseudocode
// SECURE: Load credentials from environment
class PaymentService:
    function __init__():
        this.apiKey = getEnvironmentVariable("PAYMENT_API_KEY")
        this.apiSecret = getEnvironmentVariable("PAYMENT_API_SECRET")

        // Fail fast if credentials missing
        if this.apiKey is null or this.apiSecret is null:
            throw ConfigurationError("Payment credentials not configured")

    function processPayment(amount, currency, cardToken):
        headers = {
            "Authorization": "Bearer " + this.apiKey,
            "Content-Type": "application/json"
        }

        payload = {
            "amount": amount,
            "currency": currency,
            "source": cardToken
            // No API key in payload
        }

        return httpPost("https://api.payment.com/charges", payload, headers)

// Usage in application startup
// Environment variables set externally (shell, container, deployment)
// $ export PAYMENT_API_KEY="sk_live_..."
// $ export PAYMENT_API_SECRET="whsec_..."
```

**Why This Is Secure:**
- Credentials never appear in source code
- Environment variables are set at runtime by deployment system
- Different environments (dev/staging/prod) use different credentials
- Credentials can be rotated without code changes
- Fail-fast behavior prevents running with missing config

---

### GOOD Example 2: Secret Management Services (Vault Pattern)

```pseudocode
// SECURE: Retrieve secrets from dedicated secrets manager
class SecretManager:
    function __init__(vaultUrl, roleId, secretId):
        // Even vault credentials can come from environment
        this.vaultUrl = vaultUrl or getEnvironmentVariable("VAULT_URL")
        this.roleId = roleId or getEnvironmentVariable("VAULT_ROLE_ID")
        this.secretId = secretId or getEnvironmentVariable("VAULT_SECRET_ID")
        this.token = null
        this.tokenExpiry = null

    function authenticate():
        response = httpPost(this.vaultUrl + "/v1/auth/approle/login", {
            "role_id": this.roleId,
            "secret_id": this.secretId
        })
        this.token = response.auth.client_token
        this.tokenExpiry = currentTime() + response.auth.lease_duration

    function getSecret(path):
        if this.token is null or currentTime() > this.tokenExpiry:
            this.authenticate()

        response = httpGet(
            this.vaultUrl + "/v1/secret/data/" + path,
            headers = {"X-Vault-Token": this.token}
        )
        return response.data.data

// Usage
secretManager = new SecretManager()
dbPassword = secretManager.getSecret("database/production").password
apiKey = secretManager.getSecret("payment/stripe").api_key
```

**Why This Is Secure:**
- Secrets stored in purpose-built, hardened secrets manager
- Access controlled by policies (who can read what)
- Automatic secret rotation support
- Audit logging of all secret access
- Dynamic secrets possible (e.g., temporary database credentials)
- Secrets never written to disk or logs

---

### GOOD Example 3: Configuration Injection at Runtime

```pseudocode
// SECURE: Dependency injection of configuration
interface IConfig:
    function getDatabaseUrl(): string
    function getApiKey(): string
    function getJwtSecret(): string

class EnvironmentConfig implements IConfig:
    function getDatabaseUrl():
        return getEnvironmentVariable("DATABASE_URL")

    function getApiKey():
        return getEnvironmentVariable("API_KEY")

    function getJwtSecret():
        return getEnvironmentVariable("JWT_SECRET")

class VaultConfig implements IConfig:
    secretManager: SecretManager

    function getDatabaseUrl():
        return this.secretManager.getSecret("db/url").value

    function getApiKey():
        return this.secretManager.getSecret("api/key").value

    function getJwtSecret():
        return this.secretManager.getSecret("jwt/secret").value

// Application uses interface - doesn't know where secrets come from
class Application:
    config: IConfig

    function __init__(config: IConfig):
        this.config = config

    function connectDatabase():
        return createConnection(this.config.getDatabaseUrl())

// Bootstrap based on environment
if getEnvironmentVariable("USE_VAULT") == "true":
    config = new VaultConfig(new SecretManager())
else:
    config = new EnvironmentConfig()

app = new Application(config)
```

**Why This Is Secure:**
- Application code never knows actual secret values at compile time
- Easy to swap secret sources (env vars in dev, vault in prod)
- Testable - can inject mock configs in tests
- Single responsibility - config management separated from business logic
- Supports gradual migration to more secure secret storage

---

### GOOD Example 4: Secure Credential Storage Patterns

```pseudocode
// SECURE: Platform-specific secure credential storage

// For server applications - use instance metadata
class CloudCredentialProvider:
    function getDatabaseCredentials():
        // AWS: Use IAM database authentication
        token = awsRdsGenerateAuthToken(
            hostname = getEnvironmentVariable("DB_HOST"),
            port = 5432,
            username = getEnvironmentVariable("DB_USER")
            // No password - uses IAM role attached to instance
        )
        return {"username": getEnvironmentVariable("DB_USER"), "token": token}

    function getApiCredentials():
        // Retrieve from AWS Secrets Manager
        response = awsSecretsManager.getSecretValue(
            SecretId = getEnvironmentVariable("API_SECRET_ARN")
        )
        return parseJson(response.SecretString)

// For CLI/desktop applications - use OS keychain
class DesktopCredentialProvider:
    function storeCredential(service, account, credential):
        // Uses OS keychain (Keychain on macOS, Credential Manager on Windows)
        keychain.setPassword(service, account, credential)

    function getCredential(service, account):
        return keychain.getPassword(service, account)

// Usage
cloudProvider = new CloudCredentialProvider()
dbCreds = cloudProvider.getDatabaseCredentials()
connection = createConnection(
    host = getEnvironmentVariable("DB_HOST"),
    user = dbCreds.username,
    authToken = dbCreds.token,  // Short-lived token, not password
    sslMode = "verify-full"
)
```

**Why This Is Secure:**
- Leverages cloud provider's identity and access management
- No long-lived passwords - uses temporary tokens
- Credentials automatically rotated by platform
- OS keychains provide encrypted, access-controlled storage
- Audit trail in cloud provider logs

---

## Edge Cases Section

### Edge Case 1: Test Credentials That Leak to Production

```pseudocode
// DANGEROUS: Test credentials that can slip into production

// In test file - seems safe
TEST_API_KEY = "sk_test_4242424242424242"
TEST_DB_PASSWORD = "testpassword123"

// But then someone copies test code to production helper:
function quickTest():
    // "Temporary" - but stays forever
    client = createClient(apiKey = "sk_test_4242424242424242")
    return client.ping()

// Or conditionals that fail:
function getApiKey():
    if isProduction():
        return getEnvironmentVariable("API_KEY")
    else:
        return "sk_test_4242424242424242"  // What if isProduction() has a bug?

// SECURE ALTERNATIVE: Use environment variables even for tests
function getApiKey():
    key = getEnvironmentVariable("API_KEY")
    if key is null:
        throw ConfigurationError("API_KEY environment variable required")
    return key
```

**Detection:** Search for `_test_`, `_dev_`, `test123`, `password123`, `example`, `placeholder` in codebase.

---

### Edge Case 2: CI/CD Pipeline Secrets Exposure

```pseudocode
// DANGEROUS: Secrets in CI/CD configuration files

// .github/workflows/deploy.yml (WRONG)
env:
    AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

// docker-compose.yml committed to repo (WRONG)
services:
    db:
        environment:
            POSTGRES_PASSWORD: mysecretpassword

// SECURE: Use CI/CD platform's secrets management
// .github/workflows/deploy.yml (CORRECT)
env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}

// docker-compose.yml (CORRECT)
services:
    db:
        environment:
            POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}  // From environment
```

**Detection:** Audit CI/CD config files, Docker Compose files, Kubernetes manifests for hardcoded credentials.

---

### Edge Case 3: Docker/Container Secrets Handling

```pseudocode
// DANGEROUS: Secrets in Dockerfile or image layers

// Dockerfile (WRONG - secrets baked into image)
FROM node:18
ENV API_KEY=sk_live_xxxxxxxxxxxxx
RUN echo "password123" > /app/.pgpass
COPY config-with-secrets.json /app/config.json

// Even if you delete later, it's in a layer:
RUN rm /app/.pgpass  // Still recoverable from image layers!

// SECURE: Use build secrets or runtime injection
// Dockerfile (CORRECT)
FROM node:18
# No secrets in build context

// docker-compose.yml with runtime secrets
services:
    app:
        environment:
            API_KEY: ${API_KEY}  // From host environment
        secrets:
            - db_password
secrets:
    db_password:
        external: true  // From Docker Swarm secrets or similar

// Or use Docker BuildKit secrets for build-time needs
# syntax=docker/dockerfile:1.2
FROM node:18
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN=$(cat /run/secrets/npm_token) npm install
```

**Detection:** Use `docker history --no-trunc <image>` to inspect layers for secrets.

---

### Edge Case 4: Logging That Accidentally Captures Secrets

```pseudocode
// DANGEROUS: Secrets leaked through logging

function connectToDatabase(config):
    logger.info("Connecting with config: " + toJson(config))
    // Logs: {"host": "db.com", "user": "admin", "password": "secret123"}

function makeApiRequest(url, headers, body):
    logger.debug("Request: " + url + " Headers: " + toJson(headers))
    // Logs: Authorization: Bearer sk_live_xxxxx

function handleError(error):
    logger.error("Error: " + error.message + " Stack: " + error.stack)
    // Stack trace might contain secrets from variables

// SECURE: Sanitize before logging
function sanitizeForLogging(obj):
    sensitiveKeys = ["password", "secret", "key", "token", "auth", "credential"]
    result = deepCopy(obj)
    for key in result.keys():
        if any(sensitive in key.lower() for sensitive in sensitiveKeys):
            result[key] = "[REDACTED]"
    return result

function connectToDatabase(config):
    logger.info("Connecting with config: " + toJson(sanitizeForLogging(config)))
    // Logs: {"host": "db.com", "user": "admin", "password": "[REDACTED]"}

// Or use structured logging with secret types
class Secret:
    value: string
    function toString(): return "[SECRET]"
    function toJson(): return "[SECRET]"
    function getValue(): return this.value  // Only accessible explicitly
```

**Detection:** Search logs for patterns like `password=`, `token=`, `key=`, bearer tokens, connection strings.

---

## Common Mistakes Section

### Mistake 1: .env Files Committed to Git

```pseudocode
// project/.env (NEVER COMMIT THIS)
DATABASE_URL=postgresql://user:password@localhost/db
API_KEY=sk_live_xxxxxxxxxx
JWT_SECRET=my-secret-key

// .gitignore (MUST INCLUDE)
.env
.env.local
.env.*.local
*.pem
*.key
credentials.json
secrets.yaml

// CORRECT: Commit a template instead
// project/.env.example (SAFE TO COMMIT)
DATABASE_URL=postgresql://user:password@localhost/db
API_KEY=your_api_key_here
JWT_SECRET=generate_a_secure_random_string

// Add pre-commit hook to prevent accidental commits
// .git/hooks/pre-commit
#!/bin/bash
if git diff --cached --name-only | grep -E '\.env$|credentials|secrets'; then
    echo "ERROR: Attempting to commit potential secrets file"
    exit 1
fi
```

**Detection:** Check git history: `git log --all --full-history -- "*.env" "*credentials*" "*secrets*"`

---

### Mistake 2: Secrets in Error Messages

```pseudocode
// DANGEROUS: Secrets exposed in error handling

function connectToPaymentApi():
    try:
        apiKey = getApiKey()
        response = httpPost(
            "https://api.payment.com/connect",
            headers = {"Authorization": "Bearer " + apiKey}
        )
    catch error:
        // Exposes API key in error log and potentially to users
        throw new Error("Failed to connect with key: " + apiKey + ". Error: " + error)

// SECURE: Never include secrets in error messages
function connectToPaymentApi():
    try:
        apiKey = getApiKey()
        response = httpPost(
            "https://api.payment.com/connect",
            headers = {"Authorization": "Bearer " + apiKey}
        )
    catch error:
        // Log correlation ID, not secrets
        correlationId = generateUUID()
        logger.error("Payment API connection failed", {
            "correlationId": correlationId,
            "errorCode": error.code,
            "endpoint": "api.payment.com"
            // No API key!
        })
        throw new Error("Payment service unavailable. Reference: " + correlationId)
```

---

### Mistake 3: Secrets in URLs (Query Parameters)

```pseudocode
// DANGEROUS: Secrets in URL query parameters

function makeAuthenticatedRequest(endpoint, apiKey):
    // API keys in URLs are logged everywhere:
    // - Browser history
    // - Server access logs
    // - Proxy logs
    // - Referrer headers
    url = "https://api.service.com" + endpoint + "?api_key=" + apiKey
    return httpGet(url)

// Even worse with multiple secrets:
url = "https://api.com/data?key=" + apiKey + "&secret=" + secretKey

// SECURE: Use headers for authentication
function makeAuthenticatedRequest(endpoint, apiKey):
    return httpGet(
        "https://api.service.com" + endpoint,
        headers = {
            "Authorization": "Bearer " + apiKey,
            // Or API-specific header
            "X-API-Key": apiKey
        }
    )
```

**Detection:** Search for URLs containing `?api_key=`, `?token=`, `?secret=`, `?password=`

---

## Detection Hints: How to Spot This Pattern in Code Review

### Automated Detection Patterns

```pseudocode
// High-confidence patterns to search for:

// 1. Direct assignment to suspicious variable names
regex: /(password|secret|key|token|credential|api.?key)\s*[=:]\s*["'][^"']+["']/i

// 2. Common API key formats
regex: /(sk_live_|sk_test_|pk_live_|pk_test_|ghp_|gho_|AKIA|AIza)/

// 3. Private key markers
regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/

// 4. Connection strings with passwords
regex: /(mysql|postgresql|mongodb|redis):\/\/[^:]+:[^@]+@/

// 5. Base64 encoded secrets (often JWT secrets)
regex: /["'][A-Za-z0-9+\/=]{40,}["']/
```

### Manual Code Review Checklist

| Check | What to Look For |
|-------|------------------|
| **Constants** | Any string constants in authentication/configuration code |
| **Config Objects** | Credential fields with non-placeholder values |
| **Connection Code** | Database connections, API clients with inline credentials |
| **Test Files** | Test credentials that might be real or become real |
| **CI/CD** | Pipeline configs, Docker files, deployment scripts |
| **Comments** | "TODO: move to env" comments with actual secrets |

### Tools for Detection

1. **git-secrets** - Prevents committing secrets to git
2. **truffleHog** - Scans git history for secrets
3. **GitGuardian** - SaaS secret detection
4. **gitleaks** - SAST tool for detecting secrets
5. **detect-secrets** - Yelp's secret detection tool

---

## Security Checklist

- [ ] No credentials, API keys, or secrets in source code
- [ ] No secrets in configuration files committed to version control
- [ ] `.gitignore` includes all secret file patterns (`.env`, `*.pem`, etc.)
- [ ] Pre-commit hooks prevent accidental secret commits
- [ ] Environment variables or secrets manager used for all credentials
- [ ] No secrets in CI/CD configuration files (use platform secrets)
- [ ] No secrets in Docker images or Dockerfile
- [ ] Logging sanitizes sensitive fields
- [ ] Error messages never include secrets
- [ ] No secrets in URL query parameters
- [ ] Test credentials are clearly fake and cannot work in production
- [ ] Secret scanning enabled in repository settings

---
