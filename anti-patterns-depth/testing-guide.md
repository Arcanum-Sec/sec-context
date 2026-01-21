# Testing Guide

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

