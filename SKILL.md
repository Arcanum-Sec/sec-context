---
name: sec-context
description: Use when generating or reviewing code to detect and prevent common security anti-patterns. Covers 25+ vulnerability classes across 10 security domains with BAD/GOOD pseudocode examples and remediation guidance. Based on 150+ research sources.
---

# Sec-Context -- AI Code Security Anti-Patterns

Security anti-pattern detection and remediation for AI coding agents. Use this skill to catch the well-documented vulnerability patterns that AI models consistently reproduce.

## When to Apply

Apply when generating or reviewing code that touches:

- authentication, authorization, or session management
- database queries or command execution
- HTML rendering, rich text, or output encoding
- user input parsing, validation, or sanitization
- cryptographic operations, hashing, or key management
- file uploads, downloads, or path handling
- API endpoints, rate limiting, or data exposure
- secrets, tokens, credentials, or configuration
- dependency selection or package management
- deployment configuration, CORS, or security headers

Also apply when explicitly asked for a security review of generated code.

## Do Not Apply

- full threat modeling (use a dedicated threat-modeling skill)
- dependency/CVE scanning or SAST/DAST tooling
- infrastructure hardening unrelated to application code
- compliance or regulatory audits

## Quick Reference Table

| Pattern | CWE | Severity | Quick Fix |
|---------|-----|----------|-----------|
| Hallucinated Packages | CWE-1357 | Critical | Verify packages exist before import |
| XSS (Reflected/Stored/DOM) | CWE-79 | Critical | Encode output for context |
| Hardcoded Secrets | CWE-798 | Critical | Use environment variables |
| SQL Injection | CWE-89 | Critical | Use parameterized queries |
| Missing Authentication | CWE-287 | Critical | Apply auth to all protected endpoints |
| Command Injection | CWE-78 | Critical | Use argument arrays, avoid shell |
| Missing Input Validation | CWE-20 | High | Validate type, length, format, range |
| Unrestricted File Upload | CWE-434 | Critical | Validate extension, MIME, and size |
| Insufficient Randomness | CWE-330 | High | Use secrets module for tokens |
| Missing Rate Limiting | CWE-770 | High | Implement per-IP/user limits |
| Excessive Data Exposure | CWE-200 | High | Use DTOs with field allowlists |
| Path Traversal | CWE-22 | High | Validate paths within allowed dirs |
| Weak Password Hashing | CWE-327 | High | Use bcrypt/argon2 with salt |
| Log Injection | CWE-117 | Medium | Sanitize newlines, use structured logging |
| Debug Mode in Production | CWE-215 | High | Environment-based configuration |
| Weak Encryption | CWE-326 | High | Use AES-GCM or ChaCha20-Poly1305 |
| Session Fixation | CWE-384 | High | Regenerate session ID on login |
| JWT Misuse | CWE-287 | High | Strong secrets, explicit algorithms |
| Mass Assignment | CWE-915 | High | Allowlist assignable fields |
| Missing Security Headers | CWE-16 | Medium | Add CSP, X-Frame-Options, HSTS |
| Open CORS | CWE-346 | Medium | Restrict to known origins |
| LDAP Injection | CWE-90 | High | Escape special LDAP characters |
| XPath Injection | CWE-643 | High | Use parameterized XPath or validate |
| Insecure Temp Files | CWE-377 | Medium | Use mkstemp with restrictive perms |
| Verbose Error Messages | CWE-209 | Medium | Generic external, detailed internal |

## Routing -- References to Load (Progressive Disclosure)

Identify which security surface(s) the current task touches, then load **only** the matching reference files. Each surface has a **breadth** file (concise BAD/GOOD pattern pairs) and, for the 6 highest-priority surfaces, a **depth** file (multiple examples, edge cases, common mistakes, detection hints).

**Load breadth first.** Add depth only when doing a thorough review, when the breadth coverage is insufficient for the specific case, or when the user explicitly asks for deeper analysis.

**Load at most 2-3 surfaces per task** to keep context manageable.

| Surface | Trigger Keywords | CWEs | Breadth | Depth |
|---------|-----------------|------|---------|-------|
| Secrets & Credentials | API key, password, token, credential, env var, vault, .env | 798, 259, 321 | [secrets-breadth.md](./references/secrets-breadth.md) | [secrets-depth.md](./references/secrets-depth.md) |
| Injection | SQL, query, command, shell, exec, LDAP, XPath, NoSQL, template | 89, 77, 78, 90, 643 | [injection-breadth.md](./references/injection-breadth.md) | [injection-depth.md](./references/injection-depth.md) |
| Cross-Site Scripting | innerHTML, html_safe, raw, dangerouslySetInnerHTML, CSP, sanitize, encode | 79, 80, 83, 87 | [xss-breadth.md](./references/xss-breadth.md) | [xss-depth.md](./references/xss-depth.md) |
| Authentication & Sessions | login, session, JWT, password, MFA, token, cookie, OAuth, rate limit | 287, 384, 613, 307, 308, 640 | [authentication-breadth.md](./references/authentication-breadth.md) | [authentication-depth.md](./references/authentication-depth.md) |
| Cryptography | encrypt, hash, bcrypt, AES, MD5, SHA, IV, nonce, key, random | 327, 328, 330, 338, 916 | [cryptography-breadth.md](./references/cryptography-breadth.md) | [cryptography-depth.md](./references/cryptography-depth.md) |
| Input Validation | validate, sanitize, regex, parse, type check, allowlist, canonicalize | 20, 1286, 185, 1333, 129 | [input-validation-breadth.md](./references/input-validation-breadth.md) | [input-validation-depth.md](./references/input-validation-depth.md) |
| Configuration & Deployment | debug, CORS, headers, error messages, admin, default credentials | 215, 209, 16, 346, 1004 | [config-deployment-breadth.md](./references/config-deployment-breadth.md) | -- |
| Dependencies & Supply Chain | package, dependency, npm, gem, pip, version, supply chain, slopsquatting | 1357, 1104, 829 | [dependencies-breadth.md](./references/dependencies-breadth.md) | -- |
| API Security | endpoint, auth, IDOR, rate limit, mass assignment, DTO, data exposure | 862, 639, 915, 200, 770 | [api-security-breadth.md](./references/api-security-breadth.md) | -- |
| File Handling | upload, download, path, file, traversal, symlink, permission, temp | 22, 434, 59, 377 | [file-handling-breadth.md](./references/file-handling-breadth.md) | -- |

## Required Workflow

1. **Identify surfaces** -- determine which security surfaces the current code touches using the trigger keywords above.
2. **Load breadth** -- read the breadth file for each matching surface (max 2-3).
3. **Check patterns** -- compare the code against the BAD examples. Flag matches.
4. **Apply fixes** -- use the GOOD examples as remediation templates.
5. **Go deeper if needed** -- load the depth file when edge cases, common mistakes, or thorough review guidance is required.
6. **Output findings** -- report specific vulnerabilities found, secure replacements, and any test suggestions.

## Output Guidance

When reporting findings:

- Reference specific anti-pattern names and CWE IDs.
- Show the insecure pattern found and the secure replacement.
- Prioritize by severity (Critical > High > Medium).
- Keep findings tied to the actual code being reviewed -- avoid generic recitals.
- Suggest concrete tests for the most critical findings.
- If risk is low, state it clearly and move on.

## Security Surface Identification Checklist

**Use this checklist to identify which security surfaces are relevant to the current task. Scan the categories below and note which ones apply to the code being written or reviewed. Then load ONLY the matching reference files from the routing table above.**

**Do NOT load references for categories that are not relevant. Do NOT attempt to verify every item -- focus only on the surfaces touched by the current code path.**

### Secrets & Credentials
- [ ] No hardcoded API keys, passwords, tokens, or secrets
- [ ] Credentials loaded from environment variables or secret managers
- [ ] No secrets in client-side/frontend code
- [ ] Git history checked for accidentally committed secrets

### Input Handling
- [ ] All user input validated on the SERVER side
- [ ] Input type, length, and format constraints enforced
- [ ] Database queries use parameterized/prepared statements
- [ ] Shell commands use argument arrays, not string concatenation
- [ ] File paths validated and canonicalized before use

### Output Encoding
- [ ] HTML output properly encoded to prevent XSS
- [ ] Context-appropriate encoding (HTML, URL, JS, CSS)
- [ ] Content-Security-Policy header configured
- [ ] Error messages don't expose internal details

### Authentication & Sessions
- [ ] Passwords hashed with bcrypt/Argon2 (not MD5/SHA1)
- [ ] Session tokens generated with cryptographically secure randomness
- [ ] Session IDs regenerated on authentication state changes
- [ ] Rate limiting on authentication endpoints
- [ ] JWT tokens use strong secrets and explicit algorithms

### Cryptography
- [ ] Modern algorithms only (AES-GCM, ChaCha20-Poly1305)
- [ ] Keys from environment/secret manager, not hardcoded
- [ ] Unique IVs/nonces for each encryption operation
- [ ] Key derivation uses PBKDF2/Argon2/scrypt

### File Operations
- [ ] File uploads validate extension, MIME type, and magic bytes
- [ ] File size limits enforced
- [ ] Uploaded files stored outside web root
- [ ] Path traversal prevented with basename + realpath validation
- [ ] Temp files use mkstemp with restrictive permissions

### API Security
- [ ] All endpoints require authentication (unless explicitly public)
- [ ] Object-level authorization verified (ownership checks)
- [ ] Response DTOs with explicit field allowlists
- [ ] Rate limiting applied to prevent abuse
- [ ] Error responses use standard format without internal details

### Dependencies
- [ ] Package names verified to exist before importing
- [ ] Dependencies pinned to exact versions with lockfiles
- [ ] No packages with known vulnerabilities
- [ ] Transitive dependencies reviewed

### Configuration
- [ ] Debug mode disabled in production
- [ ] Default credentials replaced with strong values
- [ ] Security headers configured (CSP, HSTS, X-Frame-Options)
- [ ] CORS restricted to known origins
- [ ] Admin interfaces protected with additional authentication

## Attribution

This skill is based on the [Sec-Context](https://github.com/arcanum-sec/sec-context) project by Jason Haddix / Arcanum Information Security, licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Content distilled from 150+ sources across academic papers, CVE databases, security blogs, and developer communities.
