# Anti-Patterns Breadth - Comprehensive Security Coverage

This directory contains a comprehensive collection of security anti-patterns extracted from the original ANTI_PATTERNS_BREADTH.md file. Each pattern is now stored as an individual file for easier reference and use.

## Overview

This collection covers 10 major categories of security vulnerabilities with detailed examples of bad practices (BAD) and secure alternatives (GOOD). Each file includes:
- Description of the vulnerability
- Common CWE references
- Severity indicators
- BAD code examples showing the anti-pattern
- GOOD code examples showing secure practices
- Related security considerations

## Quick Reference

- [Quick Reference Table](quick-reference-table.md) - Overview of all patterns
- [Instructions for AI/LLM](INSTRUCTIONS.md) - How to use these patterns

## Patterns by Category

### 1. Secrets and Credentials Management
- [Hardcoded Passwords and API Keys](hardcoded-passwords-api-keys.md)
- [Credentials in Configuration Files](credentials-in-config-files.md)
- [Secrets in Client-Side Code](secrets-in-client-side-code.md)
- [Insecure Credential Storage](insecure-credential-storage.md)
- [Missing Secret Rotation Considerations](missing-secret-rotation.md)

### 2. Injection Vulnerabilities
- [SQL Injection](sql-injection.md)
- [Command Injection](command-injection.md)
- [LDAP Injection](ldap-injection.md)
- [XPath Injection](xpath-injection.md)
- [NoSQL Injection](nosql-injection.md)
- [Template Injection](template-injection.md)

### 3. Cross-Site Scripting (XSS)
- [Reflected XSS](reflected-xss.md)
- [Stored XSS](stored-xss.md)
- [DOM-Based XSS](dom-based-xss.md)
- [Missing Content-Security-Policy](missing-content-security-policy.md)
- [Improper Output Encoding](improper-output-encoding.md)

### 4. Authentication and Session Management
- [Weak Password Requirements](weak-password-requirements.md)
- [Missing Rate Limiting on Auth Endpoints](missing-rate-limiting-auth.md)
- [Insecure Session Token Generation](insecure-session-token-generation.md)
- [Session Fixation Vulnerabilities](session-fixation.md)
- [JWT Misuse](jwt-misuse.md)
- [Missing MFA Considerations](missing-mfa.md)
- [Insecure Password Reset Flows](insecure-password-reset.md)

### 5. Cryptographic Failures
- [Using Deprecated Algorithms](deprecated-crypto-algorithms.md)
- [Hardcoded Encryption Keys](hardcoded-encryption-keys.md)
- [ECB Mode Usage](ecb-mode-usage.md)
- [Missing or Weak IVs/Nonces](missing-weak-ivs-nonces.md)
- [Rolling Your Own Crypto](rolling-your-own-crypto.md)
- [Insecure Random Number Generation](insecure-random-generation.md)
- [Improper Key Derivation](improper-key-derivation.md)

### 6. Input Validation
- [Missing Server-Side Validation](missing-server-side-validation.md)
- [Improper Type Checking](improper-type-checking.md)
- [Missing Length Limits](missing-length-limits.md)
- [Regex Denial of Service (ReDoS)](regex-denial-of-service.md)
- [Accepting and Processing Untrusted Data](accepting-untrusted-data.md)
- [Missing Canonicalization](missing-canonicalization.md)

### 7. Configuration and Deployment
- [Debug Mode in Production](debug-mode-in-production.md)
- [Verbose Error Messages](verbose-error-messages.md)
- [Default Credentials](default-credentials.md)
- [Insecure CORS Configuration](insecure-cors-configuration.md)
- [Missing Security Headers](missing-security-headers.md)
- [Exposed Admin Interfaces](exposed-admin-interfaces.md)
- [Unnecessary Open Ports and Services](unnecessary-open-ports.md)

### 8. Dependency and Supply Chain Security
- [Using Outdated Packages](outdated-packages.md)
- [Not Pinning Dependency Versions](not-pinning-dependency-versions.md)
- [Typosquatting and Slopsquatting Risks](typosquatting-risks.md)
- [Including Unnecessary Dependencies](unnecessary-dependencies.md)
- [Missing Integrity Checks](missing-integrity-checks.md)
- [Trusting Transitive Dependencies Blindly](trusting-transitive-dependencies.md)

### 9. API Security
- [Missing Authentication on Endpoints](missing-authentication-endpoints.md)
- [Broken Object-Level Authorization (IDOR)](broken-object-level-authorization.md)
- [Mass Assignment Vulnerabilities](mass-assignment.md)
- [Excessive Data Exposure](excessive-data-exposure.md)
- [Missing Rate Limiting](missing-rate-limiting-api.md)
- [Improper Error Handling in APIs](improper-error-handling-api.md)

### 10. File Handling
- [Path Traversal Vulnerabilities](path-traversal.md)
- [Unrestricted File Uploads](unrestricted-file-uploads.md)
- [Missing File Type Validation](missing-file-type-validation.md)
- [Insecure Temporary File Handling](insecure-temporary-file-handling.md)
- [Symlink Vulnerabilities](symlink-vulnerabilities.md)
- [Unsafe File Permissions](unsafe-file-permissions.md)

## How to Use This Collection

Each file in this directory is self-contained and includes:
- Pattern description and context
- BAD examples showing vulnerable code
- GOOD examples showing secure alternatives
- Security considerations and best practices

You can reference individual files based on specific security concerns, or use the entire collection as a comprehensive security reference.

## Source

This content was extracted from the original `ANTI_PATTERNS_BREADTH.md` file to provide better organization and easier access to individual patterns.
