# Quick Reference Table

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

---

