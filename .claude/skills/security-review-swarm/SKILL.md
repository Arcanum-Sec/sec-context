---
name: security-review-swarm
description: Comprehensive security code review using parallel agent swarms. Use this skill when performing security audits, vulnerability assessments, or pre-deployment security reviews on codebases. Triggers include: "security review", "security audit", "vulnerability scan", "find vulnerabilities", "check for security issues", "pentest the code", "audit authentication", "review for injection", "check for XSS", "credential scan", or any request involving security analysis of code. Supports both quick breadth scans and deep audits using specialized parallel agents for secrets, injection, XSS, authentication, cryptography, input validation, and dependency analysis.
---

# Security Review Swarm

Orchestrates parallel security review agents using Claude Code's TeammateTool and Task system for comprehensive vulnerability detection.

## Usage Patterns

```
/security-review                        # Quick breadth review of staged/recent changes
/security-review src/                   # Review specific directory (breadth)
/security-review --deep                 # Deep audit with parallel specialists
/security-review --deep src/auth/       # Deep audit of specific path
/security-review --full                 # Complete swarm: all specialists in parallel
```

## Review Modes

| Mode | Agents | Patterns | Use Case |
|------|--------|----------|----------|
| **Quick** (default) | 1 | 25+ breadth | PRs, quick scans, daily reviews |
| **Deep** (`--deep`) | 1 | 7 critical depth | Auth, crypto, payments, pre-launch |
| **Full** (`--full`) | 7 parallel | All patterns | Complete security audit |

## Orchestration Instructions

### Mode 1: Quick Review (Default)

Single-agent review using BREADTH patterns:

1. Load `references/ANTI_PATTERNS_BREADTH.md`
2. Determine scope (file path, `git diff HEAD~1`, or `git diff --cached`)
3. Analyze against all 25+ patterns, prioritizing:
   - §1: Secrets and Credentials
   - §2: Injection (SQL, Command, NoSQL)
   - §3: XSS (Reflected, Stored, DOM)
   - §4: Authentication & Sessions
4. Report findings in standard format

### Mode 2: Deep Review (`--deep`)

Single-agent deep dive using DEPTH patterns:

1. Load `references/ANTI_PATTERNS_DEPTH.md`
2. For each of the 7 critical patterns, check:
   - Multiple manifestation examples
   - Edge cases section
   - Common mistakes section
   - Detection hints
3. Include security checklists in report

### Mode 3: Full Swarm Review (`--full`)

Parallel specialist agents for comprehensive coverage:

```pseudocode
// 1. Create review team
Teammate({ operation: "spawnTeam", team_name: "security-review-{timestamp}" })

// 2. Create task queue for findings aggregation
TaskCreate({ subject: "Aggregate Findings", description: "Collect all specialist reports" })

// 3. Spawn 7 parallel specialists
specialists = [
    {name: "secrets-scanner", focus: "Pattern 1: Hardcoded Secrets"},
    {name: "injection-hunter", focus: "Pattern 2: SQL/Command Injection"},
    {name: "xss-detector", focus: "Pattern 3: Cross-Site Scripting"},
    {name: "auth-auditor", focus: "Pattern 4: Authentication & Sessions"},
    {name: "crypto-reviewer", focus: "Pattern 5: Cryptographic Failures"},
    {name: "input-validator", focus: "Pattern 6: Input Validation"},
    {name: "dependency-checker", focus: "Pattern 7: Dependencies & Supply Chain"}
]

FOR specialist IN specialists:
    Task({
        team_name: team_name,
        name: specialist.name,
        subagent_type: "general-purpose",
        prompt: buildSpecialistPrompt(specialist, targetPath, context),
        run_in_background: true
    })

// 4. Wait for all specialists to report
// 5. Synthesize findings into unified report
// 6. Cleanup team
```

## Specialist Prompts

### Secrets Scanner Agent

```
You are a security specialist focused on credential and secrets exposure.

SCOPE: {target_path}

Review for Pattern 1 (Hardcoded Secrets) from the security anti-patterns guide:

CHECK FOR:
1. API keys, tokens, passwords in source code
2. Database connection strings with embedded credentials
3. JWT secrets and signing keys
4. Private keys (RSA, EC, SSH)
5. OAuth client secrets (especially in frontend code)
6. AWS/GCP/Azure credentials
7. Secrets in CI/CD configs, Docker files, environment files
8. Credentials leaked in logs or error messages
9. Test credentials that could work in production
10. Secrets in URL query parameters

DETECTION PATTERNS:
- Variables named: password, secret, key, token, credential, api_key
- Patterns: sk_live_, sk_test_, ghp_, gho_, AKIA, AIza
- Private key markers: -----BEGIN (RSA|EC|DSA|OPENSSH)?PRIVATE KEY-----
- Connection strings: (mysql|postgresql|mongodb|redis)://[^:]+:[^@]+@

Send findings to team-lead with:
- File path and line number
- CWE reference (CWE-798, CWE-259, CWE-321)
- Severity (Critical/High)
- Specific remediation
```

### Injection Hunter Agent

```
You are a security specialist focused on injection vulnerabilities.

SCOPE: {target_path}

Review for Pattern 2 (Injection) from the security anti-patterns guide:

CHECK FOR:
1. SQL queries with string concatenation or interpolation
2. Dynamic table/column names without allowlist
3. ORDER BY, LIMIT clauses with user input
4. Shell commands constructed with user data
5. LDAP filter construction
6. XPath query building
7. NoSQL query injection ($ne, $gt operators from user input)
8. Template injection (SSTI)
9. Second-order injection (stored data used unsafely later)
10. ORM raw queries without parameterization

DETECTION PATTERNS:
- String concat in queries: (SELECT|INSERT|UPDATE|DELETE).*(\+|concat|\${|f['"])
- Shell with variables: (system|exec|subprocess).*(\+|\${)
- shell=True usage

Send findings to team-lead with CWE-89, CWE-78, CWE-90, CWE-643 references.
```

### XSS Detector Agent

```
You are a security specialist focused on Cross-Site Scripting.

SCOPE: {target_path}

Review for Pattern 3 (XSS) from the security anti-patterns guide:

CHECK FOR:
1. innerHTML, document.write with user data
2. React dangerouslySetInnerHTML without sanitization
3. Vue v-html directive with user input
4. Angular bypassSecurityTrust* usage
5. Template |safe, {{{ }}} (triple braces), <%- %> patterns
6. User input in HTML attributes (especially event handlers)
7. JavaScript context injection
8. URL context (javascript:, data: schemes)
9. CSS context injection
10. Missing Content-Security-Policy headers

CONTEXT-SPECIFIC ENCODING CHECK:
- HTML body: &lt; &gt; &amp; &quot; &#x27;
- Attributes: Above + &#x60; &#x3D;
- JavaScript: \\' \\" \\n \\x3c \\x3e
- URL: encodeURIComponent

Send findings to team-lead with CWE-79, CWE-80, CWE-83 references.
```

### Auth Auditor Agent

```
You are a security specialist focused on authentication and session security.

SCOPE: {target_path}

Review for Pattern 4 (Authentication) from the security anti-patterns guide:

CHECK FOR:
1. Weak password validation (length only, no breach check)
2. Predictable session tokens (sequential, timestamp-based)
3. Session not regenerated after login (fixation)
4. JWT "none" algorithm acceptance
5. Weak JWT secrets (< 256 bits)
6. Tokens in localStorage (XSS exposure)
7. Missing token expiration
8. No rate limiting on auth endpoints
9. Insecure password reset flows
10. Missing MFA for sensitive operations

SESSION SECURITY:
- HttpOnly, Secure, SameSite cookie flags
- Session invalidation on logout
- Concurrent session handling

Send findings to team-lead with CWE-287, CWE-384, CWE-613, CWE-307 references.
```

### Crypto Reviewer Agent

```
You are a security specialist focused on cryptographic implementations.

SCOPE: {target_path}

Review for Pattern 5 (Cryptographic Failures) from the security anti-patterns guide:

CHECK FOR:
1. Deprecated algorithms (MD5, SHA1 for security, DES, RC4)
2. Hardcoded encryption keys
3. ECB mode usage (reveals patterns)
4. Missing or predictable IVs/nonces
5. Custom/"homegrown" crypto implementations
6. Math.random() for security tokens
7. Weak key derivation (direct hash vs PBKDF2/Argon2)
8. Insufficient key lengths (< 256 bits for symmetric)
9. Password storage without bcrypt/argon2
10. Missing authenticated encryption (use GCM, not CBC alone)

SECURE ALTERNATIVES:
- Passwords: bcrypt, Argon2id, scrypt
- Symmetric: AES-256-GCM, ChaCha20-Poly1305
- Hashing: SHA-256, SHA-3, BLAKE2
- Random: secrets module, crypto.randomBytes

Send findings to team-lead with CWE-327, CWE-328, CWE-330, CWE-326 references.
```

### Input Validator Agent

```
You are a security specialist focused on input validation.

SCOPE: {target_path}

Review for Pattern 6 (Input Validation) from the security anti-patterns guide:

CHECK FOR:
1. Client-side only validation
2. Missing type checking (especially for NoSQL)
3. No length limits (DoS via large inputs)
4. ReDoS patterns: (a+)+, (a*)*
5. Trusting external data without verification
6. Missing canonicalization before validation
7. Path traversal (../ in file paths)
8. Missing URL scheme validation
9. Accepting untrusted serialized data (pickle, eval)
10. XML without entity restrictions (XXE)

VALIDATION ORDER:
1. Decode all encoding layers
2. Canonicalize (normalize unicode, resolve paths)
3. Validate against allowlist
4. Encode for output context

Send findings to team-lead with CWE-20, CWE-22, CWE-1333 references.
```

### Dependency Checker Agent

```
You are a security specialist focused on supply chain and dependency security.

SCOPE: {target_path}

Review for Pattern 7 (Dependencies) from the security anti-patterns guide:

CHECK FOR:
1. Hallucinated/non-existent packages
2. Typosquatting package names
3. Outdated dependencies with known CVEs
4. Unpinned dependency versions
5. Dependencies from untrusted sources
6. Excessive dependency permissions
7. Dev dependencies in production
8. Deprecated packages
9. Low-maintenance packages (last update > 2 years)
10. Suspicious post-install scripts

VERIFY PACKAGES EXIST:
- npm: https://registry.npmjs.org/{package}
- PyPI: https://pypi.org/pypi/{package}/json
- Check download counts and maintenance status

Send findings to team-lead with CWE-1357 (Slopsquatting) references.
```

## Report Format

```markdown
## Security Review Results

**Scope:** {files/directories reviewed}
**Mode:** {quick|deep|full}
**Agents:** {list of specialists if full mode}
**Duration:** {time taken}

### Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | X | Secrets, Injection |
| High | X | Auth, XSS |
| Medium | X | Config, Input |

### Critical Issues
{Must fix before deployment}

### High Priority
{Fix soon}

### Medium Priority
{Address when convenient}

### Findings by Category

#### 1. Secrets & Credentials
[Findings from secrets-scanner]

#### 2. Injection Vulnerabilities
[Findings from injection-hunter]

... {continue for each category}

### Good Practices Found
{Positive patterns already in place}

---

### Detailed Findings

#### {Issue Title}
- **File:** `path/to/file.ts:123`
- **CWE:** CWE-XXX (Name)
- **Severity:** Critical/High/Medium
- **Agent:** {specialist name}
- **Pattern:** Brief description
- **Code:**
  ```
  {vulnerable code snippet}
  ```
- **Fix:**
  ```
  {remediated code}
  ```
- **Reference:** ANTI_PATTERNS_{BREADTH|DEPTH}.md §{section}
```

## Auto-Escalation Rules

Automatically use DEPTH patterns (even without `--deep`) when reviewing:

- `**/auth/**`, `**/login/**`, `**/session/**`
- `**/payment/**`, `**/stripe/**`, `**/billing/**`
- `**/crypto/**`, `**/encrypt/**`, `**/token/**`
- Files containing: `password`, `secret`, `jwt`, `bcrypt`, `oauth`

Automatically use FULL swarm (even without `--full`) when:

- Reviewing > 50 files
- Pre-production/release audit requested
- Scope includes authentication + payments + API
- User mentions "comprehensive" or "complete" audit

## Team Lifecycle

```pseudocode
// Full swarm cleanup sequence
FOR specialist IN active_specialists:
    Teammate({ operation: "requestShutdown", target_agent_id: specialist.name })
    // Wait for shutdown_approved message

// Verify all shutdown before cleanup
Teammate({ operation: "cleanup" })
```

## References

- `references/ANTI_PATTERNS_BREADTH.md` - 25+ patterns, ~65K tokens
- `references/ANTI_PATTERNS_DEPTH.md` - 7 critical patterns with edge cases, ~100K tokens
