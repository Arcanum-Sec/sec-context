# Security Review Skill

Performs security code review using the sec-context anti-patterns guide.

## Usage

```
/security-review                      # Quick review of recent changes (BREADTH)
/security-review path/to/file.ts      # Review specific file (BREADTH)
/security-review --deep               # Deep audit of recent changes (DEPTH)
/security-review --deep src/auth/     # Deep audit of specific directory (DEPTH)
```

## Which Document to Use

| Document | Tokens | Patterns | Use When |
|----------|--------|----------|----------|
| **BREADTH** (default) | ~65K | 25+ | General reviews, PRs, quick scans |
| **DEPTH** (`--deep`) | ~100K | 7 critical | Auth, crypto, payments, pre-launch audits |

**BREADTH** covers: secrets, injection, XSS, auth, crypto, input validation, config, dependencies, API security, file handling

**DEPTH** deep-dives: secrets, injection, XSS, auth, crypto, input validation — with edge cases, attack scenarios, detection hints, and checklists

**Rule of thumb**: Use BREADTH for everyday reviews. Use DEPTH when touching authentication, payments, cryptography, or before deploying to production.

## Instructions

When this skill is invoked:

### 1. Load Security Context

Read the appropriate anti-patterns document based on the flag:
- **Default (no flag)**: `.claude/security/ANTI_PATTERNS_BREADTH.md`
- **Deep mode (`--deep`)**: `.claude/security/ANTI_PATTERNS_DEPTH.md`

### 2. Determine Scope

- If a file path is provided, review that specific file
- If no path is provided, get recent changes with `git diff HEAD~1` or staged changes with `git diff --cached`
- For large changesets, prioritize files that handle: user input, authentication, database queries, file operations, API endpoints

### 2.1 Auto-select DEPTH for Critical Paths

Even without `--deep`, automatically use DEPTH document if reviewing:
- `**/auth/**`, `**/login/**`, `**/session/**` → Auth patterns
- `**/stripe/**`, `**/payment/**`, `**/webhook/**` → Payment security
- `**/crypto/**`, `**/hash/**`, `**/token/**` → Cryptographic patterns
- Files containing: `password`, `secret`, `apiKey`, `jwt`, `bcrypt`

### 3. Analyze Code

For each file/change, check against the anti-patterns. Prioritize based on the code being reviewed:

**High Priority (always check):**
- §1: Secrets and Credentials (API keys, tokens, passwords)
- §2: Injection (SQL, NoSQL, command injection)
- §3: XSS (user input rendered in HTML)
- §4: Authentication (session handling, auth checks)

**Medium Priority:**
- §5: Cryptographic Failures (token generation, password hashing)
- §6: Input Validation (form inputs, API parameters)
- §8: Dependency Security (npm/pip packages, supply chain)
- §9: API Security (authorization, data exposure)
- §10: File Handling (uploads, path traversal)

### 4. Report Findings

Format findings as:

```markdown
## Security Review Results

### Critical Issues
[Issues that must be fixed before deployment]

### High Priority
[Issues that should be fixed soon]

### Medium Priority
[Issues to address when convenient]

### Good Practices Found
[Positive security patterns already in place]

---

### Detailed Findings

#### [Issue Title]
- **File**: `path/to/file.ts:123`
- **CWE**: CWE-XXX (Name)
- **Severity**: Critical/High/Medium
- **Pattern**: Brief description of the vulnerable pattern
- **Fix**: Specific remediation steps with code example
```

### 5. Provide Actionable Fixes

For each issue, provide:
1. The specific line(s) of code affected
2. A concrete code fix (not just advice)
3. Reference to the relevant section in the anti-patterns doc
