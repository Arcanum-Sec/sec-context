# Security Review: 02-auth-service.js

## References Loaded and Why

| Reference File | Why Loaded |
|---|---|
| `authentication-breadth.md` | File handles login, JWT, password reset -- core auth surface |
| `secrets-breadth.md` | Lines 13-15 contain hardcoded credentials (DB_PASSWORD, JWT_SECRET, ADMIN_API_KEY) |
| `cryptography-breadth.md` | Lines 29-32 and 49 use MD5 hashing; line 91 uses `Math.random()` |

**Depth files were not loaded.** The breadth references were sufficient to identify and classify all findings. The BAD/GOOD patterns directly matched every vulnerability. Depth files would have been loaded if edge cases or ambiguous patterns required further analysis.

---

## Findings (10 vulnerabilities)

---

### 1. CRITICAL -- Hardcoded Secrets (CWE-798)

**Lines 13-15:**
```js
const DB_PASSWORD = "pr0duction_p@ss!";
const JWT_SECRET = "my-super-secret-jwt-key-2024";
const ADMIN_API_KEY = "sk-admin-9f8e7d6c5b4a3210";
```

Three secrets hardcoded in source. If this file is committed to version control, these are permanently exposed in git history. The JWT secret is short and guessable, matching the "weak JWT secret" anti-pattern from `secrets-breadth.md` section 1.1.

**Fix:** Load from environment variables; validate presence at startup:
```js
const DB_PASSWORD = process.env.DB_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
if (!DB_PASSWORD || !JWT_SECRET || !ADMIN_API_KEY) {
  throw new Error("Required secrets not configured");
}
if (JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be at least 256 bits");
}
```

---

### 2. CRITICAL -- JWT "none" Algorithm Accepted (CWE-287)

**Line 74:**
```js
jwt.verify(token, JWT_SECRET, { algorithms: ["none", "HS256", "HS384", "HS512"] });
```

Allowing `"none"` means an attacker can forge a token with `alg: "none"`, remove the signature, set `role: "admin"`, and bypass authentication entirely. This is the exact exploit described in `authentication-breadth.md` section 4.5.

**Fix:** Only allow the specific algorithm you sign with:
```js
jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
```

---

### 3. CRITICAL -- Weak Password Hashing: MD5 (CWE-327, CWE-916)

**Lines 29-32 and 49:**
```js
crypto.createHash("md5").update(password).digest("hex");
```

MD5 is cryptographically broken. No salt is used. Rainbow tables for MD5 are widely available, and GPUs can compute billions of hashes per second. Matches `cryptography-breadth.md` section 5.1 (deprecated algorithms) exactly.

**Fix:** Use bcrypt or argon2:
```js
const bcrypt = require("bcrypt");
const hashedPassword = await bcrypt.hash(password, 12);
// Verification:
const match = await bcrypt.compare(password, user.password);
```

---

### 4. CRITICAL -- Math.random() Reset Token (CWE-330)

**Line 91:**
```js
const resetToken = Math.random().toString(36).substring(2, 10);
```

`Math.random()` is not cryptographically secure -- the internal state can be predicted from observed outputs. This produces only ~8 alphanumeric characters (~41 bits of weak entropy). Matches `cryptography-breadth.md` section 5.6.

**Fix:**
```js
const resetToken = crypto.randomBytes(32).toString("hex");
```

---

### 5. HIGH -- Weak Password Policy (CWE-521)

**Line 24:**
```js
if (password.length < 4)
```

Minimum length of 4 allows trivially weak passwords like `"1234"`. No complexity, no common-password check, no breach check. Matches `authentication-breadth.md` section 4.1 BAD example verbatim.

**Fix:** Enforce 12+ characters minimum, check against common password lists, and optionally check HaveIBeenPwned via k-anonymity API (see `authentication-breadth.md` section 4.1 GOOD example).

---

### 6. HIGH -- Excessive Token Lifetime (CWE-613)

**Line 62:**
```js
{ expiresIn: "365d" }
```

A 1-year JWT expiration means a stolen token is exploitable for up to a year with no revocation mechanism. Access tokens should be 15-60 minutes; use refresh tokens for longer sessions.

**Fix:**
```js
{ expiresIn: "15m" }  // Short-lived access token + refresh token pattern
```

---

### 7. HIGH -- No Rate Limiting on Auth Endpoints (CWE-307)

None of `/auth/login`, `/auth/register`, or `/auth/reset-password` have rate limiting. This enables brute-force, credential stuffing, and password reset flooding. Matches `authentication-breadth.md` section 4.2.

**Fix:** Add rate limiting middleware (e.g., `express-rate-limit`):
```js
const rateLimit = require("express-rate-limit");
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
app.post("/auth/login", authLimiter, (req, res) => { ... });
```

---

### 8. HIGH -- Reset Token Returned in Response Body (CWE-200)

**Line 97:**
```js
res.json({ message: "Reset email sent", token: resetToken });
```

The password reset token is returned directly in the HTTP response. In production this should only be sent via email. Returning it in the API response defeats the purpose of the reset flow.

**Fix:** Only send the token via email; return a generic confirmation message.

---

### 9. MEDIUM -- User Enumeration + Hash Leakage (CWE-209)

**Lines 44-46, 52-55, 87:**
```js
// Login: reveals whether user exists
{ error: `User '${username}' not found in database` }
// Login: leaks password hashes in debug field
{ debug: { expected: user.password, received: hashedInput } }
// Reset: reveals whether email is registered
{ error: `No account found for ${email}` }
```

Three separate enumeration vectors. The `debug` field on lines 53-54 is especially severe -- it returns the stored password hash to the client, enabling offline cracking. While user enumeration is typically Medium, the hash leakage elevates this to effectively Critical urgency.

**Fix:** Use a single generic message for all auth failures:
```js
res.status(401).json({ error: "Invalid credentials" });
```
Remove the `debug` field entirely. For password reset, always return the same response regardless of whether the email exists.

---

### 10. MEDIUM -- No Input Validation on Registration (CWE-20)

**Lines 21-34:**

`username` and `email` are accepted without any validation. No type checking, no length limits, no format validation. This could lead to unbounded string storage, injection into logs or downstream systems, and invalid email addresses.

**Fix:** Validate types, enforce length limits, and verify email format before processing.

---

## Findings Summary

| # | Severity | Issue | CWE | Line(s) |
|---|----------|-------|-----|---------|
| 1 | Critical | Hardcoded secrets | 798 | 13-15 |
| 2 | Critical | JWT "none" algorithm | 287 | 74 |
| 3 | Critical | MD5 password hashing | 327 | 29-32, 49 |
| 4 | Critical | Math.random() reset token | 330 | 91 |
| 5 | High | Min password length of 4 | 521 | 24 |
| 6 | High | 365-day JWT expiry | 613 | 62 |
| 7 | High | No rate limiting | 307 | 20, 39, 83 |
| 8 | High | Reset token in response | 200 | 97 |
| 9 | Medium | User enumeration + hash leakage | 209 | 44-55, 87 |
| 10 | Medium | No input validation | 20 | 21-34 |

**Totals: 4 Critical, 4 High, 2 Medium** -- this service needs significant hardening before any deployment.

---
---

# Sec-Context Skill Evaluation

## Overall Verdict: Highly Useful

The sec-context skill materially improved the quality, structure, and completeness of this review compared to what an unassisted LLM review would produce.

---

## How Reference Files Were Selected (Decision Process)

The selection followed the skill's prescribed routing workflow:

### Step 1: Identify surfaces via trigger keywords

I scanned `02-auth-service.js` and matched keywords from the routing table:

| Code Element | Matched Keywords | Surface |
|---|---|---|
| `JWT_SECRET`, `DB_PASSWORD`, `ADMIN_API_KEY` (lines 13-15) | API key, password, token, credential | **Secrets & Credentials** |
| `/auth/login`, `/auth/register`, JWT sign/verify, session handling | login, session, JWT, password, token | **Authentication & Sessions** |
| `crypto.createHash("md5")`, `Math.random()` | hash, MD5, random | **Cryptography** |

This gave exactly 3 surfaces, within the skill's recommended "max 2-3 surfaces per task" limit.

### Step 2: Load breadth files only

I loaded:
- `authentication-breadth.md` -- covers weak passwords, rate limiting, session tokens, JWT misuse, password reset
- `secrets-breadth.md` -- covers hardcoded credentials, config secrets, client-side secrets
- `cryptography-breadth.md` -- covers MD5/SHA1, hardcoded keys, weak randomness, key derivation

### Step 3: Depth files -- deliberately not loaded

The breadth references were sufficient. Every vulnerability in the file directly matched a BAD example in one of the three breadth files. Depth would have been warranted if:
- A pattern was partially correct and needed nuanced edge-case analysis
- The user asked for deeper investigation
- A finding was ambiguous

None of those conditions applied here -- the anti-patterns are textbook.

### Step 4: Input validation surface -- deliberately skipped

The file also has an input validation problem (finding #10). The skill's routing table lists an "Input Validation" surface, but loading a 4th surface would have exceeded the 2-3 surface guideline for diminishing returns. The input validation finding was identified from the skill's checklist section ("All user input validated on the SERVER side") without needing the full reference file.

---

## What Worked Well

### 1. Progressive Disclosure / Routing Table
The routing table was the single most valuable piece. It prevented both over-loading (reading all 10 reference files) and under-coverage (missing a surface). The keyword-to-surface mapping was accurate -- every keyword I matched led to a relevant reference.

### 2. BAD/GOOD Pattern Pairs
The pseudocode examples acted as a direct pattern-matching checklist. Several findings were identified because the code literally matched a BAD example:
- Finding #5 (weak password policy): `if (password.length < 4)` is nearly identical to `authentication-breadth.md` section 4.1 BAD example.
- Finding #2 (JWT "none" algorithm): `algorithms: ["none", ...]` matches section 4.5 word-for-word.
- Finding #3 (MD5 hashing): Directly flagged by `cryptography-breadth.md` section 5.1.
- Finding #4 (Math.random): Directly flagged by `cryptography-breadth.md` section 5.6.

This reduced the risk of false negatives.

### 3. CWE Mapping
Each pattern carries CWE IDs. This saved lookup time and ensured the report uses standardized identifiers. Every finding has a CWE because the skill made assignment trivial.

### 4. Structured Workflow
The "Required Workflow" (Identify surfaces -> Load breadth -> Check patterns -> Apply fixes -> Go deeper -> Output findings) gave a repeatable methodology, valuable for consistency across multiple file reviews.

### 5. Context Efficiency
Only 3 breadth files were loaded (~1,600 lines total). This is far less than loading all 10 surface files (~5,000+ lines) and still achieved complete coverage of this file's vulnerabilities.

---

## What Could Be Improved

### 1. Language-Specific Fix Guidance
References use language-agnostic pseudocode, which is good for breadth but requires mental translation. For Node.js specifically: knowing to use `require("bcrypt")`, `express-rate-limit`, `crypto.randomBytes()`, etc., requires existing knowledge. Optional language-specific notes at the end of each pattern would reduce friction.

### 2. Input Validation Gap in Auth Surface
Since auth services almost always need input validation, a brief note in the authentication references about validating request body shapes would catch finding #10 without needing to load a 4th surface.

### 3. Severity Scoring Rubric
The skill says "Prioritize by severity" but doesn't provide a scoring matrix. A simple rubric (e.g., "exploitable remotely without auth = Critical") would improve consistency across reviewers.

### 4. Hash Leakage Severity
Finding #9 is classified as Medium (user enumeration / CWE-209), but the `debug` field returning actual password hashes is effectively Critical. The skill's patterns cover verbose error messages but don't specifically call out "returning stored credentials in API responses" as a distinct Critical pattern. This edge case could be explicitly mentioned.

---

## Quantitative Assessment

| Metric | Score (1-5) | Notes |
|---|---|---|
| **Surface routing accuracy** | 5 | Trigger keywords matched perfectly; no irrelevant surfaces loaded |
| **Pattern coverage** | 4 | Caught all major issues; input validation gap noted above |
| **Fix quality** | 4 | GOOD examples are solid templates; need language adaptation |
| **Context efficiency** | 5 | 3 breadth files was optimal for this file |
| **Workflow clarity** | 5 | Step-by-step process was easy to follow |
| **CWE accuracy** | 5 | All CWE mappings were correct and specific |
| **Overall usefulness** | 4.5 | Significant improvement over unassisted review |

---

## Conclusion

The sec-context skill turned what would be a general "look for common issues" review into a **systematic, evidence-based audit** with proper CWE classification. The progressive disclosure model (routing table -> breadth -> optional depth) is well-designed and kept context usage proportional to the complexity of the code. For this authentication service, 3 breadth files were sufficient to identify all 10 vulnerabilities with zero false positives. The main areas for improvement are language-specific fix guidance, a severity scoring rubric, and capturing the "hash leakage in response" edge case as a distinct Critical pattern.
