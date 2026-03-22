# Security Review: 01-user-search-api.py

**Reviewed file:** `/private/tmp/sec-context-mockups/01-user-search-api.py`
**Skill used:** sec-context
**Date:** 2026-03-21

---

## Reference Files Loaded

| File | Why |
|------|-----|
| `injection-breadth.md` | SQL queries built with f-strings — matches trigger keywords `SQL`, `query` |
| `input-validation-breadth.md` | No validation on any user input (`q`, `sort`, `limit`, `user_id`) |
| `api-security-breadth.md` | No authentication, no authorization, no rate limiting, excessive data exposure (SSN, salary) |
| `config-deployment-breadth.md` | `debug=True` and `host="0.0.0.0"` in the startup block |

**Depth files loaded:** None. All vulnerabilities matched straightforward breadth patterns.

---

## Findings (7 vulnerabilities, ordered by severity)

---

### 1. SQL Injection via f-string concatenation — CRITICAL

**CWE-89** | Lines 23, 47

Both endpoints build SQL by interpolating user input directly into query strings:

```python
# Line 23 - search_users: THREE injection points
sql = f"SELECT ... WHERE name LIKE '%{query}%' ORDER BY {sort_by} LIMIT {limit}"

# Line 47 - get_user: ONE injection point
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

This matches the BAD pattern from `injection-breadth.md` Section 2.1 (string concatenation in SQL queries). An attacker can extract the entire database, drop tables, or bypass any logic.

**Fix:** Parameterize values, allowlist identifiers:

```python
ALLOWED_SORT_COLUMNS = {"name", "email", "id"}

@app.route("/api/users/search", methods=["GET"])
def search_users():
    query = request.args.get("q", "")
    sort_by = request.args.get("sort", "name")
    limit = request.args.get("limit", "50")

    # Allowlist sort column (cannot be parameterized)
    if sort_by not in ALLOWED_SORT_COLUMNS:
        sort_by = "name"

    # Validate limit as integer, clamp range
    try:
        limit = min(max(int(limit), 1), 100)
    except ValueError:
        limit = 50

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT id, name, email FROM users WHERE name LIKE ? ORDER BY {sort_by} LIMIT ?",
        (f"%{query}%", limit),
    )
    # ...
```

And for `get_user`:

```python
cursor.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
```

---

### 2. Missing Authentication — CRITICAL

**CWE-287** | Lines 12, 42

Neither endpoint has any authentication. Any anonymous HTTP client can search all users and retrieve individual profiles including SSNs and salaries. This matches `api-security-breadth.md` Section 9.1 (unprotected API endpoints).

**Fix:** Add authentication middleware (e.g., `@login_required` or token verification) before every route that returns user data. For the search endpoint, consider requiring admin-level authorization given the sensitivity of the data returned.

---

### 3. Excessive Data Exposure — HIGH

**CWE-200** | Lines 23, 28-36, 52

Both endpoints return `ssn`, `salary`, `phone`, and `address` to any caller. This matches the BAD pattern from `api-security-breadth.md` Section 9.4 ("Returns entire user object including sensitive fields").

**Fix:** Use an explicit field allowlist (DTO pattern):

```python
SAFE_FIELDS = ("id", "name", "email")

# SELECT only what you need — never SELECT *
cursor.execute("SELECT id, name, email FROM users WHERE ...")
```

If SSN/salary are needed for admin views, gate them behind authorization with a separate endpoint.

---

### 4. Debug Mode on 0.0.0.0 — HIGH

**CWE-215** | Line 57

```python
app.run(debug=True, host="0.0.0.0", port=5000)
```

`debug=True` enables the Werkzeug interactive debugger, which allows **remote code execution** from any machine that can reach port 5000. Binding to `0.0.0.0` exposes it to the entire network. This matches `config-deployment-breadth.md` Section 7.1.

**Fix:**

```python
if __name__ == "__main__":
    debug = os.environ.get("FLASK_ENV") == "development"
    host = "127.0.0.1" if debug else "0.0.0.0"
    app.run(debug=debug, host=host, port=5000)
```

In production, use a proper WSGI server (gunicorn, uWSGI) instead of `app.run()`.

---

### 5. Missing Input Validation — HIGH

**CWE-20** | Lines 15-17

- `q` — no length limit (DoS via huge search string, per `input-validation-breadth.md` Section 6.3)
- `sort` — no allowlist (injection vector, covered above)
- `limit` — no type check or range bound; could be `"99999999"` or a non-numeric string
- `user_id` — no format validation; fed directly into SQL

**Fix:** Validate every parameter server-side:

```python
query = request.args.get("q", "")
if len(query) > 200:
    return jsonify({"error": "Query too long"}), 400

try:
    limit = min(max(int(request.args.get("limit", "50")), 1), 100)
except ValueError:
    return jsonify({"error": "Invalid limit"}), 400
```

---

### 6. Missing Rate Limiting — HIGH

**CWE-770** | Lines 12, 42

No rate limiting on either endpoint. An attacker can enumerate the entire user database or brute-force user IDs. Matches `api-security-breadth.md` Section 9.5.

**Fix:** Add per-IP rate limiting (e.g., Flask-Limiter):

```python
from flask_limiter import Limiter
limiter = Limiter(app, default_limits=["100 per minute"])
```

---

### 7. No Error Handling / Verbose Errors — MEDIUM

**CWE-209** | Global

No try/except blocks around database operations. With `debug=True`, unhandled exceptions expose full stack traces, SQL queries, file paths, and the interactive debugger to the client. Matches `config-deployment-breadth.md` Section 7.2.

**Fix:** Wrap DB operations in try/except and return generic error messages to clients. Log details server-side.

---

## Summary Table

| # | Vulnerability | CWE | Severity | Line(s) |
|---|--------------|-----|----------|---------|
| 1 | SQL Injection (f-string queries) | CWE-89 | Critical | 23, 47 |
| 2 | Missing Authentication | CWE-287 | Critical | 12, 42 |
| 3 | Excessive Data Exposure (SSN, salary) | CWE-200 | High | 23, 28-36, 52 |
| 4 | Debug Mode + 0.0.0.0 binding | CWE-215 | High | 57 |
| 5 | Missing Input Validation | CWE-20 | High | 15-17 |
| 6 | Missing Rate Limiting | CWE-770 | High | 12, 42 |
| 7 | Verbose Error Messages | CWE-209 | Medium | Global |

The most urgent fixes are #1 (SQL injection) and #2 (missing auth) — together they mean any anonymous user on the network can extract the entire database with a single crafted request.

---
---

# Skill Evaluation: sec-context

## Was the skill useful?

**Yes.** The skill provided a structured, repeatable workflow for security review that measurably improved the quality and consistency of the output compared to relying on general knowledge alone.

## Specific benefits observed

### 1. Structured surface identification via routing table

The routing table with trigger keywords eliminated guesswork about which security domains to evaluate. Instead of mentally enumerating "what could go wrong," the checklist-driven approach ensured systematic coverage. For this file, scanning the code against the trigger keywords immediately surfaced 4 relevant surfaces out of 10.

### 2. Concrete BAD/GOOD pattern pairs as comparison templates

The breadth reference files provided exact anti-patterns to compare against the code:
- `injection-breadth.md` Section 2.1 shows `"SELECT * FROM users WHERE username = '" + username + "'"` — the same concatenation pattern as line 23's f-string.
- `api-security-breadth.md` Section 9.1 shows unprotected endpoints returning `SELECT *` — matching both endpoints.
- `api-security-breadth.md` Section 9.4 shows returning password_hash, SSN — directly matching the response on lines 28-36.
- `config-deployment-breadth.md` Section 7.1 shows `app.config.debug = TRUE` — matching line 57.
- `input-validation-breadth.md` Section 6.3 shows missing length limits — matching the unvalidated `q` parameter.

Without these, the review would still catch the obvious SQL injection, but might underweight the data exposure or debug mode issues.

### 3. CWE attribution without external lookup

Each reference maps patterns to CWEs, making the output immediately traceable to standard vulnerability databases. This saved time and ensured accuracy in classification.

### 4. Severity-based prioritization

The quick reference table assigns severity levels per pattern, which provided a consistent ordering for findings (Critical before High before Medium) rather than presenting them in arbitrary order.

### 5. Progressive disclosure kept context manageable

The breadth-first, depth-on-demand design meant loading 4 breadth files was sufficient. None of the depth files were needed because every vulnerability in the code matched a straightforward breadth pattern. This kept total reference context well under the point where it would degrade reasoning quality.

## How reference selection was decided

### Step 1: Code scan for security surfaces

Read the file and identified what it does:
- Builds SQL queries with user input (Injection)
- Exposes API endpoints with no auth (API Security)
- Accepts unvalidated parameters (Input Validation)
- Runs with `debug=True` on `0.0.0.0` (Configuration)

### Step 2: Match against routing table trigger keywords

| Surface | Trigger keywords matched | Loaded? |
|---|---|---|
| Secrets & Credentials | None found in code | No |
| Injection | `SQL`, `query`, f-string concatenation | **Yes — breadth** |
| Cross-Site Scripting | No HTML rendering | No |
| Authentication & Sessions | No auth code present (that's the problem, but covered by API Security) | No |
| Cryptography | No crypto operations | No |
| Input Validation | No `validate`, no type checks, no length limits | **Yes — breadth** |
| Configuration & Deployment | `debug=True`, `host="0.0.0.0"` | **Yes — breadth** |
| Dependencies & Supply Chain | Standard Flask/sqlite3 | No |
| API Security | Unprotected endpoints, `SELECT *`, sensitive fields in response | **Yes — breadth** |
| File Handling | No file operations | No |

### Step 3: Breadth vs depth decision

All issues were clearly identifiable from breadth patterns alone:
- SQL injection via string concatenation is the textbook example in Section 2.1
- Missing auth on endpoints is Section 9.1's exact BAD example
- `SELECT *` returning sensitive fields is Section 9.4
- `debug=True` is Section 7.1
- Missing length limits is Section 6.3

No edge cases or ambiguous patterns required depth analysis.

## Potential improvements to the skill

1. **Python/Flask-specific examples** — The pseudocode patterns are language-agnostic, which is good for breadth but means the reviewer must mentally translate. Having one concrete example per popular framework (Flask, Django, Express, Spring) in the depth files would speed up the "match and fix" step.

2. **Composite vulnerability scoring** — The file has 7 findings. A composite risk score or "exploitability chain" section (e.g., "SQL injection + no auth + debug mode = trivial full compromise") would help communicate aggregate risk to non-security stakeholders.

3. **The "load at most 2-3 surfaces" guideline was slightly restrictive for this file** — 4 surfaces were clearly relevant. The guideline should say "2-3 typically, more if clearly warranted" to avoid artificially limiting coverage.

4. **Cross-reference notes between overlapping surfaces** — Rate limiting appears in both API Security and Input Validation. A note saying "for rate limiting, see API Security Section 9.5 as the canonical reference" would reduce ambiguity.

## Conclusion

The skill converted what would be an ad-hoc review into a systematic, traceable process. The routing table ensured no relevant surface was missed, the BAD/GOOD patterns provided precise evidence for each finding, and the progressive disclosure design kept context efficient. The output is more consistent, better attributed, and more actionable than a review done without the skill.
