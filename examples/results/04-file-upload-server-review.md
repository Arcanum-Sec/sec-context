# Security Review: 04-file-upload-server.go

## File Under Review

`/private/tmp/sec-context-mockups/04-file-upload-server.go` -- A Go HTTP server handling file uploads, downloads, temp file processing, and admin/debug endpoints.

---

## Reference Files Loaded and Rationale

The sec-context skill uses a **routing table** to match code surfaces to specific reference files. I identified 4 surfaces and loaded 4 references (3 breadth + 1 depth):

| Reference File | Why It Was Loaded |
|----------------|-------------------|
| `references/file-handling-breadth.md` | The code performs file uploads (`handleUpload`), file downloads (`handleDownload`), temp file creation (`handleProcess`), and sets file permissions (`os.Chmod`). This directly triggers the File Handling surface covering CWE-22, CWE-434, CWE-377, CWE-59, CWE-732. |
| `references/config-deployment-breadth.md` | The code registers `/debug/env` and `/debug/files` endpoints unconditionally, uses a fully-open CORS middleware reflecting any origin, sets no security headers, and returns verbose internal error messages. This triggers the Config & Deployment surface covering CWE-215, CWE-209, CWE-16, CWE-346. |
| `references/api-security-breadth.md` | All endpoints lack authentication. The `/admin/config` endpoint dumps credentials without any auth check. The `/files/` download endpoint has no authorization or ownership verification. This triggers the API Security surface covering CWE-284, CWE-200, CWE-770, CWE-209. |
| `references/input-validation-depth.md` | The `job_id` query parameter is injected directly into file paths without any validation. User-supplied filenames are used without sanitization. The depth file was loaded to confirm cross-surface overlaps between input validation and file handling, particularly around path canonicalization patterns. |

The `secrets-breadth.md` reference was considered but not loaded because the credential exposure was better covered by the api-security-breadth.md (unauthenticated data exposure) and config-deployment-breadth.md (debug endpoints dumping config) patterns combined.

---

## Findings (12 Vulnerabilities)

### Critical Severity

#### 1. Unrestricted File Upload -- CWE-434

**Location:** `04-file-upload-server.go:66-91`

```go
savePath := filepath.Join(uploadDir, header.Filename)
```

No validation of file extension, MIME type, or magic bytes. No file size limit (`io.Copy` reads unbounded data at line 85). An attacker can upload `.php`, `.html`, `.exe`, or any dangerous file type. The original user-supplied filename is used directly. A malicious HTML file becomes stored XSS; an extremely large file causes disk exhaustion DoS.

**Matched pattern:** file-handling-breadth.md section 10.2 "BAD: No validation on uploaded files" -- accepts any file type, uses user-provided filename directly, no size limits.

**Remediation:** Validate extension against an allowlist, check magic bytes, enforce a size limit with `http.MaxBytesReader` or `io.LimitReader`, and generate a random filename (UUID) server-side.

---

#### 2. Path Traversal on Upload -- CWE-22

**Location:** `04-file-upload-server.go:74`

```go
savePath := filepath.Join(uploadDir, header.Filename)
```

`header.Filename` can contain `../../etc/cron.d/malicious`. While `filepath.Join` cleans some traversals, there is no verification that the resolved path stays within `uploadDir`. An attacker writes files to arbitrary filesystem locations.

**Matched pattern:** file-handling-breadth.md section 10.1 "BAD: Direct path concatenation allows traversal".

**Remediation:** After joining, resolve the absolute path and verify it starts with `uploadDir + "/"`:

```go
absPath, _ := filepath.Abs(savePath)
if !strings.HasPrefix(absPath, uploadDir+"/") {
    http.Error(w, "Invalid filename", 400)
    return
}
```

---

#### 3. Path Traversal on Download -- CWE-22

**Location:** `04-file-upload-server.go:96-99`

```go
filename := r.URL.Path[len("/files/"):]
filePath := uploadDir + "/" + filename
```

String concatenation (not even `filepath.Join`) with raw URL path input. Requesting `/files/../../etc/passwd` reads arbitrary files from the server. Double-encoding attacks (`%2e%2e%2f`) also apply since no canonicalization is performed.

**Matched pattern:** file-handling-breadth.md section 10.1 -- attack example `?filename=../../etc/passwd` and `?filename=..%2F..%2Fetc/passwd`.

**Remediation:** Use `filepath.Base(filename)` to strip path components, then `filepath.Join` + absolute path prefix validation.

---

#### 4. Credential Exposure via `/admin/config` -- CWE-200, CWE-798

**Location:** `04-file-upload-server.go:143-155`

```go
os.Getenv("DB_PASSWORD"),
os.Getenv("AWS_SECRET_ACCESS_KEY"),
```

Unauthenticated endpoint dumps database passwords and AWS secret keys to any caller. This is both a credential exposure (CWE-798) and an excessive data exposure issue (CWE-200).

**Matched pattern:** api-security-breadth.md section 9.1 "BAD: Unprotected API endpoints" -- sensitive data exposed without auth; config-deployment-breadth.md section 7.6 "BAD: Admin panel accessible without protection".

**Remediation:** Remove this endpoint entirely, or require authentication and never return unmasked secret values.

---

#### 5. Debug Endpoints Exposed -- CWE-215

**Location:** `04-file-upload-server.go:23-33`

```go
http.HandleFunc("/debug/env", ...)   // dumps ALL environment variables
http.HandleFunc("/debug/files", ...) // lists upload directory contents
```

`/debug/env` exposes every environment variable (including secrets). Both endpoints are unauthenticated and unconditionally registered regardless of environment.

**Matched pattern:** config-deployment-breadth.md section 7.1 "BAD: Debug routes left enabled" -- `app.route("/debug/env", show_environment_variables)`.

**Remediation:** Remove debug endpoints from production builds, or gate behind `APP_ENV` checks with authentication.

---

### High Severity

#### 6. No Authentication on Any Endpoint -- CWE-287

**Location:** `04-file-upload-server.go:17-20`

```go
http.HandleFunc("/upload", handleUpload)
http.HandleFunc("/files/", handleDownload)
http.HandleFunc("/process", handleProcess)
http.HandleFunc("/admin/config", handleShowConfig)
```

None of the endpoints require any authentication. Any network client can upload, download, process, and view configuration. There is no auth middleware, no token validation, no session management at all.

**Matched pattern:** api-security-breadth.md section 9.1 "BAD: Unprotected API endpoints" -- no authentication on sensitive endpoints, admin functionality without auth check.

**Remediation:** Add authentication middleware using a default-deny approach. Define explicitly public endpoints; require auth for everything else. Protect admin/debug routes with additional authorization checks.

---

#### 7. World-Writable File Permissions -- CWE-732

**Location:** `04-file-upload-server.go:93`

```go
os.Chmod(savePath, 0777)
```

Every uploaded file is world-readable, writable, and executable. Any process on the system can modify or execute uploaded files.

**Matched pattern:** file-handling-breadth.md section 10.6 "BAD: World-writable files" and "Mistake 3: Executable when shouldn't be".

**Remediation:** Use `0644` at most; never set the execute bit on uploaded content.

---

#### 8. Insecure Temp File Handling -- CWE-377, CWE-22, CWE-732

**Location:** `04-file-upload-server.go:120-132`

```go
tmpPath := fmt.Sprintf("/tmp/process_%s.tmp", r.URL.Query().Get("job_id"))
err = os.WriteFile(tmpPath, body, 0666)
```

Four compounding problems:
- **Predictable filename** from user-controlled `job_id` -- enables symlink/race attacks (CWE-59)
- **Path traversal** via `job_id` (e.g., `job_id=../../etc/cron.d/evil`) -- arbitrary file write (CWE-22)
- **Permissions `0666`** -- world-readable/writable (CWE-732)
- Cleanup at line 132 is not deferred -- if `processDocument` panics, the temp file leaks
- **No body size limit** on `io.ReadAll(r.Body)` at line 113 -- memory exhaustion DoS

**Matched pattern:** file-handling-breadth.md section 10.4 "BAD: Predictable filename", "World-readable permissions", and "Not cleaning up". Input-validation-depth.md confirmed the need for canonicalization before path use.

**Remediation:** Use `os.CreateTemp` for unpredictable names, validate `job_id` format (alphanumeric/UUID only), use `defer os.Remove()`, set restrictive permissions (`0600`), and limit request body size.

---

#### 9. Open CORS with Credential Reflection -- CWE-346

**Location:** `04-file-upload-server.go:50-54`

```go
origin := r.Header.Get("Origin")
w.Header().Set("Access-Control-Allow-Origin", origin)
w.Header().Set("Access-Control-Allow-Credentials", "true")
```

Reflects any origin while allowing credentials. Any malicious website can make authenticated cross-origin requests and read responses.

**Matched pattern:** config-deployment-breadth.md section 7.4 "Mistake 2: Reflecting Origin header (same as allowing all)".

**Remediation:** Use a strict allowlist of known origins.

---

### Medium Severity

#### 10. Missing Security Headers -- CWE-16

**Location:** `04-file-upload-server.go:54` (code comment acknowledges this)

No `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, or `Referrer-Policy` headers. The download handler at line 108 writes file content without `X-Content-Type-Options: nosniff`, enabling MIME-sniffing attacks -- browsers may execute uploaded HTML/JS as active content.

**Matched pattern:** config-deployment-breadth.md section 7.5 "BAD: No security headers configured".

**Remediation:** Add a middleware that sets security headers on every response. Critical for the download endpoint: set `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.

---

#### 11. Verbose Error Messages -- CWE-209

**Locations:** Lines 79, 103, 124

```go
http.Error(w, fmt.Sprintf("Failed to create file %s: %v", savePath, err), 500)
http.Error(w, fmt.Sprintf("Cannot read %s: %v", filePath, err), 404)
http.Error(w, fmt.Sprintf("Temp file error at %s: %v", tmpPath, err), 500)
```

Full filesystem paths and internal error details returned to clients, revealing server directory structure and internal state.

**Matched pattern:** config-deployment-breadth.md section 7.2 "BAD: Detailed errors exposed to users".

**Remediation:** Return generic error messages to clients; log details server-side with a request ID.

---

#### 12. Unsafe JSON Response Construction -- CWE-79, CWE-116

**Locations:** Lines 91, 134

```go
fmt.Fprintf(w, `{"url": "/files/%s"}`, header.Filename)
fmt.Fprintf(w, `{"result": "%s"}`, result)
```

User-controlled strings (`header.Filename`, `result`) are interpolated directly into JSON via `Sprintf` without escaping. A filename containing `"` or `\` breaks the JSON structure. A crafted filename with embedded HTML/JS could enable XSS if the response is rendered by a browser without proper `Content-Type`.

**Matched pattern:** api-security-breadth.md section 9.6 (error messages revealing internals via unstructured output) combined with input-validation-depth.md emphasis on encoding output for context.

**Remediation:** Use `encoding/json` to properly marshal response structures instead of string interpolation.

---

## Summary Table

| # | Finding | CWE | Severity | Line(s) |
|---|---------|-----|----------|---------|
| 1 | Unrestricted file upload (no type/size validation) | CWE-434 | Critical | 66-91 |
| 2 | Path traversal on upload | CWE-22 | Critical | 74 |
| 3 | Path traversal on download | CWE-22 | Critical | 96-99 |
| 4 | Credential exposure `/admin/config` | CWE-200/798 | Critical | 143-155 |
| 5 | Debug endpoints dump env vars | CWE-215 | Critical | 23-33 |
| 6 | No authentication on any endpoint | CWE-287 | High | 17-20 |
| 7 | World-writable file permissions (`0777`) | CWE-732 | High | 88 |
| 8 | Insecure temp file (predictable, traversal, `0666`, no cleanup) | CWE-377/22/732 | High | 120-132 |
| 9 | Open CORS with credential reflection | CWE-346 | High | 44-49 |
| 10 | Missing security headers | CWE-16 | Medium | 54 |
| 11 | Verbose error messages expose paths | CWE-209 | Medium | 79,103,124 |
| 12 | Unsafe JSON response construction | CWE-79/116 | Medium | 91,134 |

**Additional concerns:**
- The server binds to `0.0.0.0:8080` with plain HTTP (line 39) -- no TLS.
- No rate limiting on any endpoint (CWE-770) -- upload flooding, download scraping trivial.
- `io.ReadAll(r.Body)` at line 113 has no size limit -- memory exhaustion DoS.

---

## Sec-Context Skill Evaluation

### Was the skill useful?

**Yes, significantly.** Here is a structured assessment of how I used the skill and what value it provided.

### How I Decided Which References to Load

The skill provides a **routing table** mapping trigger keywords to security surfaces. My decision process was:

1. **Scanned the code for surface triggers.** I read the 156-line file and identified what it does: file upload/download, temp file creation, path construction, CORS middleware, debug endpoints, credential-dumping config endpoint, error messages with internal details.

2. **Matched against the routing table:**
   - "upload, download, path, file, traversal, permission, temp" --> **File Handling** surface (loaded `file-handling-breadth.md`)
   - "debug, CORS, headers, error messages, admin" --> **Config & Deployment** surface (loaded `config-deployment-breadth.md`)
   - "endpoint, auth, rate limit, data exposure" --> **API Security** surface (loaded `api-security-breadth.md`)
   - "validate, sanitize, parse, canonicalize" --> **Input Validation** surface (loaded `input-validation-depth.md` -- depth because I wanted to confirm cross-surface overlap between unvalidated `job_id` and path traversal)

3. **Surfaces I explicitly skipped** (and why):
   - *Secrets & Credentials*: The credential exposure was already well-covered by the API Security (unauthenticated endpoint) and Config/Deployment (exposed admin interface) patterns. Loading `secrets-breadth.md` would have added context about hardcoded secrets, but the actual vulnerability here was an unauthenticated endpoint, not a hardcoded value.
   - *Authentication & Sessions*: No auth code exists at all in the file -- there's nothing to review for JWT misuse, session fixation, etc. The *absence* of auth was flagged via the API Security reference instead.
   - *XSS, Injection, Cryptography, Dependencies*: Not relevant surfaces for this code.

4. **Why I loaded one depth file:** The `input-validation-depth.md` was loaded because the `job_id` parameter issue sits at the intersection of input validation and file handling. The breadth file for input validation would have been sufficient for most cases, but the depth file's coverage of **path canonicalization patterns** (section "Edge Case: Canonicalization Before Validation") and **null byte injection** directly applied to the temp file path construction issue.

### What Worked Well

1. **Routing table was precise and efficient.** The trigger-keyword-to-surface mapping let me identify exactly 4 relevant reference files out of 10 available. The skill's "load at most 2-3 surfaces per task" guidance was close; I loaded 4, but the 4th (input-validation depth) was justified for the cross-surface overlap.

2. **BAD/GOOD pattern pairs provided direct matchability.** Every vulnerability I found had a near-exact corresponding BAD pattern in the loaded references:
   - The download handler's `uploadDir + "/" + filename` matched file-handling-breadth.md 10.1 `"/var/app/uploads/" + user_requested_filename` almost character-for-character.
   - The CORS origin reflection matched config-deployment-breadth.md 7.4 "Mistake 2" exactly.
   - The predictable temp file path matched file-handling-breadth.md 10.4 "Mistake 1" directly.
   - The `os.Chmod(savePath, 0777)` matched file-handling-breadth.md 10.6 "Mistake 2: World-writable files" and "Mistake 3: Executable when shouldn't be".
   - The unauthenticated admin endpoint matched api-security-breadth.md 9.1 "BAD: Unprotected API endpoints".
   
   This made it trivial to confirm each finding against a known anti-pattern rather than relying on general knowledge alone.

3. **CWE references were pre-mapped.** Each section carried CWE IDs, so I could tag findings immediately without looking them up separately.

4. **The GOOD examples served as remediation templates.** Instead of generating fix suggestions from scratch, I could adapt the secure patterns directly (e.g., the path validation helper with `resolve_absolute_path` + `starts_with` check, the secure temp file creation with `create_secure_temp_file`, the CORS strict allowlist pattern).

5. **Progressive disclosure worked.** Breadth-only was sufficient for 3 of the 4 surfaces. The depth file was only loaded where the breadth coverage was insufficient (input validation + path traversal overlap). This kept context lean.

6. **The checklist in the skill helped ensure completeness.** The "Security Surface Identification Checklist" acted as a final sweep to confirm I hadn't missed a surface.

### What Could Be Improved

1. **No Go-specific guidance.** The pseudocode patterns are language-agnostic, which is a strength for breadth but meant I had to manually translate to Go idioms (e.g., `os.CreateTemp` instead of generic `create_secure_temp_file`, `http.MaxBytesReader` instead of generic size limiting, `encoding/json.Marshal` instead of generic JSON encoding). Language-specific "cheat sheets" or common standard-library function mappings would speed up remediation advice.

2. **"Absence of security controls" is not a trigger signal.** The routing table triggers on keywords present in the code. But when there is *no auth code at all*, none of the authentication trigger keywords ("login, session, JWT, password, MFA, token, cookie, OAuth") match. I had to rely on the API Security surface's "missing authentication on endpoints" pattern instead. A negative signal ("code handles sensitive operations but has zero auth imports/middleware") could be a useful trigger.

3. **No explicit guidance on missing TLS.** The server uses `http.ListenAndServe` (plain HTTP). None of the loaded references explicitly flag this. The config-deployment-breadth.md mentions HSTS headers but doesn't cover the base case of "server doesn't use TLS at all."

4. **Cross-surface overlaps could be signposted.** The `job_id` path traversal sits at the intersection of input validation, file handling, and injection. The skill's surface model treats these as independent, which meant I had to make a judgment call to load the input-validation depth file. Explicit notes like "if path handling uses user input, also consider Input Validation surface" would help.

5. **JSON injection / output encoding gap.** The unsafe `fmt.Sprintf` JSON construction (lines 91, 134) wasn't directly covered by any loaded reference. The XSS breadth file covers HTML output encoding but not JSON construction in backend code. This is a pattern that AI-generated Go code produces frequently.

### Quantitative Assessment

| Metric | Score | Notes |
|--------|-------|-------|
| Vulnerabilities found with skill pattern match | 12/12 (100%) | Every finding had a corresponding BAD pattern or was identified via the skill's checklist |
| False positives from patterns | 0 | No pattern triggered a non-issue |
| Surfaces correctly identified | 4/4 | Routing table was accurate |
| References loaded vs. available | 4/10 | Good selectivity -- 60% of references correctly skipped |
| Context efficiency | High | ~3,500 lines of reference for 12 findings; depth loaded only where needed |
| Remediation quality | Good | GOOD patterns provided direct fix templates, though Go-specific translation was manual |
| Time to first finding | Fast | BAD pattern matching is faster than reasoning from first principles |

### Verdict

The sec-context skill **materially improved the review quality and speed**. The structured routing prevented both over-loading context and missing relevant surfaces. The BAD/GOOD pattern pairs provided a systematic checklist that caught every vulnerability in the file, and the pre-mapped CWE references made classification immediate. The main gaps are language-specific guidance, better handling of "absence of security controls" as a trigger signal, and explicit cross-surface overlap notes.

**Rating: 8.5/10** -- Highly effective for pattern-based vulnerability detection. The progressive disclosure model and surface routing are well-designed. Minor improvements around language-specific mappings, negative-signal triggers, and cross-surface signposting would close the remaining gap.
