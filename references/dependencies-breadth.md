<!-- Source: Arcanum sec-context (https://github.com/arcanum-sec/sec-context), CC BY 4.0, Jason Haddix / Arcanum Information Security -->

## 8. Dependency and Supply Chain Security

**CWE References:** CWE-1357 (Hallucinated/Malicious Packages), CWE-1104 (Use of Unmaintained Third-Party Components), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere), CWE-494 (Download of Code Without Integrity Check)
**Severity:** Critical | **Related:** [[Dependency-Risks]]

> **Risk:** Supply chain attacks have become a leading vector for compromises. AI-generated code is particularly vulnerable: studies show 5-21% of AI-suggested packages don't exist (slopsquatting), creating opportunities for attackers to register malicious packages. Even legitimate dependencies can introduce vulnerabilities through outdated versions, typosquatting attacks, or compromised transitive dependencies.

### 8.1 Using Outdated Packages with Known Vulnerabilities

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No vulnerability scanning or version management
// ========================================

// package.json / requirements.txt / Cargo.toml (no version checking)
dependencies = {
    "lodash": "^4.17.0",       // Has known prototype pollution CVE-2019-10744
    "express": "3.x",          // EOL version with multiple CVEs
    "serialize-javascript": "1.9.0",  // XSS vulnerability
    "minimist": "0.0.8"        // Prototype pollution vulnerability
}

FUNCTION install_dependencies():
    // Vulnerable: No security audit before or after install
    package_manager.install()
    // Dependencies installed, but vulnerabilities unknown
END FUNCTION

FUNCTION run_build():
    // Vulnerable: CI/CD pipeline doesn't check for vulnerabilities
    install_dependencies()
    compile_code()
    deploy()  // Deploying known vulnerable code
END FUNCTION

// ========================================
// GOOD: Active vulnerability management
// ========================================

// Step 1: Use dependency scanning in development
FUNCTION install_dependencies():
    // Install dependencies
    package_manager.install()

    // Run vulnerability audit
    audit_result = package_manager.audit()

    IF audit_result.has_critical OR audit_result.has_high:
        log.error("Security vulnerabilities found", audit_result)
        THROW Error("Cannot install packages with known vulnerabilities")
    END IF

    IF audit_result.has_moderate:
        log.warn("Moderate vulnerabilities found - review required")
    END IF
END FUNCTION

// Step 2: CI/CD pipeline integration
FUNCTION ci_security_checks():
    // Run multiple scanners for defense in depth

    // Package manager native audit
    audit_npm = run_command("npm audit --audit-level=high")

    // Dedicated vulnerability scanner (Snyk, Dependabot, etc.)
    scan_result = security_scanner.scan({
        fail_on: ["critical", "high"],
        ignore_dev_dependencies: FALSE,  // Dev deps can still be exploited
        scan_transitive: TRUE
    })

    IF NOT scan_result.passed:
        // Block deployment
        send_alert("Security scan failed", scan_result.vulnerabilities)
        THROW PipelineError("Security checks failed")
    END IF
END FUNCTION

// Step 3: Automated updates with testing
FUNCTION schedule_dependency_updates():
    // Automated PR creation for security patches
    configure_dependabot({
        update_schedule: "weekly",
        security_updates: "immediate",  // High/critical get PRs immediately
        ignore: [],  // Don't ignore security updates
        auto_merge: {
            enabled: TRUE,
            conditions: ["tests_pass", "security_patch_only"]
        }
    })
END FUNCTION

// Step 4: Monitor for new vulnerabilities
FUNCTION monitor_dependencies():
    // Subscribe to security advisories
    advisories.subscribe({
        packages: get_production_dependencies(),
        severity: ["critical", "high", "moderate"],
        callback: FUNCTION(advisory):
            create_urgent_ticket(advisory)

            IF advisory.severity == "critical":
                send_pager_alert(advisory)
            END IF
        END FUNCTION
    })
END FUNCTION
```

### 8.2 Not Pinning Dependency Versions

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Loose version constraints
// ========================================

// package.json with ranges that allow breaking/malicious updates
{
    "dependencies": {
        "express": "*",           // ANY version - extremely dangerous
        "lodash": "latest",       // Always latest - no reproducibility
        "react": "^18.0.0",       // Major.minor.patch - allows minor bumps
        "axios": "~1.2.0",        // Allows patch updates automatically
        "moment": ""              // No version specified
    }
}

// Python requirements.txt
express            # No version - gets latest
lodash>=4.0.0      # Minimum only - accepts any newer version
react              # Latest

// Problems:
// 1. Builds not reproducible - different installs get different versions
// 2. Malicious version published = auto-installed on next build
// 3. Breaking changes silently introduced
// 4. "Works on my machine" issues

FUNCTION deploy():
    // Different developers/builds get different dependency versions
    install_dependencies()  // Non-deterministic
    run_tests()             // May pass with one version, fail with another
    deploy_to_production()  // Production behavior unpredictable
END FUNCTION

// ========================================
// GOOD: Exact version pinning with lockfiles
// ========================================

// package.json with exact versions
{
    "dependencies": {
        "express": "4.18.2",      // Exact version
        "lodash": "4.17.21",      // Exact version
        "react": "18.2.0",        // Exact version
        "axios": "1.6.2",         // Exact version
        "moment": "2.29.4"        // Exact version
    }
}

// Python requirements.txt with exact pins
express==4.18.2
lodash==4.17.21
react==18.2.0

// Step 1: Always use lockfiles
FUNCTION setup_project():
    // Generate and commit lockfile
    package_manager.install()

    // Commit the lockfile to version control
    // package-lock.json, yarn.lock, Pipfile.lock, poetry.lock, Cargo.lock
    git.add("package-lock.json")
    git.commit("Lock dependency versions for reproducible builds")
END FUNCTION

// Step 2: Use lockfile for installs
FUNCTION install_dependencies():
    // Use frozen/locked install (no modifications to lockfile)
    // npm ci, pip install --no-deps, poetry install --no-update
    package_manager.install_from_lockfile()

    // Verify lockfile matches package file
    IF lockfile_outdated():
        THROW Error("Lockfile out of sync - run package_manager.install locally")
    END IF
END FUNCTION

// Step 3: CI verification
FUNCTION ci_verify_lockfile():
    // Ensure lockfile is present and used
    IF NOT file_exists("package-lock.json"):
        THROW Error("Lockfile missing - add to version control")
    END IF

    // Install with strict lockfile adherence
    result = run_command("npm ci")  // Fails if lockfile doesn't match

    IF NOT result.success:
        THROW Error("Lockfile integrity check failed")
    END IF
END FUNCTION

// Step 4: Controlled updates
FUNCTION update_dependency(package_name, new_version):
    // Update one dependency at a time with review
    package_manager.update(package_name, new_version)

    // Run full test suite
    run_all_tests()

    // Check for vulnerabilities in new version
    security_scan()

    // Create PR for review
    create_pull_request({
        title: "Update " + package_name + " to " + new_version,
        body: generate_changelog_diff(package_name),
        reviewers: ["security-team"]
    })
END FUNCTION
```

### 8.3 Typosquatting and Slopsquatting Risks

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Accepting AI package suggestions without verification
// ========================================

// AI suggests: "Use the 'coloUrs' package for terminal colors"
// Developer copies without checking:

IMPORT colours from "colours"        // Typosquat of "colors"
IMPORT lodashs from "lodashs"        // Typosquat of "lodash"
IMPORT requets from "requets"        // Typosquat of "requests"
IMPORT electorn from "electorn"      // Typosquat of "electron"
IMPORT cripto from "cripto"          // Typosquat of "crypto"

// Slopsquatting: AI hallucinated package that doesn't exist
// Attacker registers it with malicious code
IMPORT ai-json-parser from "ai-json-parser"  // Never existed - attacker registered

FUNCTION install_package(name):
    // Dangerous: No verification that package is legitimate
    package_manager.install(name)
END FUNCTION

// Attack vector:
// 1. AI hallucinates package name "react-utils-helper"
// 2. Package doesn't exist on npm
// 3. Attacker monitors AI suggestions, registers "react-utils-helper"
// 4. Malicious code runs in thousands of projects

// ========================================
// GOOD: Verify packages before installation
// ========================================

FUNCTION verify_package(package_name):
    // Step 1: Check if package exists in official registry
    package_info = registry.lookup(package_name)

    IF package_info IS NULL:
        log.error("Package does not exist", {name: package_name})
        RETURN {valid: FALSE, reason: "Package not found in registry"}
    END IF

    // Step 2: Check package age and download stats
    IF package_info.created_date > (now() - 30_DAYS):
        log.warn("Recently created package - review carefully", {
            name: package_name,
            created: package_info.created_date
        })
    END IF

    IF package_info.weekly_downloads < 1000:
        log.warn("Low download count - verify legitimacy", {
            name: package_name,
            downloads: package_info.weekly_downloads
        })
    END IF

    // Step 3: Check for typosquatting indicators
    similar_packages = find_similar_names(package_name)
    FOR similar IN similar_packages:
        IF similar.downloads > package_info.downloads * 100:
            log.warn("Possible typosquat of popular package", {
                requested: package_name,
                popular_similar: similar.name
            })
            RETURN {valid: FALSE, reason: "Possible typosquat of " + similar.name}
        END IF
    END FOR

    // Step 4: Check publisher reputation
    IF NOT package_info.publisher.verified:
        log.warn("Unverified publisher", {publisher: package_info.publisher.name})
    END IF

    // Step 5: Check for known malicious indicators
    IF security_database.is_malicious(package_name):
        log.error("Known malicious package", {name: package_name})
        RETURN {valid: FALSE, reason: "Package flagged as malicious"}
    END IF

    RETURN {valid: TRUE, info: package_info}
END FUNCTION

FUNCTION install_package_safely(name):
    verification = verify_package(name)

    IF NOT verification.valid:
        THROW Error("Package verification failed: " + verification.reason)
    END IF

    // Only install after verification
    package_manager.install(name)
END FUNCTION

// Use allowlist for approved packages
FUNCTION enforce_package_allowlist():
    approved_packages = load_allowlist("approved-packages.txt")

    current_dependencies = get_all_dependencies()

    FOR dep IN current_dependencies:
        IF dep NOT IN approved_packages:
            log.error("Unapproved dependency", {package: dep})
            THROW SecurityError("Package not in allowlist: " + dep)
        END IF
    END FOR
END FUNCTION

// Common typosquatting patterns to check
FUNCTION get_typosquat_variants(name):
    variants = []

    // Character substitution
    variants.add(name.replace("l", "1"))   // lodash -> 1odash
    variants.add(name.replace("o", "0"))   // colors -> c0lors

    // Double characters
    FOR i IN range(len(name)):
        variants.add(name[:i] + name[i] + name[i:])  // lodash -> llodash

    // Missing characters
    FOR i IN range(len(name)):
        variants.add(name[:i] + name[i+1:])  // lodash -> ldash

    // Transposed characters
    FOR i IN range(len(name)-1):
        variants.add(name[:i] + name[i+1] + name[i] + name[i+2:])

    RETURN variants
END FUNCTION
```

### 8.4 Including Unnecessary Dependencies

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Kitchen-sink dependencies
// ========================================

// Adding large libraries for simple tasks
IMPORT moment from "moment"          // 300KB for date formatting
IMPORT lodash from "lodash"          // Entire library for one function
IMPORT jquery from "jquery"          // Just for simple DOM selection
IMPORT bootstrap from "bootstrap"    // Just for one CSS class
IMPORT aws_sdk from "aws-sdk"        // Entire SDK for one service

FUNCTION format_date(date):
    // Using 300KB library for simple formatting
    RETURN moment(date).format("YYYY-MM-DD")
END FUNCTION

FUNCTION capitalize_string(str):
    // Using lodash just for capitalize
    RETURN lodash.capitalize(str)
END FUNCTION

// Problems:
// 1. Larger attack surface - more code = more potential vulnerabilities
// 2. Each dependency is a supply chain risk
// 3. Transitive dependencies multiply the risk
// 4. Bloated bundle size affects performance
// 5. More packages to audit and update

// ========================================
// GOOD: Minimal, targeted dependencies
// ========================================

// Option 1: Use native language features
FUNCTION format_date(date):
    // Native Intl.DateTimeFormat (no dependency)
    formatter = Intl.DateTimeFormat("en-CA", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit"
    })
    RETURN formatter.format(date)
END FUNCTION

FUNCTION capitalize_string(str):
    // Native string methods (no dependency)
    IF str.length == 0:
        RETURN str
    END IF
    RETURN str[0].toUpperCase() + str.slice(1).toLowerCase()
END FUNCTION

// Option 2: Use focused micro-packages when needed
IMPORT date_fns_format from "date-fns/format"  // Just the format function
IMPORT capitalize from "lodash/capitalize"      // Just capitalize, not all of lodash

// Option 3: Import only what you need from modular packages
IMPORT { S3Client } from "@aws-sdk/client-s3"  // Just S3, not entire AWS SDK

// Dependency audit function
FUNCTION audit_dependencies():
    dependencies = get_all_dependencies()
    issues = []

    FOR dep IN dependencies:
        // Check for large packages that could be replaced
        IF dep.size > SIZE_THRESHOLD:
            // Analyze actual usage
            used_exports = analyze_imports(dep.name)
            total_exports = get_package_exports(dep.name)

            usage_ratio = used_exports.count / total_exports.count

            IF usage_ratio < 0.1:  // Using less than 10% of package
                issues.append({
                    package: dep.name,
                    size: dep.size,
                    usage: usage_ratio,
                    recommendation: "Consider focused alternative or native implementation"
                })
            END IF
        END IF

        // Check for deprecated packages
        IF dep.deprecated:
            issues.append({
                package: dep.name,
                reason: "deprecated",
                alternative: dep.recommended_alternative
            })
        END IF

        // Check for packages with many vulnerabilities historically
        vuln_history = get_vulnerability_history(dep.name)
        IF vuln_history.count > 5:
            issues.append({
                package: dep.name,
                reason: "frequent_vulnerabilities",
                count: vuln_history.count
            })
        END IF
    END FOR

    RETURN issues
END FUNCTION

// Enforce maximum dependency count/size
FUNCTION enforce_dependency_limits():
    deps = get_production_dependencies()

    IF deps.count > MAX_DIRECT_DEPS:
        log.warn("Too many direct dependencies", {
            count: deps.count,
            max: MAX_DIRECT_DEPS
        })
    END IF

    total_deps = get_all_dependencies_including_transitive()

    IF total_deps.count > MAX_TOTAL_DEPS:
        log.error("Excessive transitive dependencies", {
            count: total_deps.count,
            max: MAX_TOTAL_DEPS
        })
    END IF
END FUNCTION
```

### 8.5 Missing Integrity Checks

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No integrity verification
// ========================================

// HTML script tag without integrity
<script src="https://cdn.example.com/library.js"></script>

// Downloading without verification
FUNCTION download_dependency(url):
    content = http.get(url)
    write_file("lib/dependency.js", content)
    // No verification that content is what we expected
END FUNCTION

// Package install without lockfile integrity
FUNCTION install():
    run_command("npm install")  // Uses ^ ranges, no integrity check
END FUNCTION

// Build process pulling from remote without checks
FUNCTION build():
    // Downloading build tools without verification
    download("https://build-tools.example.com/compiler.tar.gz")
    extract("compiler.tar.gz")
    execute("./compiler/build")  // Running unverified code
END FUNCTION

// ========================================
// GOOD: Verify integrity at every step
// ========================================

// HTML with Subresource Integrity (SRI)
<script
    src="https://cdn.example.com/library.js"
    integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
    crossorigin="anonymous">
</script>

// Download with hash verification
FUNCTION download_verified(url, expected_hash):
    content = http.get(url)

    // Calculate hash of downloaded content
    actual_hash = crypto.sha384(content)

    IF actual_hash != expected_hash:
        log.error("Integrity check failed", {
            url: url,
            expected: expected_hash,
            actual: actual_hash
        })
        THROW SecurityError("Downloaded file failed integrity check")
    END IF

    RETURN content
END FUNCTION

FUNCTION download_dependency(url, expected_hash):
    content = download_verified(url, expected_hash)
    write_file("lib/dependency.js", content)
    log.info("Dependency installed with verified integrity", {url: url})
END FUNCTION

// Package lockfile with integrity hashes
// package-lock.json includes:
{
    "lodash": {
        "version": "4.17.21",
        "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        "integrity": "sha512-v2kDE0cyTsc..."  // Verified on install
    }
}

// Strict install from lockfile
FUNCTION install_with_integrity():
    // npm ci verifies integrity hashes from lockfile
    result = run_command("npm ci")

    IF NOT result.success:
        THROW Error("Installation failed integrity verification")
    END IF
END FUNCTION

// Build reproducibility with verified tools
FUNCTION secure_build():
    // Pin and verify all build tool versions
    tools = {
        "node": {version: "20.10.0", hash: "sha256:abc123..."},
        "npm": {version: "10.2.3", hash: "sha256:def456..."},
        "compiler": {version: "1.2.3", hash: "sha256:ghi789..."}
    }

    FOR tool_name, tool_spec IN tools:
        // Verify tool binary integrity before use
        actual_hash = hash_file(get_tool_path(tool_name))

        IF actual_hash != tool_spec.hash:
            THROW SecurityError("Build tool integrity check failed: " + tool_name)
        END IF
    END FOR

    // Proceed with verified tools
    run_build()
END FUNCTION

// Generate SRI hashes for your own assets
FUNCTION generate_sri_hash(file_path):
    content = read_file(file_path)
    hash = crypto.sha384_base64(content)
    RETURN "sha384-" + hash
END FUNCTION

FUNCTION generate_script_tag(src, file_path):
    integrity = generate_sri_hash(file_path)
    RETURN '<script src="' + src + '" integrity="' + integrity + '" crossorigin="anonymous"></script>'
END FUNCTION

// Registry verification
FUNCTION verify_registry():
    // Ensure using official, signed registry
    registry_config = get_registry_config()

    IF NOT registry_config.url.startswith("https://"):
        THROW SecurityError("Registry must use HTTPS")
    END IF

    // Verify registry certificate
    IF NOT verify_certificate(registry_config.url):
        THROW SecurityError("Registry certificate verification failed")
    END IF

    // Check for registry signing if supported
    IF registry_supports_signing(registry_config.url):
        enable_signature_verification()
    END IF
END FUNCTION
```

### 8.6 Trusting Transitive Dependencies Blindly

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Ignoring transitive dependency risks
// ========================================

// Your package.json has 10 direct dependencies
// But those bring in 500+ transitive dependencies
// Each is a potential attack vector

FUNCTION show_dependency_problem():
    // You audit only direct dependencies
    direct_deps = ["express", "lodash", "axios"]  // 3 packages

    // Reality after npm install
    all_deps = get_all_installed_packages()
    print("Direct: 3, Total installed: " + all_deps.count)  // 547 packages!

    // Any of those 544 transitive deps could be:
    // - Abandoned and vulnerable
    // - Taken over by malicious actors
    // - Typosquats
    // - Compromised in CI/CD
END FUNCTION

// Event-stream incident: Dependency of dependency was compromised
// ua-parser-js incident: Popular package itself was compromised
// node-ipc incident: Maintainer added malicious code

// ========================================
// GOOD: Full dependency tree visibility and control
// ========================================

// Step 1: Analyze full dependency tree
FUNCTION analyze_dependency_tree():
    tree = package_manager.get_dependency_tree()

    analysis = {
        direct: [],
        transitive: [],
        depth_stats: {},
        risk_assessment: []
    }

    FOR dep IN tree.flatten():
        IF dep.depth == 1:
            analysis.direct.append(dep)
        ELSE:
            analysis.transitive.append(dep)
        END IF

        // Track dependency depth
        analysis.depth_stats[dep.depth] =
            (analysis.depth_stats[dep.depth] OR 0) + 1

        // Risk factors for transitive deps
        risk_score = calculate_risk(dep)
        IF risk_score > THRESHOLD:
            analysis.risk_assessment.append({
                package: dep.name,
                introduced_by: dep.parent_chain,
                risk_score: risk_score,
                factors: get_risk_factors(dep)
            })
        END IF
    END FOR

    RETURN analysis
END FUNCTION

FUNCTION calculate_risk(dep):
    risk = 0

    // Maintainer factors
    IF dep.maintainers.count == 1:
        risk += 10  // Single maintainer - bus factor
    END IF

    IF dep.last_update > 2_YEARS_AGO:
        risk += 20  // Abandoned package
    END IF

    // Security factors
    IF dep.vulnerability_count > 0:
        risk += dep.vulnerability_count * 15
    END IF

    IF dep.has_install_scripts:
        risk += 25  // Runs code on install
    END IF

    // Popularity/trust factors
    IF dep.weekly_downloads < 1000:
        risk += 10  // Low usage
    END IF

    IF NOT dep.has_types AND dep.is_js:
        risk += 5  // Less maintained indicator
    END IF

    RETURN risk
END FUNCTION

// Step 2: Detect and alert on risky transitive deps
FUNCTION monitor_transitive_deps():
    tree = get_dependency_tree()

    FOR dep IN tree.flatten():
        // Check for suspicious characteristics
        IF dep.has_install_scripts:
            log.warn("Package has install scripts", {
                package: dep.name,
                path: dep.parent_chain
            })
            // Review install scripts for malicious code
            scripts = get_install_scripts(dep)
            FOR script IN scripts:
                IF contains_suspicious_patterns(script):
                    THROW SecurityError("Suspicious install script in: " + dep.name)
                END IF
            END FOR
        END IF

        // Check for native code compilation
        IF dep.has_native_code:
            log.warn("Package compiles native code", {
                package: dep.name
            })
        END IF

        // Check for network access
        IF dep.makes_network_requests:
            log.warn("Package makes network requests", {
                package: dep.name
            })
        END IF
    END FOR
END FUNCTION

// Step 3: Use dependency scanning that covers transitives
FUNCTION full_dependency_scan():
    // Scan all dependencies, not just direct
    scan_result = security_scanner.scan({
        include_transitive: TRUE,
        include_dev_dependencies: TRUE,
        scan_depth: "all"  // Not just top-level
    })

    FOR vuln IN scan_result.vulnerabilities:
        // Show the path that introduces the vulnerability
        log.error("Vulnerability found", {
            package: vuln.package,
            version: vuln.version,
            severity: vuln.severity,
            introduced_through: vuln.dependency_path,  // e.g., "express > body-parser > qs"
            recommendation: vuln.recommendation
        })
    END FOR

    RETURN scan_result
END FUNCTION

// Step 4: Consider dependency vendoring for critical deps
FUNCTION vendor_critical_dependency(package_name):
    // Download specific version
    content = download_verified(
        get_package_url(package_name),
        get_expected_hash(package_name)
    )

    // Store in vendor directory (committed to repo)
    write_file("vendor/" + package_name, content)

    // Point imports to vendored version
    configure_import_alias(package_name, "./vendor/" + package_name)

    // Vendored code is:
    // - Not automatically updated (reduces surprise changes)
    // - Under your source control (auditable)
    // - Not subject to registry compromise
END FUNCTION

// Step 5: Use SBOM (Software Bill of Materials)
FUNCTION generate_sbom():
    sbom = {
        format: "CycloneDX",  // or SPDX
        components: [],
        dependencies: []
    }

    FOR dep IN get_all_dependencies():
        sbom.components.append({
            type: "library",
            name: dep.name,
            version: dep.version,
            purl: "pkg:npm/" + dep.name + "@" + dep.version,
            hashes: [
                {algorithm: "SHA-256", content: dep.sha256}
            ],
            licenses: dep.licenses,
            supplier: dep.publisher
        })
    END FOR

    // Export for vulnerability tracking
    write_file("sbom.json", json.encode(sbom))

    // Submit to vulnerability database for ongoing monitoring
    vuln_service.monitor_sbom(sbom)
END FUNCTION
```

---
