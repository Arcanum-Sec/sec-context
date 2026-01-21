# Using Outdated Packages with Known Vulnerabilities


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
