# Trusting Transitive Dependencies Blindly


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
