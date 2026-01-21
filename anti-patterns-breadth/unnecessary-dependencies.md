# Including Unnecessary Dependencies


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
