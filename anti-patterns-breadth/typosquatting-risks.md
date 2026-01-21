# Typosquatting and Slopsquatting Risks


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
