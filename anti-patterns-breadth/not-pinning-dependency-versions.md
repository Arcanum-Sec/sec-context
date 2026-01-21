# Not Pinning Dependency Versions


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
