# Missing Integrity Checks


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
