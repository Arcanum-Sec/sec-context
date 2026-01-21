# Regex Denial of Service (ReDoS)


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Vulnerable regex patterns
// ========================================
FUNCTION validate_email_redos(email):
    // Vulnerable: Catastrophic backtracking on malformed input
    // Pattern with nested quantifiers
    pattern = "^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-zA-Z]+$"

    // Attack input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
    // Regex engine tries exponential combinations before failing
    RETURN regex.match(pattern, email)
END FUNCTION

FUNCTION validate_url_redos(url):
    // Vulnerable: Multiple overlapping groups
    pattern = "^(https?://)?(www\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)*$"

    // Attack input: "http://aaaaaaaaaaaaaaaaaaaaaaaa"
    RETURN regex.match(pattern, url)
END FUNCTION

FUNCTION search_with_regex(user_pattern, content):
    // Vulnerable: User-controlled regex pattern
    // Attacker provides: "(a+)+$" with input "aaaaaaaaaaaaaaaaaaaX"
    RETURN regex.search(user_pattern, content)
END FUNCTION

// ReDoS patterns to avoid:
// - Nested quantifiers: (a+)+, (a*)*
// - Overlapping alternatives: (a|a)+, (a|ab)+
// - Quantified groups with repetition: (a+b+)+

// ========================================
// GOOD: Safe regex patterns and practices
// ========================================
FUNCTION validate_email_safe(email):
    // First: Length check before regex
    IF email.length > 254:
        RETURN FALSE
    END IF

    // Use atomic groups or possessive quantifiers if available
    // Or use simpler, non-backtracking patterns
    pattern = "^[^@\s]+@[^@\s]+\.[^@\s]+$"  // Simple, no backtracking risk

    RETURN regex.match(pattern, email)
END FUNCTION

FUNCTION validate_email_best(email):
    // Best: Use a validated library
    TRY:
        validated = email_validator.validate(email)
        RETURN TRUE
    CATCH ValidationError:
        RETURN FALSE
    END TRY
END FUNCTION

FUNCTION validate_url_safe(url):
    // Length limit first
    IF url.length > 2048:
        RETURN FALSE
    END IF

    // Use URL parser instead of regex
    TRY:
        parsed = url_parser.parse(url)
        RETURN parsed.host IS NOT NULL AND parsed.protocol IN ["http:", "https:"]
    CATCH ParseError:
        RETURN FALSE
    END TRY
END FUNCTION

FUNCTION search_with_safe_pattern(user_input, content):
    // Never use user input directly as regex
    // Escape special characters if literal match needed
    escaped_input = regex.escape(user_input)

    // Set timeout on regex operations
    RETURN regex.search(escaped_input, content, timeout=1000)  // 1 second max
END FUNCTION

// Use RE2 or similar guaranteed-linear-time regex engine
FUNCTION search_with_re2(pattern, content):
    // RE2 rejects patterns that could cause exponential backtracking
    TRY:
        compiled = re2.compile(pattern)
        RETURN compiled.search(content)
    CATCH UnsupportedPatternError:
        // Pattern rejected due to backtracking risk
        THROW ValidationError("Invalid search pattern")
    END TRY
END FUNCTION

// Safe pattern testing
FUNCTION is_safe_regex(pattern):
    // Detect common ReDoS patterns
    dangerous_patterns = [
        "\\(.+\\)+\\+",    // (x+)+
        "\\(.+\\)\\*\\+",  // (x*)+
        "\\(.+\\)+\\*",    // (x+)*
        "\\(.+\\|.+\\)+"   // (a|b)+
    ]

    FOR dangerous IN dangerous_patterns:
        IF regex.search(dangerous, pattern):
            RETURN FALSE
        END IF
    END FOR

    RETURN TRUE
END FUNCTION
```
