# Pattern 6: Input Validation and Data Sanitization

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


**CWE References:** CWE-20 (Improper Input Validation), CWE-1286 (Improper Validation of Syntactic Correctness of Input), CWE-185 (Incorrect Regular Expression), CWE-1333 (Inefficient Regular Expression Complexity), CWE-129 (Improper Validation of Array Index)

**Priority Score:** 21 (Frequency: 9, Severity: 7, Detectability: 5)

---

## Introduction: The Foundation That AI Frequently Skips

Input validation is the **first line of defense** against virtually all injection attacks, data corruption, and application crashes. Yet AI-generated code consistently fails to implement proper validation, treating it as an afterthought or skipping it entirely.

**Why AI Models Skip or Fail at Input Validation:**

1. **Training Data Focuses on "Happy Path":** Most tutorial code, documentation examples, and Stack Overflow answers demonstrate functionality with expected inputs. Validation code is often omitted for brevity, teaching AI that it's optional.

2. **Validation Is Contextual:** Proper validation depends on business rules, data types, and downstream usage—context that AI often lacks. The model can't know that a "name" field shouldn't exceed 100 characters or that an "age" must be between 0 and 150.

3. **Client-Side Validation Appears Complete:** AI training data often contains client-side form validation (JavaScript). The model learns these patterns but fails to understand that server-side validation is the actual security boundary.

4. **Regex Complexity:** AI generates complex regex patterns that may be vulnerable to catastrophic backtracking (ReDoS) or miss edge cases. The model optimizes for matching expected patterns, not rejecting malicious ones.

5. **Trust Boundary Confusion:** AI doesn't inherently understand which data sources are trustworthy. It may validate user form input but trust data from internal APIs, databases, or message queues that could also be compromised.

6. **Type System Overconfidence:** In typed languages, AI may assume type declarations are sufficient validation, missing the need for range checks, format validation, and semantic constraints.

**Why This Matters - The Foundation of All Injection Attacks:**

Every major vulnerability class depends on inadequate input validation:
- **SQL Injection:** Unvalidated input in queries
- **Command Injection:** Unvalidated input in shell commands
- **XSS:** Unvalidated input rendered in HTML
- **Path Traversal:** Unvalidated file paths
- **Deserialization Attacks:** Unvalidated serialized objects
- **Buffer Overflows:** Unvalidated input lengths
- **Business Logic Bypass:** Unvalidated business constraints

**Impact Statistics:**
- CWE-20 (Improper Input Validation) appears in OWASP Top 10 as a root cause of multiple vulnerabilities
- 42% of SQL injection vulnerabilities trace back to missing input validation (NIST NVD analysis)
- ReDoS vulnerabilities increased 143% year-over-year in npm packages (Snyk 2024)
- 67% of AI-generated validation code only validates on the client side (Security research 2025)

---

## BAD Examples: Different Manifestations

### BAD Example 1: Client-Side Only Validation

```pseudocode
// VULNERABLE: All validation in frontend, server trusts everything

// Frontend validation (JavaScript)
function validateForm(form):
    if form.email is empty:
        showError("Email required")
        return false

    if not isValidEmail(form.email):
        showError("Invalid email format")
        return false

    if form.password.length < 8:
        showError("Password must be 8+ characters")
        return false

    if form.age < 0 or form.age > 150:
        showError("Invalid age")
        return false

    // Form is "valid", submit to server
    return true

// Backend endpoint (VULNERABLE - no validation)
function handleRegistration(request):
    // AI assumes frontend validated, so just use the data
    email = request.body.email      // Could be anything
    password = request.body.password // Could be empty
    age = request.body.age          // Could be -1 or 9999999

    // Directly store in database
    query = "INSERT INTO users (email, password, age) VALUES (?, ?, ?)"
    database.execute(query, [email, hashPassword(password), age])

    return {"success": true}
```

**Why This Is Dangerous:**
- Attackers bypass JavaScript by sending direct HTTP requests (curl, Postman, scripts)
- Browser dev tools allow modifying form data before submission
- Server receives arbitrary data with no protection
- Data integrity issues cascade through the application
- SQL injection still possible if query construction is vulnerable elsewhere

**Attack Scenario:**
```pseudocode
// Attacker sends directly to API:
POST /api/register
Content-Type: application/json

{
    "email": "'; DROP TABLE users; --",
    "password": "",
    "age": -9999999999
}
```

---

### BAD Example 2: Partial Validation (Type but Not Range)

```pseudocode
// VULNERABLE: Validates type exists, ignores business constraints

function processPayment(request):
    // Type checking only
    if typeof(request.amount) != "number":
        return error("Amount must be a number")

    if typeof(request.quantity) != "integer":
        return error("Quantity must be an integer")

    // MISSING: Range validation
    // amount could be negative (refund attack)
    // quantity could be 0 or MAX_INT (business logic bypass)

    total = request.amount * request.quantity
    chargeCustomer(request.customerId, total)

    return {"charged": total}

// Attacker exploits:
{
    "amount": -100.00,      // Negative = credit instead of charge
    "quantity": 999999999,  // Integer overflow potential
    "customerId": "12345"
}
```

**Why This Is Dangerous:**
- Type validation is necessary but not sufficient
- Business logic depends on reasonable ranges
- Integer overflow can wrap to unexpected values
- Negative values can invert expected behavior
- Zero values can bypass payment or cause division errors

---

### BAD Example 3: Regex Without Anchors

```pseudocode
// VULNERABLE: Regex matches substring, not entire input

// Email validation without anchors
EMAIL_PATTERN = "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

function validateEmail(email):
    if regex.match(EMAIL_PATTERN, email):
        return true
    return false

// This PASSES validation:
validateEmail("MALICIOUS_PAYLOAD user@example.com MALICIOUS_PAYLOAD")
// Because "user@example.com" matches somewhere in the string

// Filename validation without anchors
SAFE_FILENAME = "[a-zA-Z0-9_-]+"

function validateFilename(filename):
    if regex.match(SAFE_FILENAME, filename):
        return true
    return false

// This PASSES validation:
validateFilename("../../../etc/passwd")
// Because "etc" matches the pattern somewhere in the string
```

**Why This Is Dangerous:**
- Regex matches anywhere in string, not the complete input
- Injection payloads can surround or precede valid patterns
- Path traversal bypasses filename validation
- Email field can contain XSS payloads around valid address
- Common in AI-generated code which copies regex patterns without anchors

**Fix Preview:**
```pseudocode
// SECURE: Use ^ and $ anchors to match entire input
EMAIL_PATTERN = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
SAFE_FILENAME = "^[a-zA-Z0-9_-]+$"
```

---

### BAD Example 4: ReDoS-Vulnerable Patterns

```pseudocode
// VULNERABLE: Catastrophic backtracking regex patterns

// Email validation with ReDoS vulnerability
// Pattern: nested quantifiers with overlapping character classes
VULNERABLE_EMAIL = "^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\.[a-zA-Z]+$"

// Attack input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
// The regex engine backtracks exponentially trying all combinations

// URL validation with ReDoS
VULNERABLE_URL = "^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$"

// Attack input: long string of valid URL characters followed by invalid character
// "http://example.com/" + "a" * 30 + "!"

// Naive duplicate word finder (common tutorial example)
DUPLICATE_WORDS = "\b(\w+)\s+\1\b"
// Can hang on: "word word word word word word word word word word!"

function validateInput(input, pattern):
    // This can hang for minutes or crash the server
    return regex.match(pattern, input)
```

**Why This Is Dangerous:**
- Single malicious request can consume 100% CPU for minutes
- Denial of Service without requiring many requests
- AI copies these patterns from tutorials without understanding complexity
- Nested quantifiers `(a+)+`, `(a*)*`, `(a?)*` are red flags
- Overlapping character classes compound the problem

**ReDoS Complexity Analysis:**
```pseudocode
// Pattern: (a+)+$
// Input: "aaaaaaaaaaaaaaaaaaaaaaaaX"
//
// For 25 'a's followed by 'X':
// - The engine tries every possible way to split the 'a's between groups
// - Time complexity: O(2^n) where n is input length
// - 25 chars = 33 million+ combinations to try
// - 30 chars = 1 billion+ combinations
```

---

### BAD Example 5: Missing Null/Undefined Checks

```pseudocode
// VULNERABLE: Assumes data structure completeness

function processUserProfile(user):
    // No null checks - any missing field crashes
    fullName = user.firstName + " " + user.lastName  // Crash if null

    emailDomain = user.email.split("@")[1]  // Crash if email is null

    age = parseInt(user.profile.age)  // Crash if profile is null

    // Process address (deeply nested)
    city = user.profile.address.city.toUpperCase()  // Multiple crash points

    return {
        "name": fullName,
        "domain": emailDomain,
        "age": age,
        "city": city
    }

// API returns partial data:
{
    "firstName": "John",
    "lastName": null,           // Could be null
    "email": null,              // Could be missing
    "profile": {
        "age": "25"
        // address is missing entirely
    }
}
```

**Why This Is Dangerous:**
- Application crashes reveal error messages to attackers
- Null pointer exceptions can leak stack traces
- Partial data from APIs, databases, or user input is common
- AI assumes training data structures are always complete
- Cascading failures when one field is null

---

### BAD Example 6: Trusting Array Indices from User Input

```pseudocode
// VULNERABLE: Using user input directly as array index

function getItemByIndex(request):
    items = ["item0", "item1", "item2", "item3", "item4"]
    index = request.params.index  // User-provided

    // No validation - trusts user to provide valid index
    return items[index]  // Out of bounds or negative index

// Worse: Array index used for data access
function getUserData(request):
    userIndex = parseInt(request.params.id)

    // Could access negative index, other users' data, or crash
    return allUsersData[userIndex]

// Object property access from user input
function getConfigValue(request):
    configKey = request.params.key

    // Prototype pollution or access to __proto__, constructor
    return config[configKey]
```

**Why This Is Dangerous:**
- Negative indices wrap to end of array in some languages
- Out-of-bounds access crashes or returns undefined behavior
- Integer overflow can produce unexpected indices
- Object property access allows prototype pollution
- `__proto__`, `constructor`, `prototype` keys can modify object behavior

**Attack Scenarios:**
```pseudocode
// Array out of bounds:
GET /items?index=99999999
GET /items?index=-1

// Prototype pollution via property access:
GET /config?key=__proto__
GET /config?key=constructor
POST /config {"key": "__proto__", "value": {"isAdmin": true}}
```

---

## GOOD Examples: Proper Patterns

### GOOD Example 1: Server-Side Validation Patterns

```pseudocode
// SECURE: Comprehensive server-side validation with clear error messages

function handleRegistration(request):
    errors = []

    // Email validation
    email = request.body.email
    if email is null or email is empty:
        errors.append({"field": "email", "message": "Email is required"})
    else if length(email) > 254:  // RFC 5321 limit
        errors.append({"field": "email", "message": "Email too long"})
    else if not isValidEmailFormat(email):
        errors.append({"field": "email", "message": "Invalid email format"})
    else if not isAllowedEmailDomain(email):  // Business rule
        errors.append({"field": "email", "message": "Email domain not allowed"})

    // Password validation
    password = request.body.password
    if password is null or password is empty:
        errors.append({"field": "password", "message": "Password is required"})
    else if length(password) < 12:
        errors.append({"field": "password", "message": "Password must be 12+ characters"})
    else if length(password) > 128:  // Prevent DoS via bcrypt
        errors.append({"field": "password", "message": "Password too long"})
    else if not meetsComplexityRequirements(password):
        errors.append({"field": "password", "message": "Password too weak"})

    // Age validation (integer with business range)
    age = request.body.age
    if age is null:
        errors.append({"field": "age", "message": "Age is required"})
    else if typeof(age) != "integer":
        errors.append({"field": "age", "message": "Age must be a whole number"})
    else if age < 13:  // Business rule: minimum age
        errors.append({"field": "age", "message": "Must be at least 13 years old"})
    else if age > 150:  // Sanity check
        errors.append({"field": "age", "message": "Invalid age"})

    // Return all errors at once (better UX than one at a time)
    if errors.length > 0:
        return {"success": false, "errors": errors}

    // Only process after validation passes
    hashedPassword = hashPassword(password)
    createUser(email, hashedPassword, age)
    return {"success": true}
```

**Why This Is Secure:**
- Every field validated before use
- Type, format, length, and business rules all checked
- Clear, specific error messages for debugging
- All errors collected (better user experience)
- Reasonable upper bounds prevent DoS
- Validation happens server-side where client cannot bypass

---

### GOOD Example 2: Schema Validation Approaches

```pseudocode
// SECURE: Declarative schema validation with robust library

// Define schema once, reuse everywhere
USER_REGISTRATION_SCHEMA = {
    "type": "object",
    "required": ["email", "password", "age", "name"],
    "additionalProperties": false,  // Reject unknown fields
    "properties": {
        "email": {
            "type": "string",
            "format": "email",
            "maxLength": 254
        },
        "password": {
            "type": "string",
            "minLength": 12,
            "maxLength": 128
        },
        "age": {
            "type": "integer",
            "minimum": 13,
            "maximum": 150
        },
        "name": {
            "type": "object",
            "required": ["first", "last"],
            "properties": {
                "first": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                    "pattern": "^[\\p{L}\\s'-]+$"  // Unicode letters, spaces, hyphens, apostrophes
                },
                "last": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100,
                    "pattern": "^[\\p{L}\\s'-]+$"
                }
            }
        }
    }
}

function handleRegistration(request):
    // Validate entire payload against schema
    validationResult = schemaValidator.validate(request.body, USER_REGISTRATION_SCHEMA)

    if not validationResult.valid:
        return {
            "success": false,
            "errors": validationResult.errors  // Detailed error per field
        }

    // Data is guaranteed to match schema structure and constraints
    processRegistration(request.body)
    return {"success": true}

// Additional business logic validation after schema validation
function processRegistration(data):
    // Schema ensures structure; now check business rules
    if isEmailAlreadyRegistered(data.email):
        throw ValidationError("Email already registered")

    if isCommonPassword(data.password):
        throw ValidationError("Password is too common")

    createUser(data)
```

**Why This Is Secure:**
- Schema is declarative, easy to audit
- `additionalProperties: false` prevents unexpected data injection
- Type coercion handled consistently by library
- Unicode-aware patterns for international names
- Nested object validation built-in
- Separation of structural validation and business rules

---

### GOOD Example 3: Safe Regex Patterns

```pseudocode
// SECURE: Anchored, bounded, and ReDoS-resistant patterns

// Email validation - anchored and bounded
// Note: Perfect email validation is complex; often better to just check format
// and verify via confirmation email
EMAIL_PATTERN = "^[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,253}\\.[a-zA-Z]{2,63}$"

// Safe filename - anchored, limited character set, bounded length
FILENAME_PATTERN = "^[a-zA-Z0-9][a-zA-Z0-9._-]{0,254}$"

// Safe identifier (alphanumeric + underscore, starts with letter)
IDENTIFIER_PATTERN = "^[a-zA-Z][a-zA-Z0-9_]{0,63}$"

// URL path segment - no special characters
PATH_SEGMENT_PATTERN = "^[a-zA-Z0-9._-]{1,255}$"

function validateWithSafeRegex(input, pattern, maxLength):
    // Length check BEFORE regex (prevents ReDoS)
    if input is null or length(input) > maxLength:
        return false

    // Use timeout-protected regex matching if available
    try:
        return regexMatchWithTimeout(pattern, input, timeout = 100ms)
    catch TimeoutException:
        logWarning("Regex timeout on input: " + truncate(input, 50))
        return false

// For complex patterns, use atomic groups or possessive quantifiers
// (syntax varies by regex engine)

// VULNERABLE: (a+)+
// SAFE: (?>a+)+ (atomic group - no backtracking into group)
// SAFE: a++ (possessive quantifier - never backtracks)

// Alternative: Linear-time regex engines (RE2, rust regex)
// These reject patterns that could have exponential complexity
function validateWithLinearRegex(input, pattern):
    // RE2 guarantees O(n) matching time
    return RE2.match(pattern, input)
```

**Why This Is Secure:**
- All patterns anchored with `^` and `$`
- Length bounded to prevent long input attacks
- Character classes don't overlap (no `[a-zA-Z0-9]+` next to `[a-z]+`)
- No nested quantifiers that could cause backtracking
- Timeout protection as defense in depth
- Option to use linear-time regex engines

---

### GOOD Example 4: Type Coercion Handling

```pseudocode
// SECURE: Explicit type handling with safe coercion

function parseIntegerSafe(value, min, max):
    // Handle null/undefined
    if value is null or value is undefined:
        return {valid: false, error: "Value is required"}

    // If already integer, validate range
    if typeof(value) == "integer":
        if value < min or value > max:
            return {valid: false, error: "Value out of range: " + min + "-" + max}
        return {valid: true, value: value}

    // If string, parse carefully
    if typeof(value) == "string":
        // Check for valid integer string (no floats, no hex, no scientific)
        if not regex.match("^-?[0-9]+$", value):
            return {valid: false, error: "Invalid integer format"}

        parsed = parseInt(value, 10)  // Always specify radix

        // Check for NaN (parsing failure)
        if isNaN(parsed):
            return {valid: false, error: "Could not parse integer"}

        // Check for overflow
        if parsed < MIN_SAFE_INTEGER or parsed > MAX_SAFE_INTEGER:
            return {valid: false, error: "Integer overflow"}

        // Range check
        if parsed < min or parsed > max:
            return {valid: false, error: "Value out of range: " + min + "-" + max}

        return {valid: true, value: parsed}

    // Reject all other types
    return {valid: false, error: "Expected integer, got " + typeof(value)}

// Usage
function handlePayment(request):
    amountResult = parseIntegerSafe(request.body.amount, 1, 1000000)  // 1 cent to $10,000
    if not amountResult.valid:
        return error("amount: " + amountResult.error)

    quantityResult = parseIntegerSafe(request.body.quantity, 1, 100)
    if not quantityResult.valid:
        return error("quantity: " + quantityResult.error)

    // Safe to use validated integers
    total = amountResult.value * quantityResult.value
    processPayment(total)
```

**Why This Is Secure:**
- Explicit handling of null/undefined
- Type checking before operations
- Safe string-to-integer parsing with radix
- Overflow checking for platform limits
- Range validation for business constraints
- Clear error messages for each failure mode

---

### GOOD Example 5: Whitelist Validation

```pseudocode
// SECURE: Allowlist approach - only accept known-good values

// For enum-like fields, use explicit allowlist
ALLOWED_COUNTRIES = ["US", "CA", "GB", "DE", "FR", "JP", "AU"]
ALLOWED_ROLES = ["user", "moderator", "admin"]
ALLOWED_SORT_FIELDS = ["name", "date", "price", "rating"]
ALLOWED_FILE_EXTENSIONS = [".jpg", ".jpeg", ".png", ".gif", ".pdf"]

function validateCountry(input):
    // Case-insensitive comparison against allowlist
    normalized = input.toUpperCase().trim()
    if normalized in ALLOWED_COUNTRIES:
        return {valid: true, value: normalized}
    return {valid: false, error: "Invalid country code"}

function validateSortField(input):
    // Exact match required
    if input in ALLOWED_SORT_FIELDS:
        return {valid: true, value: input}
    return {valid: false, error: "Invalid sort field"}

function validateFileUpload(filename, content):
    // Extension whitelist
    extension = getExtension(filename).toLowerCase()
    if extension not in ALLOWED_FILE_EXTENSIONS:
        return {valid: false, error: "File type not allowed"}

    // ALSO validate content type (magic bytes)
    detectedType = detectFileType(content)
    if detectedType.extension != extension:
        return {valid: false, error: "File content doesn't match extension"}

    // Additional: check file isn't actually executable or contains script
    if containsExecutableContent(content):
        return {valid: false, error: "File contains disallowed content"}

    return {valid: true}

// For SQL column/table names (cannot be parameterized)
function validateColumnName(input, allowedColumns):
    if input in allowedColumns:
        return input  // Safe to use in query
    throw ValidationError("Invalid column name")

// Usage in query
function searchProducts(filters):
    sortField = validateColumnName(filters.sortBy, ["name", "price", "created_at"])
    sortOrder = filters.order == "desc" ? "DESC" : "ASC"  // Binary choice

    // Now safe to interpolate (they're from allowlist)
    query = "SELECT * FROM products ORDER BY " + sortField + " " + sortOrder
    return database.query(query)
```

**Why This Is Secure:**
- Only pre-approved values accepted
- No regex complexity or bypass potential
- Clear, auditable list of allowed values
- Easy to update when requirements change
- File validation checks both extension AND content
- SQL identifiers validated against explicit list

---

### GOOD Example 6: Canonicalization Before Validation

```pseudocode
// SECURE: Normalize input before validation to prevent bypass

function validatePath(input):
    // Step 1: Reject null bytes (used to bypass filters)
    if contains(input, "\x00"):
        return {valid: false, error: "Invalid character in path"}

    // Step 2: Decode URL encoding (multiple rounds to catch double-encoding)
    decoded = input
    for i in range(3):  // Max 3 rounds of decoding
        newDecoded = urlDecode(decoded)
        if newDecoded == decoded:
            break  // No more encoding to decode
        decoded = newDecoded

    // Step 3: Normalize path separators
    normalized = decoded.replace("\\", "/")

    // Step 4: Resolve path (remove . and ..)
    resolved = resolvePath(normalized)

    // Step 5: Check against allowed base directory
    allowedBase = "/var/www/uploads/"
    if not resolved.startsWith(allowedBase):
        return {valid: false, error: "Path traversal detected"}

    // Step 6: Check for remaining dangerous patterns
    if contains(resolved, ".."):
        return {valid: false, error: "Invalid path component"}

    return {valid: true, value: resolved}

function validateUsername(input):
    // Normalize Unicode before validation
    // NFC = Canonical Composition (combines characters)
    normalized = unicodeNormalize(input, "NFC")

    // Check for confusable characters (homoglyphs)
    if containsHomoglyphs(normalized):
        return {valid: false, error: "Username contains confusable characters"}

    // Now validate the normalized form
    if not regex.match("^[a-zA-Z0-9_]{3,20}$", normalized):
        return {valid: false, error: "Invalid username format"}

    return {valid: true, value: normalized}

function validateUrl(input):
    // Parse URL to get components
    parsed = parseUrl(input)

    if parsed is null:
        return {valid: false, error: "Invalid URL"}

    // Validate scheme (allowlist)
    if parsed.scheme not in ["http", "https"]:
        return {valid: false, error: "Only HTTP(S) URLs allowed"}

    // Check for IP addresses (may be SSRF target)
    if isIpAddress(parsed.host):
        return {valid: false, error: "IP addresses not allowed"}

    // Check for internal hostnames
    if parsed.host.endsWith(".internal") or parsed.host == "localhost":
        return {valid: false, error: "Internal URLs not allowed"}

    // Check for credentials in URL
    if parsed.username or parsed.password:
        return {valid: false, error: "Credentials in URL not allowed"}

    // Reconstruct URL from parsed components (normalizes encoding)
    canonicalUrl = buildUrl(parsed.scheme, parsed.host, parsed.port, parsed.path)

    return {valid: true, value: canonicalUrl}
```

**Why This Is Secure:**
- Multiple encoding layers decoded before validation
- Path normalization prevents traversal with `/./` or `/../`
- Unicode normalization prevents homoglyph attacks
- URL parsing validates structure before checking content
- Allowlist for URL schemes prevents `file://`, `javascript:` etc.
- SSRF protection by rejecting internal hostnames and IPs

---

## Edge Cases Section

### Edge Case 1: Unicode Normalization Issues

```pseudocode
// DANGEROUS: Validating before normalization allows bypass

// Attack: Using decomposed Unicode characters
// "admin" can be represented as:
// - "admin" (5 ASCII characters)
// - "admin" with combining characters: "admin" + accent marks
// - Confusables: "αdmin" (Greek alpha), "аdmin" (Cyrillic a)

function vulnerableUsernameCheck(input):
    if input == "admin":
        return "Cannot register as admin"
    return "OK"

// Attacker uses: "аdmin" (Cyrillic 'а' looks like Latin 'a')
vulnerableUsernameCheck("аdmin")  // Returns "OK"
// But displays as "admin" in UI!

// SECURE: Normalize and check for confusables
function secureUsernameCheck(input):
    // Step 1: Unicode normalize to NFC
    normalized = unicodeNormalize(input, "NFC")

    // Step 2: Convert confusables to ASCII equivalent
    ascii = convertConfusablesToAscii(normalized)

    // Step 3: Check reserved names against ASCII version
    reservedNames = ["admin", "root", "system", "administrator", "support"]
    if ascii.toLowerCase() in reservedNames:
        return {valid: false, error: "Reserved username"}

    // Step 4: Only allow safe character set
    if not isAsciiAlphanumeric(input):
        return {valid: false, error: "Username must be ASCII letters and numbers"}

    return {valid: true, value: normalized}
```

**Detection:** Test with Unicode confusables for admin/root, combining characters, zero-width characters.

---

### Edge Case 2: Null Byte Injection

```pseudocode
// DANGEROUS: Null bytes can truncate strings in some languages

// Filename validation bypass with null byte
filename = "malicious.php\x00.jpg"

// In C/PHP, strcmp might only see "malicious.php\x00"
// The ".jpg" is ignored
if filename.endsWith(".jpg"):
    uploadFile(filename)  // Allows .php upload!

// Path validation bypass
path = "/safe/directory/../../etc/passwd\x00/safe/suffix"
// Validation sees: ends with "/safe/suffix" - looks OK
// File system sees: "/etc/passwd"

// SECURE: Strip null bytes first
function sanitizeInput(input):
    // Remove null bytes entirely
    sanitized = input.replace("\x00", "")

    // Also remove other control characters
    sanitized = removeControlCharacters(sanitized)

    return sanitized

function validateFilename(input):
    sanitized = sanitizeInput(input)

    // Now validate
    if sanitized != input:
        return {valid: false, error: "Invalid characters in filename"}

    // Continue with extension validation
    // ...
```

**Detection:** Test all string inputs with embedded null bytes (`\x00`, `%00`).

---

### Edge Case 3: Type Confusion

```pseudocode
// DANGEROUS: Loose type comparison leads to bypass

// JavaScript/PHP style loose comparison
function vulnerableAuth(password):
    storedHash = "0e123456789"  // Some MD5 hashes start with "0e"
    inputHash = md5(password)

    // In PHP: "0e123456789" == "0e987654321" is TRUE!
    // Both are interpreted as 0 * 10^(number) = 0
    if inputHash == storedHash:  // Loose comparison
        return "Authenticated"
    return "Failed"

// Type confusion with arrays
function vulnerablePasswordReset(token):
    // Expected: token = "abc123def456"
    // Attack: token = {"$gt": ""}  (MongoDB injection via type confusion)

    if database.findOne({"resetToken": token}):
        return "Token found"

// SECURE: Strict type checking
function secureAuth(password):
    storedHash = getStoredHash(user)
    inputHash = hashPassword(password)

    // Strict comparison and constant-time
    if typeof(inputHash) != "string" or typeof(storedHash) != "string":
        return "Failed"

    if not constantTimeEquals(inputHash, storedHash):
        return "Failed"

    return "Authenticated"

function securePasswordReset(token):
    // Enforce string type
    if typeof(token) != "string":
        return {valid: false, error: "Invalid token format"}

    // Validate format
    if not regex.match("^[a-f0-9]{64}$", token):
        return {valid: false, error: "Invalid token format"}

    // Now safe to query
    result = database.findOne({"resetToken": token})
    // ...
```

**Detection:** Test with different types: arrays, objects, numbers, booleans where strings expected.

---

### Edge Case 4: Integer Overflow in Validation

```pseudocode
// DANGEROUS: Validation passes but computation overflows

function vulnerablePurchase(quantity, price):
    // Validate ranges
    if quantity < 0 or quantity > 1000000:
        return error("Invalid quantity")
    if price < 0 or price > 1000000:
        return error("Invalid price")

    // Both pass validation, but multiplication overflows!
    // quantity = 999999, price = 999999
    // total = 999998000001 (exceeds 32-bit integer)
    total = quantity * price  // OVERFLOW

    chargeCustomer(total)  // May wrap to negative or small number

// SECURE: Check for overflow in computation
function securePurchase(quantity, price):
    // Validate individual ranges
    if not isValidInteger(quantity, 1, 1000):
        return error("Invalid quantity")
    if not isValidInteger(price, 1, 10000000):  // in cents
        return error("Invalid price")

    // Check multiplication won't overflow
    MAX_SAFE_TOTAL = 2147483647  // 32-bit signed max

    if quantity > MAX_SAFE_TOTAL / price:
        return error("Order total too large")

    total = quantity * price  // Now safe

    // Additional business validation
    if total > MAX_ALLOWED_TRANSACTION:
        return error("Transaction exceeds limit")

    chargeCustomer(total)

// Alternative: Use arbitrary precision arithmetic for money
function securePurchaseWithDecimal(quantity, price):
    quantityDecimal = Decimal(quantity)
    priceDecimal = Decimal(price)

    total = quantityDecimal * priceDecimal  // No overflow

    if total > Decimal(MAX_ALLOWED_TRANSACTION):
        return error("Transaction exceeds limit")

    chargeCustomer(total)
```

**Detection:** Test with MAX_INT, MAX_INT-1, boundary values, and combinations that multiply to overflow.

---

## Common Mistakes Section

### Common Mistake 1: Validating Formatted Output Instead of Input

```pseudocode
// WRONG: Validate after formatting
function displayUserData(userId):
    userData = database.getUser(userId)  // Raw from DB

    // Format for display
    formattedName = formatName(userData.name)
    formattedBio = formatBio(userData.bio)

    // Validating AFTER format - too late!
    if containsHtml(formattedName):  // Already formatted/escaped
        return error("Invalid name")

    return template.render(formattedName, formattedBio)

// CORRECT: Validate at input, encode at output
function saveUserData(request):
    name = request.body.name
    bio = request.body.bio

    // Validate raw input BEFORE storing
    if not isValidName(name):
        return error("Invalid name")

    if containsDangerousPatterns(bio):
        return error("Invalid bio content")

    // Store validated (but not encoded) data
    database.saveUser({"name": name, "bio": bio})

function displayUserData(userId):
    userData = database.getUser(userId)

    // Encode for output context (don't validate again)
    return template.render({
        "name": htmlEncode(userData.name),
        "bio": htmlEncode(userData.bio)
    })
```

**Why This Is Wrong:**
- Validation should happen at input boundary, not output
- Formatted/encoded data may pass validation but still be dangerous
- Encoding should happen at output, specific to context
- Validation after formatting is security theater

---

### Common Mistake 2: Using String Operations on Binary Data

```pseudocode
// WRONG: String operations on binary data
function processUploadedImage(fileContent):
    // Convert binary to string - CORRUPTS DATA
    contentString = fileContent.toString("utf-8")

    // String operations fail on binary
    if contentString.startsWith("\x89PNG"):  // May not work correctly
        processImage(contentString)  // Corrupted!

    // Regex on binary data is meaningless
    if regex.match("<script>", contentString):  // False sense of security
        return error("Invalid image")

// CORRECT: Use binary operations for binary data
function processUploadedImage(fileContent):
    // Keep as binary buffer
    buffer = fileContent  // Raw bytes

    // Check magic bytes using binary comparison
    PNG_MAGIC = bytes([0x89, 0x50, 0x4E, 0x47])  // \x89PNG
    JPEG_MAGIC = bytes([0xFF, 0xD8, 0xFF])

    if buffer.slice(0, 4) == PNG_MAGIC:
        imageType = "png"
    else if buffer.slice(0, 3) == JPEG_MAGIC:
        imageType = "jpeg"
    else:
        return error("Unsupported image format")

    // Use dedicated image library for validation
    try:
        image = imageLibrary.load(buffer)

        // Validate image properties
        if image.width > MAX_WIDTH or image.height > MAX_HEIGHT:
            return error("Image too large")

        // Re-encode image (strips any embedded code)
        cleanBuffer = imageLibrary.encode(image, imageType)
        return {valid: true, content: cleanBuffer}

    catch ImageError:
        return error("Invalid image file")
```

**Why This Is Wrong:**
- UTF-8 decoding corrupts binary data with invalid sequences
- String operations assume text encoding that doesn't apply
- Regex cannot meaningfully match binary patterns
- Magic byte checks should use binary comparison

---

### Common Mistake 3: Inconsistent Validation Across Endpoints

```pseudocode
// WRONG: Different validation in different places
// API Endpoint 1: Strict validation
function createUserApi(request):
    if not isValidEmail(request.email):
        return error("Invalid email")
    if not isStrongPassword(request.password):
        return error("Weak password")
    createUser(request.email, request.password)

// API Endpoint 2: No validation (developer forgot)
function createUserFromOAuth(oauthData):
    // Trust OAuth provider's email
    createUser(oauthData.email, generateRandomPassword())

// Internal function: Also no validation (assumes callers validated)
function createUserInternal(email, password):
    // Directly insert to database - SQL injection if email not validated upstream
    query = "INSERT INTO users (email, password) VALUES ('" + email + "', ?)"
    database.execute(query, [password])

// CORRECT: Centralized validation
class UserValidator:
    function validateEmail(email):
        if email is null or email is empty:
            throw ValidationError("Email required")
        if length(email) > 254:
            throw ValidationError("Email too long")
        if not regex.match(EMAIL_PATTERN, email):
            throw ValidationError("Invalid email format")
        return email.toLowerCase().trim()

    function validatePassword(password):
        // ... password validation
        return password

    function validateUserData(data):
        return {
            "email": this.validateEmail(data.email),
            "password": this.validatePassword(data.password)
        }

// Single creation function used by all endpoints
function createUser(data):
    validated = UserValidator.validateUserData(data)

    // Now safe to use parameterized query
    query = "INSERT INTO users (email, password) VALUES (?, ?)"
    database.execute(query, [validated.email, hashPassword(validated.password)])

// All endpoints use the same function
function createUserApi(request):
    createUser(request.body)

function createUserFromOAuth(oauthData):
    createUser({"email": oauthData.email, "password": generateRandomPassword()})
```

**Why This Is Wrong:**
- Multiple code paths = multiple places to forget validation
- Different validation rules cause inconsistent security posture
- Internal functions shouldn't trust callers validated correctly
- Centralized validation ensures consistent security

---

## Validation Framework Patterns

### Pattern 1: Layered Validation Architecture

```pseudocode
// Layer 1: Transport-level validation (before application code)
// - Request size limits
// - Content-Type checking
// - Rate limiting
// Typically configured in web server/framework

// Layer 2: Schema validation (structure and types)
function validateSchema(data, schema):
    return schemaValidator.validate(data, schema)

// Layer 3: Format validation (syntax)
function validateFormats(data):
    errors = []
    if data.email and not isValidEmailFormat(data.email):
        errors.append("Invalid email format")
    if data.url and not isValidUrl(data.url):
        errors.append("Invalid URL format")
    return errors

// Layer 4: Business rule validation (semantics)
function validateBusinessRules(data, context):
    errors = []
    if data.endDate < data.startDate:
        errors.append("End date must be after start date")
    if data.quantity > context.inventory.available:
        errors.append("Insufficient inventory")
    return errors

// Orchestration
function validateRequest(request, schema, context):
    // Layer 2: Schema
    schemaResult = validateSchema(request.body, schema)
    if not schemaResult.valid:
        return {valid: false, errors: schemaResult.errors, layer: "schema"}

    // Layer 3: Format
    formatErrors = validateFormats(request.body)
    if formatErrors.length > 0:
        return {valid: false, errors: formatErrors, layer: "format"}

    // Layer 4: Business rules
    businessErrors = validateBusinessRules(request.body, context)
    if businessErrors.length > 0:
        return {valid: false, errors: businessErrors, layer: "business"}

    return {valid: true, data: request.body}
```

### Pattern 2: Validation Pipeline with Short-Circuit

```pseudocode
// Define validators as composable functions
validators = [
    (data) => checkRequired(data, ["email", "password"]),
    (data) => checkTypes(data, {email: "string", password: "string"}),
    (data) => checkLength(data.email, 1, 254),
    (data) => checkLength(data.password, 12, 128),
    (data) => checkFormat(data.email, EMAIL_PATTERN),
    (data) => checkPasswordStrength(data.password),
    (data) => checkEmailNotRegistered(data.email)  // Async/DB check
]

function validatePipeline(data, validators):
    for validator in validators:
        result = validator(data)
        if not result.valid:
            return result  // Short-circuit on first failure
    return {valid: true, data: data}

// Usage
result = validatePipeline(requestData, validators)
if not result.valid:
    return error(result.message)
processValidatedData(result.data)
```

### Pattern 3: Declarative Field Validation

```pseudocode
// Define validation rules per field
FIELD_RULES = {
    "email": {
        required: true,
        type: "string",
        maxLength: 254,
        format: "email",
        transform: (v) => v.toLowerCase().trim()
    },
    "age": {
        required: true,
        type: "integer",
        min: 0,
        max: 150
    },
    "role": {
        required: true,
        type: "string",
        enum: ["user", "admin", "moderator"]
    },
    "tags": {
        required: false,
        type: "array",
        items: {
            type: "string",
            maxLength: 50,
            pattern: "^[a-z0-9-]+$"
        },
        maxItems: 10
    }
}

function validateFields(data, rules):
    result = {}
    errors = []

    for fieldName, fieldRules in rules:
        value = data[fieldName]

        // Required check
        if fieldRules.required and (value is null or value is undefined):
            errors.append({field: fieldName, message: "Required"})
            continue

        // Skip optional empty fields
        if value is null or value is undefined:
            continue

        // Type check
        if typeof(value) != fieldRules.type:
            errors.append({field: fieldName, message: "Invalid type"})
            continue

        // Apply transform if exists
        if fieldRules.transform:
            value = fieldRules.transform(value)

        // Range/length checks based on type
        error = validateFieldConstraints(value, fieldRules)
        if error:
            errors.append({field: fieldName, message: error})
            continue

        result[fieldName] = value

    if errors.length > 0:
        return {valid: false, errors: errors}
    return {valid: true, data: result}
```

---

## Detection Hints: How to Spot Missing Validation

### Code Review Patterns

```pseudocode
// 1. Request body used directly without validation
request.body.xxx      // Search for: request\.body\.\w+
req.params.xxx        // Search for: req\.params\.\w+
request.query.xxx     // Search for: request\.query\.\w+

// 2. Missing null checks before property access
user.profile.address  // Search for: \w+\.\w+\.\w+ (chained access without ?.)
data.items[0]         // Search for: \w+\[\d+\] (hardcoded array index)

// 3. Type coercion without validation
parseInt(xxx)         // Search for: parseInt\([^,]+\) (no radix)
Number(xxx)           // Search for: Number\(\w+
parseFloat(xxx)       // Without subsequent isNaN check

// 4. Regex without anchors
/pattern/             // Search for: /[^/^][^$]+[^$/]/ (no ^ or $)
new RegExp("xxx")     // Search for: new RegExp\("[^^]

// 5. Client-side validation only
if (form.valid)       // Look for validation in frontend, missing in backend
validate()            // In JS files, search corresponding backend endpoint

// 6. Array access from user input
array[userInput]      // Search for: \[\w+\.\w+\] (property access with user data)
object[key]           // Where key comes from request

// GREP patterns for security review:
// request\.(body|params|query)\.\w+
// parseInt\([^,)]+\)(?!\s*,\s*10)
// \.\w+\.\w+\.\w+(?!\?)
// /[^/]+/(?!.*[^\\]\$)
```

### Testing Patterns

```pseudocode
// Automated validation testing checklist:

// 1. Boundary testing
- Test with null, undefined, empty string for all fields
- Test with max length + 1 characters
- Test with min - 1 and max + 1 for numeric ranges
- Test with integer overflow values (2^31, 2^32, 2^64)

// 2. Type confusion testing
- Send array where string expected: {"email": ["test@test.com"]}
- Send object where string expected: {"email": {"$gt": ""}}
- Send number where string expected: {"email": 12345}
- Send boolean where string expected: {"email": true}

// 3. Encoding bypass testing
- URL encoding: %00, %2e%2e%2f
- Unicode encoding: \u0000, \u002e
- Double encoding: %2500
- Mixed case: %2E%2e%2F

// 4. Injection payload testing
- SQL: ' OR '1'='1, '; DROP TABLE users; --
- Command: ; ls, | cat /etc/passwd, `whoami`
- Path: ../../../etc/passwd, ....//....//
- XSS: <script>alert(1)</script>, javascript:alert(1)

// 5. ReDoS testing
- For each regex, test with pattern: (valid_char * 30) + invalid_char
- Measure response time - should be < 100ms
- Exponential time indicates ReDoS vulnerability
```

---

## Security Checklist

- [ ] All user input validated on the server side (never trust client-side only)
- [ ] Schema validation enforces expected structure (`additionalProperties: false`)
- [ ] All required fields checked for null/undefined/empty
- [ ] String lengths validated with reasonable maximums (prevents DoS)
- [ ] Numeric values validated for type, range, and overflow potential
- [ ] Arrays validated for max length and item constraints
- [ ] Enum fields validated against explicit allowlist
- [ ] All regex patterns anchored with `^` and `$`
- [ ] Regex patterns tested for ReDoS vulnerability
- [ ] Length checked BEFORE regex matching (ReDoS mitigation)
- [ ] Timeout protection on regex operations (defense in depth)
- [ ] Unicode input normalized before validation (NFC/NFKC)
- [ ] Null bytes (`\x00`, `%00`) rejected in string input
- [ ] Path inputs canonicalized and validated against allowed directories
- [ ] URL inputs parsed and validated (scheme, host, no credentials)
- [ ] File uploads validated by both extension AND content type
- [ ] Integer arithmetic checked for overflow before computation
- [ ] Type coercion explicit with proper error handling
- [ ] Validation consistent across all endpoints (centralized validators)
- [ ] Error messages helpful but don't leak validation logic details
- [ ] Validation rules documented and version controlled
- [ ] Validation tested with fuzzing and boundary values

---

# Executive Summary
