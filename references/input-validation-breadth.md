<!-- Source: Arcanum sec-context (https://github.com/arcanum-sec/sec-context), CC BY 4.0, Jason Haddix / Arcanum Information Security -->

## 6. Input Validation

**CWE References:** CWE-20 (Improper Input Validation), CWE-1284 (Improper Validation of Specified Quantity in Input), CWE-1333 (Inefficient Regular Expression Complexity), CWE-22 (Path Traversal), CWE-180 (Incorrect Behavior Order: Validate Before Canonicalize)
**Severity:** High | **Related:** [[Input-Validation]]

> **Risk:** Input validation failures are a foundational vulnerability enabling most other attack classes. AI-generated code frequently relies solely on client-side validation (trivially bypassed) or omits validation entirely. Missing length limits enable DoS attacks, improper type checking allows type confusion attacks, and ReDoS patterns can freeze services. All user input must be validated on the server with type, length, format, and range constraints.

### 6.1 Missing Server-Side Validation (Client-Only)

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Client-side only validation
// ========================================
// Frontend JavaScript
FUNCTION validate_form_client_only():
    email = document.getElementById("email").value
    age = document.getElementById("age").value

    IF NOT email.includes("@"):
        show_error("Invalid email")
        RETURN FALSE
    END IF

    IF age < 0 OR age > 150:
        show_error("Invalid age")
        RETURN FALSE
    END IF

    // Form submits if client-side validation passes
    form.submit()
END FUNCTION

// Backend - NO validation!
FUNCTION create_user(request):
    // Vulnerable: Trusts client-side validation completely
    email = request.body.email
    age = request.body.age

    database.insert("users", {email: email, age: age})
    RETURN {success: TRUE}
END FUNCTION

// Attack: Attacker bypasses JavaScript with direct HTTP request
// curl -X POST /api/users -d '{"email":"not-an-email","age":-999}'
// Result: Invalid data stored in database

// ========================================
// GOOD: Server-side validation (client-side is UX only)
// ========================================
// Backend - validates everything
FUNCTION create_user(request):
    // Validate all input server-side
    validation_errors = []

    // Email validation
    email = request.body.email
    IF typeof(email) != "string":
        validation_errors.append("Email must be a string")
    ELSE IF NOT regex.match("^[^@]+@[^@]+\.[^@]+$", email):
        validation_errors.append("Invalid email format")
    ELSE IF email.length > 254:
        validation_errors.append("Email too long")
    END IF

    // Age validation
    age = request.body.age
    IF typeof(age) != "number" OR NOT is_integer(age):
        validation_errors.append("Age must be an integer")
    ELSE IF age < 0 OR age > 150:
        validation_errors.append("Age must be between 0 and 150")
    END IF

    IF validation_errors.length > 0:
        RETURN {success: FALSE, errors: validation_errors}
    END IF

    // Safe to process validated data
    database.insert("users", {email: email, age: age})
    RETURN {success: TRUE}
END FUNCTION

// Client-side validation is still useful for UX (immediate feedback)
// but NEVER rely on it for security
```

### 6.2 Improper Type Checking

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Missing or weak type validation
// ========================================
FUNCTION process_payment_weak(request):
    amount = request.body.amount
    quantity = request.body.quantity

    // Vulnerable: No type checking
    total = amount * quantity

    // What if amount = "100" (string)? JavaScript: "100" * 2 = 200 (coerced)
    // What if amount = [100]? Some languages coerce arrays unexpectedly
    // What if quantity = {"$gt": 0}? NoSQL injection possible

    charge_card(user, total)
END FUNCTION

FUNCTION get_user_weak(request):
    user_id = request.params.id

    // Vulnerable: ID could be array, object, or unexpected type
    // MongoDB: ?id[$ne]=null returns all users!
    RETURN database.find_one({id: user_id})
END FUNCTION

FUNCTION calculate_discount_weak(price, discount_percent):
    // Vulnerable: No validation of numeric types
    // discount_percent = "50" → string concatenation in some languages
    // discount_percent = NaN → NaN propagates through calculations
    final_price = price - (price * discount_percent / 100)
    RETURN final_price
END FUNCTION

// ========================================
// GOOD: Strict type validation
// ========================================
FUNCTION process_payment_safe(request):
    // Validate amount
    amount = request.body.amount
    IF typeof(amount) != "number":
        THROW ValidationError("Amount must be a number")
    END IF
    IF NOT is_finite(amount) OR is_nan(amount):
        THROW ValidationError("Amount must be a valid number")
    END IF
    IF amount <= 0:
        THROW ValidationError("Amount must be positive")
    END IF

    // Validate quantity
    quantity = request.body.quantity
    IF typeof(quantity) != "number" OR NOT is_integer(quantity):
        THROW ValidationError("Quantity must be an integer")
    END IF
    IF quantity <= 0 OR quantity > 1000:
        THROW ValidationError("Quantity must be between 1 and 1000")
    END IF

    // Safe to calculate
    total = amount * quantity

    // Additional: Prevent floating point issues with currency
    total_cents = round(total * 100)  // Work in cents
    charge_card(user, total_cents)
END FUNCTION

FUNCTION get_user_safe(request):
    user_id = request.params.id

    // Strict type checking
    IF typeof(user_id) != "string":
        THROW ValidationError("User ID must be a string")
    END IF

    // Format validation (e.g., UUID)
    IF NOT is_valid_uuid(user_id):
        THROW ValidationError("Invalid user ID format")
    END IF

    RETURN database.find_one({id: user_id})
END FUNCTION

// Type coercion helper with explicit validation
FUNCTION parse_integer_strict(value, min, max):
    IF typeof(value) == "number":
        IF NOT is_integer(value):
            THROW ValidationError("Expected integer, got float")
        END IF
        result = value
    ELSE IF typeof(value) == "string":
        IF NOT regex.match("^-?[0-9]+$", value):
            THROW ValidationError("Invalid integer format")
        END IF
        result = parse_int(value)
    ELSE:
        THROW ValidationError("Expected number or numeric string")
    END IF

    IF result < min OR result > max:
        THROW ValidationError("Value out of range: " + min + " to " + max)
    END IF

    RETURN result
END FUNCTION
```

### 6.3 Missing Length Limits

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No length limits on input
// ========================================
FUNCTION create_post_unlimited(request):
    title = request.body.title
    content = request.body.content

    // Vulnerable: No length limits
    // Attacker sends 1GB title, exhausts memory/storage
    database.insert("posts", {title: title, content: content})
END FUNCTION

FUNCTION search_unlimited(request):
    query = request.params.q

    // Vulnerable: Long query strings can DoS search systems
    // Also enables ReDoS if query is used in regex
    results = database.search(query)
    RETURN results
END FUNCTION

FUNCTION process_file_unlimited(request):
    file_content = request.body.file

    // Vulnerable: No file size limit
    // Attacker uploads 10GB file, exhausts disk/memory
    save_file(file_content)
END FUNCTION

// Real-world DoS: JSON payload with deeply nested objects
// {"a":{"a":{"a":{"a":...}}}}  // 1000 levels deep
// Can crash parsers or exhaust stack space

// ========================================
// GOOD: Enforce length limits on all inputs
// ========================================
CONSTANT MAX_TITLE_LENGTH = 200
CONSTANT MAX_CONTENT_LENGTH = 50000
CONSTANT MAX_SEARCH_QUERY = 500
CONSTANT MAX_FILE_SIZE = 10 * 1024 * 1024  // 10MB
CONSTANT MAX_JSON_DEPTH = 20

FUNCTION create_post_limited(request):
    title = request.body.title
    content = request.body.content

    // Validate title length
    IF typeof(title) != "string":
        THROW ValidationError("Title must be a string")
    END IF
    IF title.length == 0:
        THROW ValidationError("Title is required")
    END IF
    IF title.length > MAX_TITLE_LENGTH:
        THROW ValidationError("Title exceeds " + MAX_TITLE_LENGTH + " characters")
    END IF

    // Validate content length
    IF typeof(content) != "string":
        THROW ValidationError("Content must be a string")
    END IF
    IF content.length > MAX_CONTENT_LENGTH:
        THROW ValidationError("Content exceeds " + MAX_CONTENT_LENGTH + " characters")
    END IF

    database.insert("posts", {title: title, content: content})
END FUNCTION

FUNCTION search_limited(request):
    query = request.params.q

    IF typeof(query) != "string":
        THROW ValidationError("Query must be a string")
    END IF
    IF query.length > MAX_SEARCH_QUERY:
        THROW ValidationError("Search query too long")
    END IF
    IF query.length < 2:
        THROW ValidationError("Search query too short")
    END IF

    results = database.search(query)
    RETURN results
END FUNCTION

// Configure request body limits at framework level
FUNCTION configure_server():
    server.set_body_limit(MAX_FILE_SIZE)
    server.set_json_depth_limit(MAX_JSON_DEPTH)
    server.set_parameter_limit(1000)  // Max form fields
    server.set_header_size_limit(8192)  // 8KB header limit
END FUNCTION

// Array length limits
FUNCTION process_batch_request(request):
    items = request.body.items

    IF NOT is_array(items):
        THROW ValidationError("Items must be an array")
    END IF
    IF items.length > 100:
        THROW ValidationError("Maximum 100 items per batch")
    END IF

    FOR item IN items:
        process_single_item(item)
    END FOR
END FUNCTION
```

### 6.4 Regex Denial of Service (ReDoS)

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

### 6.5 Accepting and Processing Untrusted Data

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Trusting external data sources
// ========================================
FUNCTION process_webhook_unsafe(request):
    // Vulnerable: No signature verification
    data = json.parse(request.body)

    // Attacker can spoof webhook requests
    IF data.event == "payment_completed":
        mark_order_paid(data.order_id)  // Dangerous!
    END IF
END FUNCTION

FUNCTION fetch_and_process_unsafe(url):
    // Vulnerable: Processing arbitrary external content
    response = http.get(url)
    data = json.parse(response.body)

    // No validation of response structure
    database.insert("external_data", data)
END FUNCTION

FUNCTION deserialize_unsafe(serialized_data):
    // Vulnerable: Pickle/eval deserialization of untrusted data
    // Allows arbitrary code execution!
    object = pickle.loads(serialized_data)
    RETURN object
END FUNCTION

FUNCTION process_xml_unsafe(xml_string):
    // Vulnerable: XXE (XML External Entity) attack
    parser = xml.create_parser()
    doc = parser.parse(xml_string)
    // Attacker XML: <!ENTITY xxe SYSTEM "file:///etc/passwd">
    RETURN doc
END FUNCTION

// ========================================
// GOOD: Validate and sanitize external data
// ========================================
FUNCTION process_webhook_safe(request):
    // Verify webhook signature
    signature = request.headers.get("X-Signature")
    expected = hmac_sha256(WEBHOOK_SECRET, request.raw_body)

    IF NOT constant_time_compare(signature, expected):
        log.warning("Invalid webhook signature", {ip: request.ip})
        RETURN {status: 401, error: "Invalid signature"}
    END IF

    // Validate payload structure
    data = json.parse(request.body)

    IF NOT validate_webhook_schema(data):
        RETURN {status: 400, error: "Invalid payload"}
    END IF

    // Process verified and validated data
    IF data.event == "payment_completed":
        // Additional verification: Check with payment provider
        IF verify_payment_with_provider(data.payment_id):
            mark_order_paid(data.order_id)
        END IF
    END IF
END FUNCTION

FUNCTION fetch_and_process_safe(url):
    // Validate URL is from allowed sources
    parsed_url = url_parser.parse(url)
    IF parsed_url.host NOT IN ALLOWED_HOSTS:
        THROW ValidationError("URL host not allowed")
    END IF

    // Fetch with timeout and size limits
    response = http.get(url, timeout=10, max_size=1024*1024)

    // Parse and validate structure
    TRY:
        data = json.parse(response.body)
    CATCH JSONError:
        THROW ValidationError("Invalid JSON response")
    END TRY

    // Validate against expected schema
    validated_data = validate_schema(data, EXPECTED_SCHEMA)

    // Sanitize before storing
    sanitized = sanitize_object(validated_data)
    database.insert("external_data", sanitized)
END FUNCTION

FUNCTION deserialize_safe(data, format):
    // Never use pickle/eval for untrusted data
    // Use safe serialization formats
    IF format == "json":
        RETURN json.parse(data)
    ELSE IF format == "msgpack":
        RETURN msgpack.unpack(data)
    ELSE:
        THROW Error("Unsupported format")
    END IF
END FUNCTION

FUNCTION process_xml_safe(xml_string):
    // Disable external entities and DTDs
    parser = xml.create_parser(
        resolve_entities=FALSE,
        load_dtd=FALSE,
        no_network=TRUE
    )

    TRY:
        doc = parser.parse(xml_string)
        RETURN doc
    CATCH XMLError as e:
        log.warning("XML parsing failed", {error: e.message})
        THROW ValidationError("Invalid XML")
    END TRY
END FUNCTION

// Schema validation helper
FUNCTION validate_schema(data, schema):
    // Use JSON Schema or similar validation library
    validator = JsonSchemaValidator(schema)

    IF NOT validator.is_valid(data):
        errors = validator.get_errors()
        THROW ValidationError("Schema validation failed: " + errors.join(", "))
    END IF

    RETURN data
END FUNCTION
```

### 6.6 Missing Canonicalization

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Validation without canonicalization
// ========================================
FUNCTION check_path_unsafe(requested_path):
    // Vulnerable: Path not canonicalized before validation
    IF requested_path.starts_with("/uploads/"):
        // Bypass: "../../../etc/passwd" doesn't start with /uploads/
        // But resolves to outside the directory!
        RETURN read_file(requested_path)
    END IF
    THROW AccessDenied("Invalid path")
END FUNCTION

FUNCTION check_url_unsafe(url):
    // Vulnerable: URL manipulation bypasses check
    // Blocked: "http://internal-server"
    // Bypass: "http://internal-server%00.example.com"
    // Bypass: "http://0x7f000001" (127.0.0.1 in hex)
    // Bypass: "http://localhost" vs "http://LOCALHOST" vs "http://127.0.0.1"

    IF url.contains("internal-server"):
        THROW AccessDenied("Internal URLs not allowed")
    END IF

    RETURN http.get(url)
END FUNCTION

FUNCTION validate_filename_unsafe(filename):
    // Vulnerable: Unicode normalization bypass
    // Blocked: "config.php"
    // Bypass: "config.php" with full-width characters (ｃｏｎｆｉｇ.php)
    // Bypass: "config.php\x00.txt" (null byte injection)

    IF filename.ends_with(".php"):
        THROW AccessDenied("PHP files not allowed")
    END IF

    save_file(filename)
END FUNCTION

FUNCTION check_html_unsafe(content):
    // Vulnerable: Case-sensitive blacklist
    // Blocked: "<script>"
    // Bypass: "<SCRIPT>", "<ScRiPt>", "<script ", etc.

    IF content.contains("<script>"):
        THROW AccessDenied("Scripts not allowed")
    END IF

    RETURN content
END FUNCTION

// ========================================
// GOOD: Canonicalize before validation
// ========================================
FUNCTION check_path_safe(requested_path):
    // Canonicalize path first
    base_path = path.resolve("/uploads")
    canonical_path = path.resolve(requested_path)

    // Verify canonical path is within allowed directory
    IF NOT canonical_path.starts_with(base_path):
        log.warning("Path traversal attempt", {
            requested: requested_path,
            resolved: canonical_path
        })
        THROW AccessDenied("Invalid path")
    END IF

    // Additional: Verify path doesn't contain null bytes
    IF requested_path.contains("\x00"):
        THROW AccessDenied("Invalid path characters")
    END IF

    RETURN read_file(canonical_path)
END FUNCTION

FUNCTION check_url_safe(url):
    // Parse and canonicalize URL
    TRY:
        parsed = url_parser.parse(url)
    CATCH ParseError:
        THROW AccessDenied("Invalid URL")
    END TRY

    // Normalize hostname
    host = parsed.hostname.lower()

    // Resolve to IP to catch obfuscation
    TRY:
        resolved_ip = dns.resolve(host)
    CATCH DNSError:
        THROW AccessDenied("Cannot resolve host")
    END TRY

    // Check against blocked IP ranges
    blocked_ranges = [
        "127.0.0.0/8",     // Localhost
        "10.0.0.0/8",      // Private
        "172.16.0.0/12",   // Private
        "192.168.0.0/16",  // Private
        "169.254.0.0/16"   // Link-local
    ]

    FOR range IN blocked_ranges:
        IF ip_in_range(resolved_ip, range):
            THROW AccessDenied("Internal addresses not allowed")
        END IF
    END FOR

    // Additional: Block by resolved hostname
    IF host IN BLOCKED_HOSTS:
        THROW AccessDenied("Host not allowed")
    END IF

    RETURN http.get(url)
END FUNCTION

FUNCTION validate_filename_safe(filename):
    // Remove null bytes
    clean_name = filename.replace("\x00", "")

    // Normalize Unicode (NFC form)
    normalized = unicode_normalize("NFC", clean_name)

    // Convert to ASCII-safe representation
    ascii_name = transliterate_to_ascii(normalized)

    // Extract actual extension (after normalization)
    extension = path.get_extension(ascii_name).lower()

    // Whitelist allowed extensions
    allowed_extensions = [".jpg", ".png", ".gif", ".pdf", ".txt"]
    IF extension NOT IN allowed_extensions:
        THROW AccessDenied("File type not allowed: " + extension)
    END IF

    // Generate safe filename
    safe_name = uuid() + extension
    save_file(safe_name)
END FUNCTION

FUNCTION sanitize_html_safe(content):
    // Case-insensitive checking
    lower_content = content.lower()

    // Better: Use HTML parser and whitelist approach
    parsed = html_parser.parse(content)

    // Remove all script elements regardless of case
    FOR element IN parsed.find_all("script"):
        element.remove()
    END FOR

    // Remove event handlers
    FOR element IN parsed.find_all():
        FOR attr IN element.attributes:
            IF attr.name.lower().starts_with("on"):
                element.remove_attribute(attr.name)
            END IF
        END FOR
    END FOR

    // Best: Use a sanitization library like DOMPurify
    RETURN DOMPurify.sanitize(content)
END FUNCTION

// Canonicalization order matters:
// 1. Decode (URL decode, Unicode normalize)
// 2. Canonicalize (resolve paths, lowercase hostnames)
// 3. Validate (check against rules)
// 4. Encode for output context (HTML encode, URL encode)
```

---
