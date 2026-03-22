<!-- Source: Arcanum sec-context (https://github.com/arcanum-sec/sec-context), CC BY 4.0, Jason Haddix / Arcanum Information Security -->

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
