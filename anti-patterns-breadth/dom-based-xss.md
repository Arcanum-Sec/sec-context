# DOM-Based XSS (innerHTML, document.write)


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
