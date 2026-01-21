# Improper Output Encoding (Context-Specific)


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
