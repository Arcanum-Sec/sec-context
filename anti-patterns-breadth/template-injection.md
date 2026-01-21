# Template Injection (SSTI)


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
