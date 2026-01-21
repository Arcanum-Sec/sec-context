# XPath Injection


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
