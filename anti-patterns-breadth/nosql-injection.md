# NoSQL Injection


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
