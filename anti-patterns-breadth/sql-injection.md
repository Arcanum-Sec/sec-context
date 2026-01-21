# SQL Injection (String Concatenation in Queries)


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
