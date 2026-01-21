# LDAP Injection


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
