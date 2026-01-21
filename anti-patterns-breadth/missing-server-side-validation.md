# Missing Server-Side Validation (Client-Only)


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Client-side only validation
// ========================================
// Frontend JavaScript
FUNCTION validate_form_client_only():
    email = document.getElementById("email").value
    age = document.getElementById("age").value

    IF NOT email.includes("@"):
        show_error("Invalid email")
        RETURN FALSE
    END IF

    IF age < 0 OR age > 150:
        show_error("Invalid age")
        RETURN FALSE
    END IF

    // Form submits if client-side validation passes
    form.submit()
END FUNCTION

// Backend - NO validation!
FUNCTION create_user(request):
    // Vulnerable: Trusts client-side validation completely
    email = request.body.email
    age = request.body.age

    database.insert("users", {email: email, age: age})
    RETURN {success: TRUE}
END FUNCTION

// Attack: Attacker bypasses JavaScript with direct HTTP request
// curl -X POST /api/users -d '{"email":"not-an-email","age":-999}'
// Result: Invalid data stored in database

// ========================================
// GOOD: Server-side validation (client-side is UX only)
// ========================================
// Backend - validates everything
FUNCTION create_user(request):
    // Validate all input server-side
    validation_errors = []

    // Email validation
    email = request.body.email
    IF typeof(email) != "string":
        validation_errors.append("Email must be a string")
    ELSE IF NOT regex.match("^[^@]+@[^@]+\.[^@]+$", email):
        validation_errors.append("Invalid email format")
    ELSE IF email.length > 254:
        validation_errors.append("Email too long")
    END IF

    // Age validation
    age = request.body.age
    IF typeof(age) != "number" OR NOT is_integer(age):
        validation_errors.append("Age must be an integer")
    ELSE IF age < 0 OR age > 150:
        validation_errors.append("Age must be between 0 and 150")
    END IF

    IF validation_errors.length > 0:
        RETURN {success: FALSE, errors: validation_errors}
    END IF

    // Safe to process validated data
    database.insert("users", {email: email, age: age})
    RETURN {success: TRUE}
END FUNCTION

// Client-side validation is still useful for UX (immediate feedback)
// but NEVER rely on it for security
```
