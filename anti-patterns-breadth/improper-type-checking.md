# Improper Type Checking


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Missing or weak type validation
// ========================================
FUNCTION process_payment_weak(request):
    amount = request.body.amount
    quantity = request.body.quantity

    // Vulnerable: No type checking
    total = amount * quantity

    // What if amount = "100" (string)? JavaScript: "100" * 2 = 200 (coerced)
    // What if amount = [100]? Some languages coerce arrays unexpectedly
    // What if quantity = {"$gt": 0}? NoSQL injection possible

    charge_card(user, total)
END FUNCTION

FUNCTION get_user_weak(request):
    user_id = request.params.id

    // Vulnerable: ID could be array, object, or unexpected type
    // MongoDB: ?id[$ne]=null returns all users!
    RETURN database.find_one({id: user_id})
END FUNCTION

FUNCTION calculate_discount_weak(price, discount_percent):
    // Vulnerable: No validation of numeric types
    // discount_percent = "50" → string concatenation in some languages
    // discount_percent = NaN → NaN propagates through calculations
    final_price = price - (price * discount_percent / 100)
    RETURN final_price
END FUNCTION

// ========================================
// GOOD: Strict type validation
// ========================================
FUNCTION process_payment_safe(request):
    // Validate amount
    amount = request.body.amount
    IF typeof(amount) != "number":
        THROW ValidationError("Amount must be a number")
    END IF
    IF NOT is_finite(amount) OR is_nan(amount):
        THROW ValidationError("Amount must be a valid number")
    END IF
    IF amount <= 0:
        THROW ValidationError("Amount must be positive")
    END IF

    // Validate quantity
    quantity = request.body.quantity
    IF typeof(quantity) != "number" OR NOT is_integer(quantity):
        THROW ValidationError("Quantity must be an integer")
    END IF
    IF quantity <= 0 OR quantity > 1000:
        THROW ValidationError("Quantity must be between 1 and 1000")
    END IF

    // Safe to calculate
    total = amount * quantity

    // Additional: Prevent floating point issues with currency
    total_cents = round(total * 100)  // Work in cents
    charge_card(user, total_cents)
END FUNCTION

FUNCTION get_user_safe(request):
    user_id = request.params.id

    // Strict type checking
    IF typeof(user_id) != "string":
        THROW ValidationError("User ID must be a string")
    END IF

    // Format validation (e.g., UUID)
    IF NOT is_valid_uuid(user_id):
        THROW ValidationError("Invalid user ID format")
    END IF

    RETURN database.find_one({id: user_id})
END FUNCTION

// Type coercion helper with explicit validation
FUNCTION parse_integer_strict(value, min, max):
    IF typeof(value) == "number":
        IF NOT is_integer(value):
            THROW ValidationError("Expected integer, got float")
        END IF
        result = value
    ELSE IF typeof(value) == "string":
        IF NOT regex.match("^-?[0-9]+$", value):
            THROW ValidationError("Invalid integer format")
        END IF
        result = parse_int(value)
    ELSE:
        THROW ValidationError("Expected number or numeric string")
    END IF

    IF result < min OR result > max:
        THROW ValidationError("Value out of range: " + min + " to " + max)
    END IF

    RETURN result
END FUNCTION
```
