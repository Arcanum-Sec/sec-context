# Mass Assignment Vulnerabilities


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Mass assignment - accepting all user input
// ========================================

// Attacker sends: {"name": "John", "role": "admin", "balance": 999999}
@route("/api/users/update")
@require_auth
FUNCTION update_user(request):
    // VULNERABLE: Directly assigns all request body fields
    user = database.get_user(request.user.id)

    FOR field, value IN request.body:
        user[field] = value  // Attacker can set ANY field!
    END FOR

    database.save(user)
    RETURN response(200, user)
END FUNCTION

// ORM auto-mapping vulnerability
@route("/api/users")
@require_auth
FUNCTION create_user(request):
    // VULNERABLE: ORM creates user from all request fields
    user = User.create(request.body)  // Includes role, isAdmin, etc.!
    RETURN response(201, user)
END FUNCTION

// Nested object mass assignment
@route("/api/orders")
@require_auth
FUNCTION create_order(request):
    // VULNERABLE: Nested payment object can set price
    order = Order.create({
        user_id: request.user.id,
        items: request.body.items,
        payment: request.body.payment  // Attacker sets payment.amount = 0
    })
    RETURN response(201, order)
END FUNCTION

// ========================================
// GOOD: Explicit field allowlisting
// ========================================

// Define what fields can be updated
CONSTANT USER_UPDATABLE_FIELDS = ["name", "email", "phone", "address"]
CONSTANT USER_ADMIN_FIELDS = ["role", "status", "verified"]

@route("/api/users/update")
@require_auth
FUNCTION update_user_secure(request):
    user = database.get_user(request.user.id)

    // SECURE: Only update explicitly allowed fields
    FOR field IN USER_UPDATABLE_FIELDS:
        IF field IN request.body:
            user[field] = sanitize(request.body[field])
        END IF
    END FOR

    database.save(user)

    // Return only safe fields
    RETURN response(200, user.to_public_dict())
END FUNCTION

// Admin with different field permissions
@route("/api/admin/users/{user_id}")
@require_admin
FUNCTION admin_update_user(request, user_id):
    user = database.get_user(user_id)

    // Admins can update more fields, but still allowlisted
    allowed_fields = USER_UPDATABLE_FIELDS + USER_ADMIN_FIELDS

    FOR field IN allowed_fields:
        IF field IN request.body:
            user[field] = request.body[field]
        END IF
    END FOR

    log.audit("Admin user update", {
        admin_id: request.user.id,
        user_id: user_id,
        fields_changed: request.body.keys()
    })

    database.save(user)
    RETURN response(200, user)
END FUNCTION

// Use DTOs (Data Transfer Objects) for input
CLASS UserUpdateDTO:
    name: String (max_length=100)
    email: String (email_format, max_length=255)
    phone: String (phone_format, optional)
    address: String (max_length=500, optional)

    FUNCTION from_request(body):
        dto = UserUpdateDTO()
        dto.name = validate_string(body.name, max_length=100)
        dto.email = validate_email(body.email)
        dto.phone = validate_phone(body.phone) IF body.phone ELSE NULL
        dto.address = validate_string(body.address, max_length=500) IF body.address ELSE NULL
        RETURN dto
    END FUNCTION
END CLASS

@route("/api/users/update")
@require_auth
FUNCTION update_user_dto(request):
    TRY:
        dto = UserUpdateDTO.from_request(request.body)
    CATCH ValidationError as e:
        RETURN response(400, {error: e.message})
    END TRY

    user = database.get_user(request.user.id)
    user.apply_dto(dto)  // Only applies DTO fields
    database.save(user)

    RETURN response(200, user.to_public_dict())
END FUNCTION

// Nested objects with strict validation
CLASS OrderCreateDTO:
    items: Array of OrderItemDTO
    shipping_address_id: UUID
    // payment calculated server-side, NOT from request

    FUNCTION from_request(body, user):
        dto = OrderCreateDTO()
        dto.items = [OrderItemDTO.from_request(item) FOR item IN body.items]

        // Verify address belongs to user
        address = database.get_address(body.shipping_address_id)
        IF address IS NULL OR address.user_id != user.id:
            THROW ValidationError("Invalid shipping address")
        END IF
        dto.shipping_address_id = address.id

        RETURN dto
    END FUNCTION
END CLASS

@route("/api/orders")
@require_auth
FUNCTION create_order_secure(request):
    dto = OrderCreateDTO.from_request(request.body, request.user)

    // Calculate payment server-side from validated items
    total = 0
    FOR item IN dto.items:
        product = database.get_product(item.product_id)
        total += product.price * item.quantity  // Price from DB, not request!
    END FOR

    order = Order.create({
        user_id: request.user.id,
        items: dto.items,
        shipping_address_id: dto.shipping_address_id,
        total: total  // Server-calculated
    })

    RETURN response(201, order.to_dict())
END FUNCTION
```
