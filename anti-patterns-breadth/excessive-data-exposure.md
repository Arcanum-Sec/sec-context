# Excessive Data Exposure


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Exposing too much data in API responses
// ========================================

// Returns entire user object including sensitive fields
@route("/api/users/{user_id}")
@require_auth
FUNCTION get_user(request, user_id):
    user = database.get_user(user_id)
    RETURN response(200, user)  // Includes password_hash, SSN, internal_notes!
END FUNCTION

// Returns all columns from database
@route("/api/orders")
@require_auth
FUNCTION get_orders(request):
    orders = database.query("SELECT * FROM orders WHERE user_id = ?",
                           [request.user.id])
    RETURN response(200, orders)  // Includes internal pricing, profit margins
END FUNCTION

// Exposes related entities without filtering
@route("/api/products/{id}")
FUNCTION get_product(request, id):
    product = database.get_product_with_relations(id)
    RETURN response(200, product)  // Includes supplier.contact, supplier.cost
END FUNCTION

// Debug info in production responses
@route("/api/search")
FUNCTION search(request):
    results = database.search(request.query.q)
    RETURN response(200, {
        results: results,
        query_time_ms: results.execution_time,
        sql_query: results.raw_query,  // Exposes DB schema!
        server_id: SERVER_ID
    })
END FUNCTION

// ========================================
// GOOD: Response filtering and DTOs
// ========================================

// Define response schemas
CLASS UserPublicResponse:
    id: UUID
    name: String
    avatar_url: String
    created_at: DateTime

    FUNCTION from_user(user):
        RETURN {
            id: user.id,
            name: user.name,
            avatar_url: user.avatar_url,
            created_at: user.created_at
        }
    END FUNCTION
END CLASS

CLASS UserPrivateResponse:  // For the user themselves
    id: UUID
    name: String
    email: String
    phone: String (masked)
    avatar_url: String
    created_at: DateTime
    preferences: Object

    FUNCTION from_user(user):
        RETURN {
            id: user.id,
            name: user.name,
            email: user.email,
            phone: mask_phone(user.phone),  // Show only last 4 digits
            avatar_url: user.avatar_url,
            created_at: user.created_at,
            preferences: user.preferences
        }
    END FUNCTION
END CLASS

@route("/api/users/{user_id}")
@require_auth
FUNCTION get_user_filtered(request, user_id):
    user = database.get_user(user_id)

    IF user IS NULL:
        RETURN response(404, {error: "User not found"})
    END IF

    // Different responses based on who's requesting
    IF user_id == request.user.id:
        RETURN response(200, UserPrivateResponse.from_user(user))
    ELSE:
        RETURN response(200, UserPublicResponse.from_user(user))
    END IF
END FUNCTION

// Explicit field selection in queries
@route("/api/orders")
@require_auth
FUNCTION get_orders_filtered(request):
    // Only select fields needed for the response
    orders = database.query(
        "SELECT id, status, total, created_at, shipping_address " +
        "FROM orders WHERE user_id = ?",
        [request.user.id]
    )

    RETURN response(200, {
        orders: orders.map(order => OrderResponse.from_order(order))
    })
END FUNCTION

// Filter nested relations
CLASS ProductResponse:
    id: UUID
    name: String
    description: String
    price: Decimal
    category: String
    images: Array
    average_rating: Float
    // Excludes: cost, supplier, profit_margin, internal_notes

    FUNCTION from_product(product):
        RETURN {
            id: product.id,
            name: product.name,
            description: product.description,
            price: product.price,
            category: product.category.name,  // Only category name
            images: product.images.map(i => i.url),  // Only URLs
            average_rating: product.average_rating
        }
    END FUNCTION
END CLASS

// GraphQL field filtering
FUNCTION resolve_user(parent, args, context):
    user = database.get_user(args.id)

    // Check each requested field
    allowed_fields = get_allowed_fields(context.user, user)

    result = {}
    FOR field IN context.requested_fields:
        IF field IN allowed_fields:
            result[field] = user[field]
        ELSE:
            result[field] = NULL  // Or omit entirely
        END IF
    END FOR

    RETURN result
END FUNCTION

// Never expose internal debugging info
@route("/api/search")
FUNCTION search_safe(request):
    results = database.search(request.query.q)

    RETURN response(200, {
        results: results.items.map(item => item.to_public_dict()),
        total: results.total_count,
        page: results.page
        // No query_time_ms, sql_query, or server_id
    })
END FUNCTION

// Pagination to prevent data dumping
@route("/api/users")
@require_admin
FUNCTION list_users(request):
    page = INT(request.query.page, default=1)
    per_page = MIN(INT(request.query.per_page, default=20), 100)  // Max 100

    users = database.paginate("users", page, per_page)

    RETURN response(200, {
        users: users.map(u => UserAdminResponse.from_user(u)),
        pagination: {
            page: page,
            per_page: per_page,
            total_pages: users.total_pages,
            total_count: users.total_count
        }
    })
END FUNCTION
```
