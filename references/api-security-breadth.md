<!-- Source: Arcanum sec-context (https://github.com/arcanum-sec/sec-context), CC BY 4.0, Jason Haddix / Arcanum Information Security -->

## 9. API Security

**CWE References:** CWE-284 (Improper Access Control), CWE-639 (IDOR), CWE-915 (Mass Assignment), CWE-200 (Exposure of Sensitive Information), CWE-770 (Resource Allocation Without Limits), CWE-209 (Error Message Information Exposure)
**Severity:** Critical to High | **Related:** [[API-Security]]

> **Risk:** APIs are the primary attack surface for modern applications. Missing authentication, broken authorization (IDOR), and mass assignment vulnerabilities allow attackers to access or modify data belonging to other users, escalate privileges, and exfiltrate sensitive information. AI frequently generates API endpoints without proper security controls.

### 9.1 Missing Authentication on Endpoints

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Unprotected API endpoints
// ========================================

// No authentication - anyone can access
@route("/api/users")
FUNCTION get_all_users():
    RETURN database.query("SELECT * FROM users")
END FUNCTION

// Admin functionality without auth check
@route("/api/admin/delete-user/{id}")
FUNCTION admin_delete_user(id):
    database.execute("DELETE FROM users WHERE id = ?", [id])
    RETURN {status: "deleted"}
END FUNCTION

// Sensitive data exposed without auth
@route("/api/orders/{order_id}")
FUNCTION get_order(order_id):
    RETURN database.get_order(order_id)
END FUNCTION

// "Security through obscurity" - hidden endpoint still accessible
@route("/api/internal/debug-info")
FUNCTION get_debug_info():
    RETURN {
        database_connection: DB_STRING,
        api_keys: LOADED_KEYS,
        server_config: CONFIG
    }
END FUNCTION

// ========================================
// GOOD: Authentication on all protected endpoints
// ========================================

// Middleware to enforce authentication
FUNCTION require_auth(handler):
    RETURN FUNCTION wrapped(request):
        token = request.headers.get("Authorization")

        IF token IS NULL:
            RETURN response(401, {error: "Authentication required"})
        END IF

        user = verify_token(token)
        IF user IS NULL:
            RETURN response(401, {error: "Invalid or expired token"})
        END IF

        request.user = user
        RETURN handler(request)
    END FUNCTION
END FUNCTION

// Middleware for admin-only routes
FUNCTION require_admin(handler):
    RETURN require_auth(FUNCTION wrapped(request):
        IF request.user.role != "admin":
            log.security("Unauthorized admin access attempt", {
                user_id: request.user.id,
                endpoint: request.path
            })
            RETURN response(403, {error: "Admin access required"})
        END IF

        RETURN handler(request)
    END FUNCTION)
END FUNCTION

// Protected endpoints with proper auth
@route("/api/users")
@require_admin  // Only admins can list all users
FUNCTION get_all_users(request):
    // Return only non-sensitive fields
    users = database.query("SELECT id, name, email, created_at FROM users")
    RETURN response(200, {users: users})
END FUNCTION

// Admin endpoint with proper protection
@route("/api/admin/delete-user/{id}")
@require_admin
FUNCTION admin_delete_user(request, id):
    // Audit log before action
    log.audit("User deletion", {
        admin_id: request.user.id,
        target_user_id: id
    })

    database.soft_delete("users", id)  // Soft delete for audit trail
    RETURN response(200, {status: "deleted"})
END FUNCTION

// Never expose internal/debug endpoints in production
IF environment != "production":
    @route("/api/internal/debug-info")
    @require_admin
    FUNCTION get_debug_info(request):
        RETURN {config: get_safe_config()}  // Sanitized config only
    END FUNCTION
END IF

// Default deny - explicitly define allowed public endpoints
PUBLIC_ENDPOINTS = [
    "/api/auth/login",
    "/api/auth/register",
    "/api/public/status",
    "/api/public/docs"
]

FUNCTION global_auth_middleware(request):
    IF request.path IN PUBLIC_ENDPOINTS:
        RETURN next(request)
    END IF

    // All other routes require authentication by default
    RETURN require_auth(next)(request)
END FUNCTION
```

### 9.2 Broken Object-Level Authorization (IDOR)

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: IDOR vulnerabilities - no ownership check
// ========================================

// Attacker changes user_id in URL to access others' data
@route("/api/users/{user_id}/profile")
@require_auth
FUNCTION get_user_profile(request, user_id):
    // VULNERABLE: No check that user_id belongs to authenticated user
    profile = database.get_profile(user_id)
    RETURN response(200, profile)
END FUNCTION

// Attacker can delete any order by changing order_id
@route("/api/orders/{order_id}")
@require_auth
FUNCTION delete_order(request, order_id):
    // VULNERABLE: Deletes any order regardless of owner
    database.delete("orders", order_id)
    RETURN response(200, {status: "deleted"})
END FUNCTION

// Attacker accesses any document by guessing/incrementing ID
@route("/api/documents/{doc_id}")
@require_auth
FUNCTION get_document(request, doc_id):
    // VULNERABLE: Sequential IDs make enumeration easy
    doc = database.get_document(doc_id)
    RETURN response(200, doc)
END FUNCTION

// Horizontal privilege escalation via parameter tampering
@route("/api/transfer")
@require_auth
FUNCTION transfer_funds(request):
    // VULNERABLE: from_account comes from user input
    from_account = request.body.from_account
    to_account = request.body.to_account
    amount = request.body.amount

    execute_transfer(from_account, to_account, amount)
    RETURN response(200, {status: "transferred"})
END FUNCTION

// ========================================
// GOOD: Proper object-level authorization
// ========================================

// Always verify ownership before access
@route("/api/users/{user_id}/profile")
@require_auth
FUNCTION get_user_profile(request, user_id):
    // SECURE: Verify user can only access their own profile
    IF user_id != request.user.id AND request.user.role != "admin":
        log.security("IDOR attempt blocked", {
            authenticated_user: request.user.id,
            attempted_access: user_id
        })
        RETURN response(403, {error: "Access denied"})
    END IF

    profile = database.get_profile(user_id)
    IF profile IS NULL:
        RETURN response(404, {error: "Profile not found"})
    END IF

    RETURN response(200, profile)
END FUNCTION

// Resource ownership verification
@route("/api/orders/{order_id}")
@require_auth
FUNCTION delete_order(request, order_id):
    order = database.get_order(order_id)

    IF order IS NULL:
        RETURN response(404, {error: "Order not found"})
    END IF

    // SECURE: Verify ownership before action
    IF order.user_id != request.user.id:
        log.security("Unauthorized order deletion attempt", {
            user_id: request.user.id,
            order_id: order_id,
            owner_id: order.user_id
        })
        RETURN response(403, {error: "Access denied"})
    END IF

    // Additional business logic check
    IF order.status == "shipped":
        RETURN response(400, {error: "Cannot delete shipped orders"})
    END IF

    database.delete("orders", order_id)
    RETURN response(200, {status: "deleted"})
END FUNCTION

// Use UUIDs instead of sequential IDs to prevent enumeration
FUNCTION create_document(request):
    doc_id = generate_uuid()  // Not sequential, not guessable

    database.insert("documents", {
        id: doc_id,
        owner_id: request.user.id,
        content: request.body.content
    })

    RETURN response(201, {id: doc_id})
END FUNCTION

// Implicit ownership from authenticated user
@route("/api/transfer")
@require_auth
FUNCTION transfer_funds(request):
    // SECURE: from_account MUST belong to authenticated user
    from_account = database.get_account(request.body.from_account)

    IF from_account IS NULL OR from_account.owner_id != request.user.id:
        RETURN response(403, {error: "Invalid source account"})
    END IF

    to_account = database.get_account(request.body.to_account)
    IF to_account IS NULL:
        RETURN response(404, {error: "Destination account not found"})
    END IF

    amount = request.body.amount
    IF amount <= 0 OR amount > from_account.balance:
        RETURN response(400, {error: "Invalid amount"})
    END IF

    execute_transfer(from_account.id, to_account.id, amount)

    log.audit("Funds transfer", {
        user_id: request.user.id,
        from: from_account.id,
        to: to_account.id,
        amount: amount
    })

    RETURN response(200, {status: "transferred"})
END FUNCTION

// Reusable authorization decorator
FUNCTION authorize_resource(resource_type, id_param):
    RETURN FUNCTION decorator(handler):
        RETURN FUNCTION wrapped(request):
            resource_id = request.params[id_param]
            resource = database.get(resource_type, resource_id)

            IF resource IS NULL:
                RETURN response(404, {error: resource_type + " not found"})
            END IF

            IF NOT can_access(request.user, resource):
                log.security("Authorization failed", {
                    user_id: request.user.id,
                    resource_type: resource_type,
                    resource_id: resource_id
                })
                RETURN response(403, {error: "Access denied"})
            END IF

            request.resource = resource
            RETURN handler(request)
        END FUNCTION
    END FUNCTION
END FUNCTION

// Usage
@route("/api/documents/{doc_id}")
@require_auth
@authorize_resource("documents", "doc_id")
FUNCTION get_document(request, doc_id):
    RETURN response(200, request.resource)  // Already verified
END FUNCTION
```

### 9.3 Mass Assignment Vulnerabilities

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

### 9.4 Excessive Data Exposure

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

### 9.5 Missing Rate Limiting

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No rate limiting
// ========================================

// Login endpoint vulnerable to brute force
@route("/api/auth/login")
FUNCTION login(request):
    user = database.find_by_email(request.body.email)

    IF user IS NULL OR NOT verify_password(request.body.password, user.password_hash):
        RETURN response(401, {error: "Invalid credentials"})
    END IF

    RETURN response(200, {token: create_token(user)})
END FUNCTION

// Expensive operation with no limits
@route("/api/reports/generate")
@require_auth
FUNCTION generate_report(request):
    // CPU-intensive, no limits - easy DoS
    report = generate_complex_report(request.body.params)
    RETURN response(200, report)
END FUNCTION

// SMS/email sending without limits
@route("/api/auth/send-verification")
FUNCTION send_verification(request):
    // Attacker can spam any phone/email
    send_sms(request.body.phone, generate_code())
    RETURN response(200, {status: "sent"})
END FUNCTION

// ========================================
// GOOD: Comprehensive rate limiting
// ========================================

// Rate limiter configuration
rate_limits = {
    // Per IP limits
    "ip:global": {limit: 1000, window: "1 hour"},
    "ip:auth": {limit: 10, window: "15 minutes"},
    "ip:sensitive": {limit: 5, window: "1 minute"},

    // Per user limits
    "user:global": {limit: 5000, window: "1 hour"},
    "user:write": {limit: 100, window: "1 hour"},

    // Per resource limits
    "resource:reports": {limit: 10, window: "1 hour"}
}

FUNCTION rate_limit(key_type, key_suffix=""):
    RETURN FUNCTION decorator(handler):
        RETURN FUNCTION wrapped(request):
            config = rate_limits[key_type]

            // Build rate limit key
            IF key_type.starts_with("ip:"):
                key = key_type + ":" + request.client_ip + key_suffix
            ELSE IF key_type.starts_with("user:"):
                IF request.user IS NULL:
                    RETURN response(401, {error: "Authentication required"})
                END IF
                key = key_type + ":" + request.user.id + key_suffix
            ELSE:
                key = key_type + key_suffix
            END IF

            // Check rate limit
            current = redis.incr(key)
            IF current == 1:
                redis.expire(key, config.window)
            END IF

            IF current > config.limit:
                retry_after = redis.ttl(key)
                log.security("Rate limit exceeded", {
                    key: key,
                    ip: request.client_ip,
                    user_id: request.user.id IF request.user ELSE NULL
                })
                RETURN response(429, {
                    error: "Too many requests",
                    retry_after: retry_after
                }, headers={"Retry-After": retry_after})
            END IF

            // Add rate limit headers
            response = handler(request)
            response.headers["X-RateLimit-Limit"] = config.limit
            response.headers["X-RateLimit-Remaining"] = config.limit - current
            response.headers["X-RateLimit-Reset"] = redis.ttl(key)

            RETURN response
        END FUNCTION
    END FUNCTION
END FUNCTION

// Login with rate limiting
@route("/api/auth/login")
@rate_limit("ip:auth")
FUNCTION login_protected(request):
    email = request.body.email

    // Additional per-account rate limiting
    account_key = "auth:account:" + sha256(email)
    attempts = redis.incr(account_key)
    IF attempts == 1:
        redis.expire(account_key, 3600)  // 1 hour
    END IF

    IF attempts > 5:
        // Lock account temporarily
        log.security("Account locked due to failed attempts", {email: email})
        RETURN response(423, {
            error: "Account temporarily locked",
            retry_after: redis.ttl(account_key)
        })
    END IF

    user = database.find_by_email(email)

    IF user IS NULL OR NOT verify_password(request.body.password, user.password_hash):
        // Don't reset counter on failure
        RETURN response(401, {error: "Invalid credentials"})
    END IF

    // Reset counter on successful login
    redis.delete(account_key)

    RETURN response(200, {token: create_token(user)})
END FUNCTION

// Expensive operations with strict limits
@route("/api/reports/generate")
@require_auth
@rate_limit("user:write")
@rate_limit("resource:reports")
FUNCTION generate_report_limited(request):
    // Queue for async processing if over capacity
    active_reports = get_active_report_count(request.user.id)

    IF active_reports > 3:
        RETURN response(429, {error: "Too many reports in progress"})
    END IF

    job_id = queue_report_generation(request.user.id, request.body.params)

    RETURN response(202, {
        job_id: job_id,
        status: "queued",
        estimated_time: estimate_completion_time()
    })
END FUNCTION

// SMS/email with phone/email-specific limits
@route("/api/auth/send-verification")
@rate_limit("ip:sensitive")
FUNCTION send_verification_limited(request):
    phone = request.body.phone

    // Rate limit per phone number
    phone_key = "verify:phone:" + sha256(phone)
    count = redis.incr(phone_key)
    IF count == 1:
        redis.expire(phone_key, 3600)  // 1 hour
    END IF

    IF count > 3:
        RETURN response(429, {
            error: "Too many verification requests for this number"
        })
    END IF

    // Verify phone format before sending
    IF NOT is_valid_phone(phone):
        RETURN response(400, {error: "Invalid phone number"})
    END IF

    code = generate_secure_code()
    redis.setex("verify:code:" + sha256(phone), 600, code)  // 10 min expiry

    send_sms(phone, "Your code: " + code)

    RETURN response(200, {status: "sent"})
END FUNCTION

// Sliding window rate limiter for more precise control
FUNCTION sliding_window_limit(key, limit, window_seconds):
    now = current_timestamp()
    window_start = now - window_seconds

    // Remove old entries
    redis.zremrangebyscore(key, "-inf", window_start)

    // Count current window
    count = redis.zcard(key)

    IF count >= limit:
        RETURN FALSE
    END IF

    // Add current request
    redis.zadd(key, now, generate_uuid())
    redis.expire(key, window_seconds)

    RETURN TRUE
END FUNCTION
```

### 9.6 Improper Error Handling in APIs

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Error messages revealing internal details
// ========================================

// Exposes database structure
@route("/api/users/{id}")
FUNCTION get_user_bad_errors(request, id):
    TRY:
        user = database.get_user(id)
        RETURN response(200, user)
    CATCH DatabaseError as e:
        // VULNERABLE: Exposes table names, query structure
        RETURN response(500, {
            error: "Database error",
            query: "SELECT * FROM users WHERE id = " + id,
            message: e.message,  // "Column 'password_hash' cannot be null"
            stack_trace: e.stack_trace
        })
    END TRY
END FUNCTION

// Reveals filesystem paths
@route("/api/files/{file_id}")
FUNCTION get_file_bad(request, file_id):
    TRY:
        content = read_file("/var/app/uploads/" + file_id)
        RETURN response(200, content)
    CATCH FileNotFoundError as e:
        // VULNERABLE: Exposes server filesystem structure
        RETURN response(404, {
            error: "File not found: /var/app/uploads/" + file_id,
            available_files: list_directory("/var/app/uploads/")
        })
    END TRY
END FUNCTION

// Authentication timing oracle
@route("/api/auth/login")
FUNCTION login_timing_oracle(request):
    user = database.find_by_email(request.body.email)

    IF user IS NULL:
        // Returns immediately - attacker knows email doesn't exist
        RETURN response(401, {error: "User not found"})
    END IF

    IF NOT verify_password(request.body.password, user.password_hash):
        // Takes longer due to password verification
        RETURN response(401, {error: "Invalid password"})
    END IF

    RETURN response(200, {token: create_token(user)})
END FUNCTION

// Inconsistent error format breaks security tools
@route("/api/orders")
FUNCTION create_order_inconsistent(request):
    IF NOT valid_items(request.body.items):
        RETURN response(400, "Invalid items")  // String
    END IF

    IF NOT has_stock(request.body.items):
        RETURN response(400, {msg: "Out of stock"})  // Different key
    END IF

    IF payment_failed:
        RETURN {status: "error", reason: "Payment failed"}  // No status code
    END IF
END FUNCTION

// ========================================
// GOOD: Secure, consistent error handling
// ========================================

// Standardized error response class
CLASS APIError:
    status: Integer
    code: String  // Machine-readable error code
    message: String  // User-friendly message
    request_id: String  // For support/debugging

    FUNCTION to_response():
        RETURN response(this.status, {
            error: {
                code: this.code,
                message: this.message,
                request_id: this.request_id
            }
        })
    END FUNCTION
END CLASS

// Error codes mapping (documented in API docs)
ERROR_CODES = {
    "AUTH_REQUIRED": {status: 401, message: "Authentication required"},
    "AUTH_INVALID": {status: 401, message: "Invalid credentials"},
    "FORBIDDEN": {status: 403, message: "Access denied"},
    "NOT_FOUND": {status: 404, message: "Resource not found"},
    "VALIDATION_ERROR": {status: 400, message: "Invalid request data"},
    "RATE_LIMITED": {status: 429, message: "Too many requests"},
    "INTERNAL_ERROR": {status: 500, message: "An unexpected error occurred"}
}

// Global error handler
FUNCTION global_error_handler(error, request):
    request_id = generate_request_id()

    // Log full error details internally
    log.error("Request failed", {
        request_id: request_id,
        path: request.path,
        method: request.method,
        user_id: request.user.id IF request.user ELSE NULL,
        error_type: error.type,
        error_message: error.message,
        stack_trace: error.stack_trace,
        request_body: redact_sensitive(request.body)
    })

    // Return sanitized error to client
    IF error IS APIError:
        error.request_id = request_id
        RETURN error.to_response()
    ELSE IF error IS ValidationError:
        RETURN APIError(
            status=400,
            code="VALIDATION_ERROR",
            message=error.user_message,  // Safe message
            request_id=request_id
        ).to_response()
    ELSE:
        // Generic error - never expose internal details
        RETURN APIError(
            status=500,
            code="INTERNAL_ERROR",
            message="An unexpected error occurred. Reference: " + request_id,
            request_id=request_id
        ).to_response()
    END IF
END FUNCTION

// Secure authentication with constant-time comparison
@route("/api/auth/login")
FUNCTION login_secure_errors(request):
    email = request.body.email
    password = request.body.password

    user = database.find_by_email(email)

    // Always perform password check to prevent timing oracle
    IF user IS NOT NULL:
        password_valid = constant_time_compare(
            hash_password(password, user.salt),
            user.password_hash
        )
    ELSE:
        // Fake password check to maintain consistent timing
        constant_time_compare(
            hash_password(password, generate_fake_salt()),
            DUMMY_HASH
        )
        password_valid = FALSE
    END IF

    IF NOT password_valid:
        // Same error message whether user exists or not
        log.security("Failed login attempt", {
            email_hash: sha256(email),  // Don't log raw email
            ip: request.client_ip
        })
        RETURN APIError(
            status=401,
            code="AUTH_INVALID",
            message="Invalid email or password"
        ).to_response()
    END IF

    RETURN response(200, {token: create_token(user)})
END FUNCTION

// File operations without path disclosure
@route("/api/files/{file_id}")
FUNCTION get_file_secure(request, file_id):
    // Validate file_id format (UUID only)
    IF NOT is_valid_uuid(file_id):
        RETURN APIError(
            status=400,
            code="VALIDATION_ERROR",
            message="Invalid file ID format"
        ).to_response()
    END IF

    // Look up file in database (not filesystem path)
    file_record = database.get_file(file_id)

    IF file_record IS NULL:
        RETURN APIError(
            status=404,
            code="NOT_FOUND",
            message="File not found"
        ).to_response()
    END IF

    // Check ownership
    IF file_record.owner_id != request.user.id:
        // Same error as not found - don't reveal existence
        RETURN APIError(
            status=404,
            code="NOT_FOUND",
            message="File not found"
        ).to_response()
    END IF

    TRY:
        content = storage.read(file_record.storage_key)
        RETURN response(200, content, headers={
            "Content-Type": file_record.mime_type
        })
    CATCH StorageError as e:
        log.error("File read failed", {
            file_id: file_id,
            storage_key: file_record.storage_key,
            error: e.message
        })
        RETURN APIError(
            status=500,
            code="INTERNAL_ERROR",
            message="Unable to retrieve file"
        ).to_response()
    END TRY
END FUNCTION

// Validation errors without revealing schema
FUNCTION validate_request(schema, data):
    errors = []

    FOR field, rules IN schema:
        IF field NOT IN data AND rules.required:
            errors.append({
                field: field,
                message: "This field is required"
            })
        ELSE IF field IN data:
            value = data[field]

            // Type validation
            IF NOT check_type(value, rules.type):
                errors.append({
                    field: field,
                    message: "Invalid value"  // Don't say "expected integer"
                })
            // Length validation
            ELSE IF rules.max_length AND len(value) > rules.max_length:
                errors.append({
                    field: field,
                    message: "Value too long"
                })
            END IF
        END IF
    END FOR

    IF errors.length > 0:
        THROW ValidationError(errors)
    END IF
END FUNCTION
```

---
