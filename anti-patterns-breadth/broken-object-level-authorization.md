# Broken Object-Level Authorization (IDOR)


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
