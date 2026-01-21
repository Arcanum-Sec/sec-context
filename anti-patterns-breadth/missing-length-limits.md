# Missing Length Limits


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No length limits on input
// ========================================
FUNCTION create_post_unlimited(request):
    title = request.body.title
    content = request.body.content

    // Vulnerable: No length limits
    // Attacker sends 1GB title, exhausts memory/storage
    database.insert("posts", {title: title, content: content})
END FUNCTION

FUNCTION search_unlimited(request):
    query = request.params.q

    // Vulnerable: Long query strings can DoS search systems
    // Also enables ReDoS if query is used in regex
    results = database.search(query)
    RETURN results
END FUNCTION

FUNCTION process_file_unlimited(request):
    file_content = request.body.file

    // Vulnerable: No file size limit
    // Attacker uploads 10GB file, exhausts disk/memory
    save_file(file_content)
END FUNCTION

// Real-world DoS: JSON payload with deeply nested objects
// {"a":{"a":{"a":{"a":...}}}}  // 1000 levels deep
// Can crash parsers or exhaust stack space

// ========================================
// GOOD: Enforce length limits on all inputs
// ========================================
CONSTANT MAX_TITLE_LENGTH = 200
CONSTANT MAX_CONTENT_LENGTH = 50000
CONSTANT MAX_SEARCH_QUERY = 500
CONSTANT MAX_FILE_SIZE = 10 * 1024 * 1024  // 10MB
CONSTANT MAX_JSON_DEPTH = 20

FUNCTION create_post_limited(request):
    title = request.body.title
    content = request.body.content

    // Validate title length
    IF typeof(title) != "string":
        THROW ValidationError("Title must be a string")
    END IF
    IF title.length == 0:
        THROW ValidationError("Title is required")
    END IF
    IF title.length > MAX_TITLE_LENGTH:
        THROW ValidationError("Title exceeds " + MAX_TITLE_LENGTH + " characters")
    END IF

    // Validate content length
    IF typeof(content) != "string":
        THROW ValidationError("Content must be a string")
    END IF
    IF content.length > MAX_CONTENT_LENGTH:
        THROW ValidationError("Content exceeds " + MAX_CONTENT_LENGTH + " characters")
    END IF

    database.insert("posts", {title: title, content: content})
END FUNCTION

FUNCTION search_limited(request):
    query = request.params.q

    IF typeof(query) != "string":
        THROW ValidationError("Query must be a string")
    END IF
    IF query.length > MAX_SEARCH_QUERY:
        THROW ValidationError("Search query too long")
    END IF
    IF query.length < 2:
        THROW ValidationError("Search query too short")
    END IF

    results = database.search(query)
    RETURN results
END FUNCTION

// Configure request body limits at framework level
FUNCTION configure_server():
    server.set_body_limit(MAX_FILE_SIZE)
    server.set_json_depth_limit(MAX_JSON_DEPTH)
    server.set_parameter_limit(1000)  // Max form fields
    server.set_header_size_limit(8192)  // 8KB header limit
END FUNCTION

// Array length limits
FUNCTION process_batch_request(request):
    items = request.body.items

    IF NOT is_array(items):
        THROW ValidationError("Items must be an array")
    END IF
    IF items.length > 100:
        THROW ValidationError("Maximum 100 items per batch")
    END IF

    FOR item IN items:
        process_single_item(item)
    END FOR
END FUNCTION
```
