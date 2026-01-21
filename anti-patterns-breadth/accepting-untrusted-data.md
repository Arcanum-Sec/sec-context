# Accepting and Processing Untrusted Data


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Trusting external data sources
// ========================================
FUNCTION process_webhook_unsafe(request):
    // Vulnerable: No signature verification
    data = json.parse(request.body)

    // Attacker can spoof webhook requests
    IF data.event == "payment_completed":
        mark_order_paid(data.order_id)  // Dangerous!
    END IF
END FUNCTION

FUNCTION fetch_and_process_unsafe(url):
    // Vulnerable: Processing arbitrary external content
    response = http.get(url)
    data = json.parse(response.body)

    // No validation of response structure
    database.insert("external_data", data)
END FUNCTION

FUNCTION deserialize_unsafe(serialized_data):
    // Vulnerable: Pickle/eval deserialization of untrusted data
    // Allows arbitrary code execution!
    object = pickle.loads(serialized_data)
    RETURN object
END FUNCTION

FUNCTION process_xml_unsafe(xml_string):
    // Vulnerable: XXE (XML External Entity) attack
    parser = xml.create_parser()
    doc = parser.parse(xml_string)
    // Attacker XML: <!ENTITY xxe SYSTEM "file:///etc/passwd">
    RETURN doc
END FUNCTION

// ========================================
// GOOD: Validate and sanitize external data
// ========================================
FUNCTION process_webhook_safe(request):
    // Verify webhook signature
    signature = request.headers.get("X-Signature")
    expected = hmac_sha256(WEBHOOK_SECRET, request.raw_body)

    IF NOT constant_time_compare(signature, expected):
        log.warning("Invalid webhook signature", {ip: request.ip})
        RETURN {status: 401, error: "Invalid signature"}
    END IF

    // Validate payload structure
    data = json.parse(request.body)

    IF NOT validate_webhook_schema(data):
        RETURN {status: 400, error: "Invalid payload"}
    END IF

    // Process verified and validated data
    IF data.event == "payment_completed":
        // Additional verification: Check with payment provider
        IF verify_payment_with_provider(data.payment_id):
            mark_order_paid(data.order_id)
        END IF
    END IF
END FUNCTION

FUNCTION fetch_and_process_safe(url):
    // Validate URL is from allowed sources
    parsed_url = url_parser.parse(url)
    IF parsed_url.host NOT IN ALLOWED_HOSTS:
        THROW ValidationError("URL host not allowed")
    END IF

    // Fetch with timeout and size limits
    response = http.get(url, timeout=10, max_size=1024*1024)

    // Parse and validate structure
    TRY:
        data = json.parse(response.body)
    CATCH JSONError:
        THROW ValidationError("Invalid JSON response")
    END TRY

    // Validate against expected schema
    validated_data = validate_schema(data, EXPECTED_SCHEMA)

    // Sanitize before storing
    sanitized = sanitize_object(validated_data)
    database.insert("external_data", sanitized)
END FUNCTION

FUNCTION deserialize_safe(data, format):
    // Never use pickle/eval for untrusted data
    // Use safe serialization formats
    IF format == "json":
        RETURN json.parse(data)
    ELSE IF format == "msgpack":
        RETURN msgpack.unpack(data)
    ELSE:
        THROW Error("Unsupported format")
    END IF
END FUNCTION

FUNCTION process_xml_safe(xml_string):
    // Disable external entities and DTDs
    parser = xml.create_parser(
        resolve_entities=FALSE,
        load_dtd=FALSE,
        no_network=TRUE
    )

    TRY:
        doc = parser.parse(xml_string)
        RETURN doc
    CATCH XMLError as e:
        log.warning("XML parsing failed", {error: e.message})
        THROW ValidationError("Invalid XML")
    END TRY
END FUNCTION

// Schema validation helper
FUNCTION validate_schema(data, schema):
    // Use JSON Schema or similar validation library
    validator = JsonSchemaValidator(schema)

    IF NOT validator.is_valid(data):
        errors = validator.get_errors()
        THROW ValidationError("Schema validation failed: " + errors.join(", "))
    END IF

    RETURN data
END FUNCTION
```
