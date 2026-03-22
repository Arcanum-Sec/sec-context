<!-- Source: Arcanum sec-context (https://github.com/arcanum-sec/sec-context), CC BY 4.0, Jason Haddix / Arcanum Information Security -->

## 1. Secrets and Credentials Management

**CWE References:** CWE-798 (Hard-coded Credentials), CWE-259 (Hard-coded Password)
**Severity:** Critical | **Related:** [[Hardcoded-Secrets]]

> **Risk:** Secrets committed to version control are scraped within minutes. Leads to cloud resource abuse, data breaches, and significant financial costs. AI frequently generates code with embedded credentials from tutorial examples.

### 1.1 Hardcoded Passwords and API Keys

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Hardcoded API keys and passwords
// ========================================
CONSTANT API_KEY = "sk-abcd1234efgh5678ijkl9012mnop3456"
CONSTANT DB_PASSWORD = "super_secret_password"
CONSTANT AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
CONSTANT AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

FUNCTION call_api(endpoint):
    headers = {"Authorization": "Bearer " + API_KEY}
    RETURN http.get(endpoint, headers)
END FUNCTION

// ========================================
// GOOD: Environment variables
// ========================================
FUNCTION call_api(endpoint):
    api_key = environment.get("API_KEY")

    IF api_key IS NULL:
        THROW Error("API_KEY environment variable required")
    END IF

    headers = {"Authorization": "Bearer " + api_key}
    RETURN http.get(endpoint, headers)
END FUNCTION
```

### 1.2 Credentials in Configuration Files

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Credentials in config committed to repo
// ========================================
// config.json (tracked in git)
{
    "database_url": "postgresql://admin:password123@localhost:5432/mydb",
    "redis_password": "redis_secret_123",
    "smtp_password": "mail_password"
}

FUNCTION connect_database():
    config = load_json("config.json")
    connection = database.connect(config.database_url)
    RETURN connection
END FUNCTION

// ========================================
// GOOD: External secret management
// ========================================
// config.json (no secrets, safe to commit)
{
    "database_host": "localhost",
    "database_port": 5432,
    "database_name": "mydb"
}

FUNCTION connect_database():
    config = load_json("config.json")

    // Credentials from environment or secret manager
    db_user = environment.get("DB_USER")
    db_password = environment.get("DB_PASSWORD")

    IF db_user IS NULL OR db_password IS NULL:
        THROW Error("Database credentials not configured")
    END IF

    url = "postgresql://" + db_user + ":" + db_password + "@" +
          config.database_host + ":" + config.database_port + "/" + config.database_name
    RETURN database.connect(url)
END FUNCTION
```

### 1.3 Secrets in Client-Side Code

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Secrets exposed in frontend JavaScript
// ========================================
// frontend.js (served to browser)
CONSTANT STRIPE_SECRET_KEY = "sk_live_abc123..."  // Never expose secret keys!
CONSTANT ADMIN_PASSWORD = "admin123"

FUNCTION charge_card(card_number, amount):
    RETURN http.post("https://api.stripe.com/charges", {
        api_key: STRIPE_SECRET_KEY,  // Visible in browser DevTools!
        card: card_number,
        amount: amount
    })
END FUNCTION

// ========================================
// GOOD: Backend proxy for sensitive operations
// ========================================
// frontend.js
FUNCTION charge_card(card_token, amount):
    // Only send public token, backend handles secret key
    RETURN http.post("/api/charges", {
        token: card_token,
        amount: amount
    })
END FUNCTION

// backend.js (server-side only)
FUNCTION handle_charge(request):
    stripe_key = environment.get("STRIPE_SECRET_KEY")

    RETURN stripe.charges.create({
        api_key: stripe_key,
        source: request.token,
        amount: request.amount
    })
END FUNCTION
```

### 1.4 Insecure Credential Storage

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Storing credentials in plaintext
// ========================================
FUNCTION save_user_credentials(username, password):
    // Dangerous: Plaintext password storage
    database.insert("credentials", {
        username: username,
        password: password  // Stored as-is!
    })
END FUNCTION

FUNCTION save_api_key(user_id, api_key):
    // Dangerous: No encryption
    database.insert("api_keys", {
        user_id: user_id,
        key: api_key
    })
END FUNCTION

// ========================================
// GOOD: Proper credential protection
// ========================================
FUNCTION save_user_credentials(username, password):
    // Hash passwords with bcrypt
    salt = bcrypt.generate_salt(rounds=12)
    password_hash = bcrypt.hash(password, salt)

    database.insert("credentials", {
        username: username,
        password_hash: password_hash
    })
END FUNCTION

FUNCTION save_api_key(user_id, api_key):
    // Encrypt sensitive data at rest
    encryption_key = secret_manager.get("DATA_ENCRYPTION_KEY")
    encrypted_key = aes_gcm_encrypt(api_key, encryption_key)

    database.insert("api_keys", {
        user_id: user_id,
        encrypted_key: encrypted_key
    })
END FUNCTION
```

### 1.5 Missing Secret Rotation Considerations

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Static secrets with no rotation capability
// ========================================
CONSTANT JWT_SECRET = "static_jwt_secret_forever"

FUNCTION create_token(user_id):
    // No way to rotate without breaking all existing tokens
    RETURN jwt.encode({user: user_id}, JWT_SECRET, algorithm="HS256")
END FUNCTION

// ========================================
// GOOD: Versioned secrets supporting rotation
// ========================================
FUNCTION get_jwt_secret(version=NULL):
    IF version IS NULL:
        version = environment.get("JWT_SECRET_VERSION", "v1")
    END IF

    // Fetch versioned secret from manager
    RETURN secret_manager.get("JWT_SECRET_" + version)
END FUNCTION

FUNCTION create_token(user_id):
    current_version = environment.get("JWT_SECRET_VERSION")
    secret = get_jwt_secret(current_version)

    payload = {
        user: user_id,
        secret_version: current_version,  // Include version for validation
        exp: current_timestamp() + 3600
    }
    RETURN jwt.encode(payload, secret, algorithm="HS256")
END FUNCTION

FUNCTION verify_token(token):
    // Decode header to get version
    unverified = jwt.decode(token, verify=FALSE)
    version = unverified.get("secret_version", "v1")

    secret = get_jwt_secret(version)
    RETURN jwt.decode(token, secret, algorithms=["HS256"])
END FUNCTION
```

---
