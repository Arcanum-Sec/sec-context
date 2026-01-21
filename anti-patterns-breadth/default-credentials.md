# Default Credentials


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Default credentials in code or config
// ========================================

// Mistake 1: Hardcoded default admin account
FUNCTION initialize_database():
    IF NOT user_exists("admin"):
        create_user({
            username: "admin",
            password: "admin",      // First thing attackers try
            role: "administrator"
        })
    END IF
END FUNCTION

// Mistake 2: Default passwords in configuration
config = {
    database: {
        host: "localhost",
        user: "root",
        password: "root"           // Default MySQL credentials
    },
    redis: {
        password: ""               // No password = open to network
    },
    admin_panel: {
        secret_key: "change_me"    // Never changed
    }
}

// Mistake 3: API keys with placeholder values
CONSTANT API_KEY = "YOUR_API_KEY_HERE"  // Developers forget to change
CONSTANT WEBHOOK_SECRET = "test123"

// ========================================
// GOOD: Require explicit configuration, no defaults
// ========================================

FUNCTION initialize_application():
    // Require all sensitive config to be explicitly set
    required_config = [
        "DATABASE_PASSWORD",
        "REDIS_PASSWORD",
        "SECRET_KEY",
        "API_KEY"
    ]

    FOR config_name IN required_config:
        value = get_environment_variable(config_name)

        IF value IS NULL OR value == "":
            THROW ConfigurationError(
                config_name + " must be set in environment"
            )
        END IF

        // Check for common placeholder values
        placeholder_patterns = ["change_me", "your_", "test", "example", "xxx"]
        FOR pattern IN placeholder_patterns:
            IF value.lower().contains(pattern):
                THROW ConfigurationError(
                    config_name + " appears to contain a placeholder value"
                )
            END IF
        END FOR
    END FOR
END FUNCTION

FUNCTION initialize_database():
    // Never create default admin accounts automatically
    // Instead, require explicit admin creation with strong password

    IF NOT admin_exists():
        IF environment == "development":
            log.warning("No admin account exists. Run: create_admin_account command")
        ELSE:
            log.error("No admin account configured for production")
            THROW ConfigurationError("Admin account must be created before deployment")
        END IF
    END IF
END FUNCTION

// First-run setup requires strong credentials
FUNCTION create_initial_admin(username, password):
    // Validate password strength
    IF NOT is_strong_password(password):
        THROW ValidationError("Admin password must meet complexity requirements")
    END IF

    // Hash password properly
    hashed = bcrypt.hash(password, rounds=12)

    create_user({
        username: username,
        password_hash: hashed,
        role: "administrator",
        requires_password_change: TRUE  // Force change on first login
    })
END FUNCTION

// Service accounts should use key-based auth, not passwords
FUNCTION configure_service_connections():
    // Use certificate-based auth for databases where possible
    database.connect({
        ssl_cert: load_file(env.get("DB_CLIENT_CERT")),
        ssl_key: load_file(env.get("DB_CLIENT_KEY")),
        ssl_ca: load_file(env.get("DB_CA_CERT"))
    })
END FUNCTION
```
