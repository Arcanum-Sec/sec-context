# Credentials in Configuration Files


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
