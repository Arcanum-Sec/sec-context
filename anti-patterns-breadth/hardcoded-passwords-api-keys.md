# Hardcoded Passwords and API Keys


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
