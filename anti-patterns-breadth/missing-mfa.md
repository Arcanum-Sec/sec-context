# Missing MFA Considerations


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Single-factor authentication only
// ========================================
FUNCTION login_single_factor(username, password):
    user = database.find_user(username)

    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF

    // Immediately grant full access after password verification
    token = create_session(user.id)
    RETURN {success: TRUE, token: token}
END FUNCTION

// Problems:
// - Compromised password = full account takeover
// - No protection against credential stuffing
// - Phishing attacks succeed completely
// - No step-up authentication for sensitive operations

// ========================================
// GOOD: MFA-aware authentication flow
// ========================================
FUNCTION login_with_mfa(username, password):
    user = database.find_user(username)

    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF

    // Check if MFA is enabled
    IF user.mfa_enabled:
        // Create partial session (not fully authenticated)
        partial_token = create_partial_session(user.id)

        RETURN {
            success: FALSE,
            mfa_required: TRUE,
            partial_token: partial_token,
            mfa_methods: get_user_mfa_methods(user.id)
        }
    END IF

    // If MFA not enabled, encourage setup
    token = create_session(user.id)
    RETURN {
        success: TRUE,
        token: token,
        mfa_suggestion: user.is_admin  // Strongly suggest MFA for admins
    }
END FUNCTION

FUNCTION verify_mfa(partial_token, mfa_code, mfa_method):
    session = get_partial_session(partial_token)

    IF session IS NULL OR session.expires_at < current_time():
        RETURN {success: FALSE, error: "Session expired, please login again"}
    END IF

    user = database.get_user(session.user_id)

    // Verify MFA code based on method
    is_valid = FALSE

    IF mfa_method == "totp":
        is_valid = verify_totp(user.totp_secret, mfa_code)
    ELSE IF mfa_method == "sms":
        is_valid = verify_sms_code(user.id, mfa_code)
    ELSE IF mfa_method == "backup":
        is_valid = verify_backup_code(user.id, mfa_code)
    END IF

    IF NOT is_valid:
        record_failed_mfa_attempt(user.id)
        RETURN {success: FALSE, error: "Invalid verification code"}
    END IF

    // MFA verified - create full session
    delete_partial_session(partial_token)
    token = create_session(user.id)

    RETURN {success: TRUE, token: token}
END FUNCTION

// TOTP verification with time window
FUNCTION verify_totp(secret, code):
    // Allow 1 step before and after for clock drift (30 second windows)
    FOR step IN [-1, 0, 1]:
        expected = generate_totp(secret, time_step=step)
        IF constant_time_compare(code, expected):
            RETURN TRUE
        END IF
    END FOR
    RETURN FALSE
END FUNCTION

// Step-up authentication for sensitive operations
FUNCTION require_recent_auth(user_session, max_age_seconds):
    IF current_time() - user_session.authenticated_at > max_age_seconds:
        RETURN {
            requires_reauth: TRUE,
            message: "Please re-enter your password for this action"
        }
    END IF
    RETURN {requires_reauth: FALSE}
END FUNCTION

FUNCTION perform_sensitive_action(session, action, password):
    // Require recent password entry for sensitive actions
    user = database.get_user(session.user_id)

    IF NOT bcrypt.verify(password, user.password_hash):
        RETURN {success: FALSE, error: "Invalid password"}
    END IF

    // Update authentication timestamp
    session.authenticated_at = current_time()

    // Perform the sensitive action
    RETURN execute_action(action)
END FUNCTION
```
