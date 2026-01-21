# Session Fixation Vulnerabilities


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Session ID not regenerated on login
// ========================================
FUNCTION login_vulnerable(username, password):
    // Session ID was set when user first visited (before login)
    session_id = request.get_cookie("session_id")

    user = authenticate(username, password)
    IF user IS NULL:
        RETURN {success: FALSE}
    END IF

    // Vulnerable: Reusing pre-authentication session ID
    session_store.set(session_id, {user_id: user.id, authenticated: TRUE})
    RETURN {success: TRUE}
END FUNCTION

// Attack scenario:
// 1. Attacker visits site, gets session_id=ABC123
// 2. Attacker sends victim link: https://site.com?session_id=ABC123
// 3. Victim logs in with attacker's session ID
// 4. Attacker uses session_id=ABC123 to access victim's account

// ========================================
// GOOD: Regenerate session on authentication changes
// ========================================
FUNCTION login_secure(username, password):
    user = authenticate(username, password)
    IF user IS NULL:
        RETURN {success: FALSE}
    END IF

    // CRITICAL: Invalidate old session and create new one
    old_session_id = request.get_cookie("session_id")
    IF old_session_id IS NOT NULL:
        session_store.delete(old_session_id)
    END IF

    // Generate completely new session ID
    new_session = create_session(user.id)

    // Set new session cookie
    response.set_cookie("session_id", new_session.token, {
        httponly: TRUE,
        secure: TRUE,
        samesite: "Strict"
    })

    RETURN {success: TRUE}
END FUNCTION

// Also regenerate session on privilege escalation
FUNCTION elevate_privileges(user, new_role):
    // Invalidate current session
    old_session_id = request.get_cookie("session_id")
    session_store.delete(old_session_id)

    // Create new session with elevated privileges
    new_session = create_session(user.id)
    new_session.role = new_role

    response.set_cookie("session_id", new_session.token, {
        httponly: TRUE,
        secure: TRUE,
        samesite: "Strict"
    })

    RETURN new_session
END FUNCTION

// Regenerate session periodically for long-lived sessions
FUNCTION check_session_rotation(session):
    // Rotate session every 15 minutes for active users
    IF current_timestamp() - session.created_at > 900:
        new_session = create_session(session.user_id)
        new_session.data = session.data  // Preserve session data

        session_store.delete(session.id)

        response.set_cookie("session_id", new_session.token, {
            httponly: TRUE,
            secure: TRUE,
            samesite: "Strict"
        })

        RETURN new_session
    END IF

    RETURN session
END FUNCTION
```
