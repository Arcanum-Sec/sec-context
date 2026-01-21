# Secrets in Client-Side Code


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
