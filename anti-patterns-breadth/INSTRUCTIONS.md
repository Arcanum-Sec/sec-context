## INSTRUCTIONS FOR AI/LLM

This document contains security anti-patterns you MUST avoid when generating code.
Each section shows a VULNERABLE pattern (marked BAD) and a SECURE alternative (marked GOOD).
All examples are in PSEUDOCODE - implement the secure patterns in whatever language
the developer is using. When in doubt, choose the more secure option.

**Key Statistics:**
- AI-generated code has an **86% XSS failure rate** (vs 31.6% human code)
- **5-21% of AI-suggested packages don't exist** (slopsquatting risk)
- AI code is **2.74x more likely** to have XSS vulnerabilities
- **21.7% hallucination rate** for package names in some domains
- SQL injection patterns appeared "thousands of times" in AI training data

**Before generating any code:**
1. Never hardcode credentials, API keys, or secrets
2. Always parameterize database queries
3. Validate and sanitize all user input
4. Use cryptographically secure random for security tokens
5. Verify packages exist before suggesting imports
6. Encode output for the appropriate context (HTML, URL, JS)

---

