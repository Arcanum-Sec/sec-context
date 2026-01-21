# Stored XSS (Database to Page Without Encoding)


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Stored data rendered without encoding
// ========================================
FUNCTION display_comments(post_id):
    comments = database.query("SELECT * FROM comments WHERE post_id = ?", [post_id])

    html = "<div class='comments'>"
    FOR comment IN comments:
        // Vulnerable: Stored data rendered directly
        html += "<div class='comment'>"
        html += "<strong>" + comment.author + "</strong>"
        html += "<p>" + comment.text + "</p>"
        html += "</div>"
    END FOR
    html += "</div>"
    RETURN html
END FUNCTION

FUNCTION display_user_profile(user_id):
    user = database.get_user(user_id)

    // Vulnerable: User-controlled fields rendered directly
    html = "<h1>" + user.display_name + "</h1>"
    html += "<div class='bio'>" + user.biography + "</div>"
    RETURN html
END FUNCTION

// Attack: Attacker saves comment with text: <script>stealCookies()</script>
// Result: Every user viewing the page executes attacker's script

// ========================================
// GOOD: Encode all database-sourced content
// ========================================
FUNCTION display_comments(post_id):
    comments = database.query("SELECT * FROM comments WHERE post_id = ?", [post_id])

    html = "<div class='comments'>"
    FOR comment IN comments:
        // Safe: All stored data is encoded
        html += "<div class='comment'>"
        html += "<strong>" + html_encode(comment.author) + "</strong>"
        html += "<p>" + html_encode(comment.text) + "</p>"
        html += "</div>"
    END FOR
    html += "</div>"
    RETURN html
END FUNCTION

FUNCTION display_user_profile(user_id):
    user = database.get_user(user_id)

    // Safe: Encode user-controlled fields
    html = "<h1>" + html_encode(user.display_name) + "</h1>"
    html += "<div class='bio'>" + html_encode(user.biography) + "</div>"
    RETURN html
END FUNCTION

// Better: Use templating engine with auto-escaping
FUNCTION display_comments_template(post_id):
    comments = database.query("SELECT * FROM comments WHERE post_id = ?", [post_id])

    // Templating engines like Jinja2, Handlebars auto-escape by default
    RETURN template.render("comments.html", {comments: comments})
END FUNCTION
```
