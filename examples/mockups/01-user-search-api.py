# User search API endpoint
# This endpoint allows searching for users by name and returns their profile data.

import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = "/var/data/users.db"


@app.route("/api/users/search", methods=["GET"])
def search_users():
    """Search users by name. Supports partial matching."""
    query = request.args.get("q", "")
    sort_by = request.args.get("sort", "name")
    limit = request.args.get("limit", "50")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Build the search query
    sql = f"SELECT id, name, email, phone, ssn, salary, address FROM users WHERE name LIKE '%{query}%' ORDER BY {sort_by} LIMIT {limit}"
    cursor.execute(sql)

    results = []
    for row in cursor.fetchall():
        results.append({
            "id": row[0],
            "name": row[1],
            "email": row[2],
            "phone": row[3],
            "ssn": row[4],
            "salary": row[5],
            "address": row[6],
        })

    conn.close()
    return jsonify(results)


@app.route("/api/users/<user_id>", methods=["GET"])
def get_user(user_id):
    """Get a single user by ID."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify({"id": row[0], "name": row[1], "email": row[2], "phone": row[3], "ssn": row[4], "salary": row[5]})
    return jsonify({"error": "User not found"}), 404


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
