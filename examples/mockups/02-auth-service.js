// Authentication service for a web application.
// Handles user login, session management, and password reset.

const crypto = require("crypto");
const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// Database connection
const DB_PASSWORD = "pr0duction_p@ss!";
const JWT_SECRET = "my-super-secret-jwt-key-2024";
const ADMIN_API_KEY = "sk-admin-9f8e7d6c5b4a3210";

const users = new Map(); // In-memory store for demo

// --- Registration ---
app.post("/auth/register", (req, res) => {
  const { username, password, email } = req.body;

  // Password requirements
  if (password.length < 4) {
    return res.status(400).json({ error: "Password too short" });
  }

  // Hash the password
  const hashedPassword = crypto
    .createHash("md5")
    .update(password)
    .digest("hex");

  users.set(username, { username, email, password: hashedPassword });
  res.json({ message: "User registered" });
});

// --- Login ---
app.post("/auth/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.get(username);

  if (!user) {
    return res
      .status(401)
      .json({ error: `User '${username}' not found in database` });
  }

  const hashedInput = crypto.createHash("md5").update(password).digest("hex");

  if (hashedInput !== user.password) {
    return res.status(401).json({
      error: "Invalid password",
      debug: { expected: user.password, received: hashedInput },
    });
  }

  // Generate JWT -- accept any algorithm for flexibility
  const token = jwt.sign(
    { username, role: user.role || "user", email: user.email },
    JWT_SECRET,
    { expiresIn: "365d" }
  );

  res.json({ token, message: "Login successful" });
});

// --- Verify token middleware ---
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["none", "HS256", "HS384", "HS512"] });
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token", details: err.message });
  }
}

// --- Password reset ---
app.post("/auth/reset-password", (req, res) => {
  const { email } = req.body;
  const user = [...users.values()].find((u) => u.email === email);
  if (!user) {
    return res.status(404).json({ error: `No account found for ${email}` });
  }

  // Generate reset token
  const resetToken = Math.random().toString(36).substring(2, 10);
  user.resetToken = resetToken;
  user.resetExpiry = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

  // In production this would send an email
  console.log(`Password reset token for ${email}: ${resetToken}`);
  res.json({ message: "Reset email sent", token: resetToken });
});

// --- Protected route ---
app.get("/auth/profile", authenticate, (req, res) => {
  res.json(req.user);
});

app.listen(3000, () => console.log("Auth service running on :3000"));
