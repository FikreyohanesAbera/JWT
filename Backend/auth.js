const express = require("express");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

const { issueAccessToken, issueRefreshToken } = require("../auth/jwt");
const { setAuthCookies, clearAuthCookies } = require("../auth/cookies");

// You provide these database helpers
const db = require("../db");

const router = express.Router();

// Rate limit login to slow brute force
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "Invalid input" });
    }

    // Always use normalized email
    const normalizedEmail = email.trim().toLowerCase();

    const user = await db.users.findByEmail(normalizedEmail);
    // Do not reveal whether email exists
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    // Create a refresh session (device/login instance)
    const sessionId = crypto.randomUUID();

    const refreshToken = await issueRefreshToken({
      userId: user.id,
      sessionId,
    });

    // Store only a hash of refresh token in the database
    const refreshHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    await db.refreshSessions.insert({
      id: sessionId,
      user_id: user.id,
      token_hash: refreshHash,
      revoked: false,
      expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    });

    const accessToken = await issueAccessToken({
      userId: user.id,
      role: user.role,
    });

    setAuthCookies(res, { accessToken, refreshToken });

    // Response body can be minimal, cookies carry tokens
    return res.json({
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (err) {
    return res.status(500).json({ error: "Server error" });
  }
});

router.post("/logout", async (req, res) => {
  try {
    const refresh = req.cookies?.["__Host-refresh"];
    if (refresh) {
      const refreshHash = crypto.createHash("sha256").update(refresh).digest("hex");
      await db.refreshSessions.revokeByHash(refreshHash);
    }
    clearAuthCookies(res);
    return res.json({ ok: true });
  } catch {
    clearAuthCookies(res);
    return res.json({ ok: true });
  }
});

module.exports = router;
