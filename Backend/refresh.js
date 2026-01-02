const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { issueAccessToken, issueRefreshToken } = require("../auth/jwt");
const { setAuthCookies } = require("../auth/cookies");
const db = require("../db");

const router = express.Router();

const ACCESS_PUBLIC_KEY = process.env.ACCESS_PUBLIC_KEY_PEM;
const ISSUER = "your-auth-service";

router.post("/refresh", async (req, res) => {
  try {
    const refresh = req.cookies?.["__Host-refresh"];
    if (!refresh) return res.status(401).json({ error: "Missing refresh token" });

    // Verify refresh token (signature + issuer + audience)
    const claims = jwt.verify(refresh, ACCESS_PUBLIC_KEY, {
      algorithms: ["RS256"],
      issuer: ISSUER,
      audience: "refresh",
      clockTolerance: 5,
    });

    const userId = claims.sub;
    const sessionId = claims.sid;

    // Check session exists and not revoked and hash matches
    const refreshHash = crypto.createHash("sha256").update(refresh).digest("hex");
    const session = await db.refreshSessions.findById(sessionId);

    if (!session || session.revoked) return res.status(401).json({ error: "Invalid refresh token" });
    if (session.user_id !== userId) return res.status(401).json({ error: "Invalid refresh token" });
    if (session.token_hash !== refreshHash) return res.status(401).json({ error: "Invalid refresh token" });

    // Rotate refresh token: revoke old session and create new session
    await db.refreshSessions.revokeById(sessionId);

    const newSessionId = crypto.randomUUID();
    const newRefresh = await issueRefreshToken({ userId, sessionId: newSessionId });
    const newRefreshHash = crypto.createHash("sha256").update(newRefresh).digest("hex");

    await db.refreshSessions.insert({
      id: newSessionId,
      user_id: userId,
      token_hash: newRefreshHash,
      revoked: false,
      expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    });

    // Issue new access token
    const user = await db.users.findById(userId);
    const newAccess = await issueAccessToken({ userId, role: user.role });

    setAuthCookies(res, { accessToken: newAccess, refreshToken: newRefresh });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(401).json({ error: "Invalid refresh token" });
  }
});

module.exports = router;
