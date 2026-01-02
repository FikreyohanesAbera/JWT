const { verifyAccessToken } = require("./auth/jwt");

function requireAuth(req, res, next) {
  const token = req.cookies?.["__Host-access"];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const claims = verifyAccessToken(token);
    req.user = { id: claims.sub, role: claims.role };
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

module.exports = { requireAuth };
