const jwt = require("jsonwebtoken");

// Load once at startup (do not read files per request)
const ACCESS_PRIVATE_KEY = process.env.ACCESS_PRIVATE_KEY_PEM;   // RS256 private key (PEM)
const ACCESS_PUBLIC_KEY  = process.env.ACCESS_PUBLIC_KEY_PEM;    // RS256 public key  (PEM)

const ISSUER = "your-auth-service";
const AUDIENCE = "api"; // or "gateway" or your backend identifier

function signAsync(payload, key, options) {
  return new Promise((resolve, reject) => {
    jwt.sign(payload, key, options, (err, token) => {
      if (err) return reject(err);
      resolve(token);
    });
  });
}

function verifyAccessToken(token) {
  // Verify signature + validate issuer/audience/expiry
  return jwt.verify(token, ACCESS_PUBLIC_KEY, {
    algorithms: ["RS256"],
    issuer: ISSUER,
    audience: AUDIENCE,
    clockTolerance: 5, // seconds
  });
}

async function issueAccessToken({ userId, role }) {
  return signAsync(
    { role },                  // keep payload small
    ACCESS_PRIVATE_KEY,
    {
      algorithm: "RS256",
      issuer: ISSUER,
      audience: AUDIENCE,
      subject: userId,
      expiresIn: "10m",
      jwtid: cryptoRandomId(),
      header: { kid: "v1" },   // for key rotation later
    }
  );
}

async function issueRefreshToken({ userId, sessionId }) {
  // Refresh token should be long-lived and minimal
  return signAsync(
    { sid: sessionId },        // session id
    ACCESS_PRIVATE_KEY,
    {
      algorithm: "RS256",
      issuer: ISSUER,
      audience: "refresh",     // different audience is fine
      subject: userId,
      expiresIn: "30d",
      jwtid: cryptoRandomId(),
      header: { kid: "v1" },
    }
  );
}

function cryptoRandomId() {
  return require("crypto").randomUUID();
}

module.exports = {
  issueAccessToken,
  issueRefreshToken,
  verifyAccessToken,
};
