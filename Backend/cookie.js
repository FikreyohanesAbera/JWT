function setAuthCookies(res, { accessToken, refreshToken }) {
  // Recommended cookie prefixes:
  // "__Host-" requires Secure + Path=/ and no Domain
  res.cookie("__Host-access", accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",        // access used across API
    maxAge: 10 * 60 * 1000,
  });

  res.cookie("__Host-refresh", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/auth/refresh", 
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

function clearAuthCookies(res) {
  res.clearCookie("__Host-access", { path: "/" });
  res.clearCookie("__Host-refresh", { path: "/auth/refresh" });
}

module.exports = { setAuthCookies, clearAuthCookies };
