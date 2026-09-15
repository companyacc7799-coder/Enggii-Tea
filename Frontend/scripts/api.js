/* =====================================================
   GOOGLE OAUTH RETURN HANDLER
   After Google sign-in, Supabase redirects back with the
   session in the URL hash:
     .../#access_token=...&refresh_token=...&expires_in=...
   The backend verifies Supabase access tokens directly
   (see Backend/middleware/authMiddleware.js), so we store
   the token under the same key used below. This runs on
   every page (including the login page) before anything
   else, and cleans the hash from the URL.
   ===================================================== */

(function handleOAuthHash() {
  if (!window.location.hash) return;

  const params = new URLSearchParams(
    window.location.hash.replace(/^#/, "")
  );

  const accessToken = params.get("access_token");
  const oauthError = params.get("error_description") || params.get("error");

  if (accessToken) {
    try {
      localStorage.setItem("enggii_auth_token", accessToken);

      /* The refresh token lets us silently get a new access
         token when this one expires (~1 hour). */
      const refreshToken = params.get("refresh_token");
      if (refreshToken) {
        localStorage.setItem("enggii_auth_refresh", refreshToken);
      }
    } catch (err) {
      console.error("Unable to persist Google session:", err);
    }
  }

  if (oauthError) {
    console.error("Google OAuth error:", oauthError);
  }

  /* Strip the hash so the token is never visible in the
     address bar, history or shared links. */
  history.replaceState(
    null,
    "",
    window.location.pathname + window.location.search
  );

  /* If Google sent us back to the login page, the user is
     already signed in — go to the home page instead. */
  if (
    accessToken &&
    window.location.pathname.toLowerCase().endsWith("login.html")
  ) {
    window.location.replace("../index.html");
  }
})();

/* =====================================================
   API CONFIGURATION
   Single place where the backend base URL, the auth
   token storage and the shared fetch() wrapper live.

   Every page talks ONLY to the existing Express backend
   (maths-vault backend). The browser never connects to
   Supabase directly — the backend owns the Supabase
   service key and does all authentication for us.

   For local development the backend runs on port 5000
   (see its server.js: process.env.PORT || 5000).
   ===================================================== */

/* Production: Render backend. Override from index.html via
   window.API_BASE_URL (e.g. for a different environment). */
const API_BASE_URL =
  window.API_BASE_URL || "https://enggii-tea.onrender.com";

/* localStorage keys for the session returned by
   POST /api/auth/login and POST /api/auth/register */
const TOKEN_KEY = "enggii_auth_token";
const USER_KEY = "enggii_auth_user";
const REFRESH_KEY = "enggii_auth_refresh";

/* Supabase auth endpoint — used ONLY to exchange the stored
   refresh token for a fresh access token when it expires. */
const SUPABASE_AUTH_URL = "https://oeczqbbdjifhyobhhcys.supabase.co";
const SUPABASE_PUBLISHABLE_KEY =
  "sb_publishable_7Mt2qUoOUlgNnHwWN6OUDw__Q9i1DrJ";

/* Error type with an HTTP status, so pages can tell
   "bad credentials" (401) apart from "server down" (0). */
class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "ApiError";
    this.status = status || 0;
  }
}

function defaultStatusMessage(status) {
  switch (status) {
    case 400: return "Invalid request. Please check your input and try again.";
    case 401: return "Your session has expired or your credentials are wrong. Please log in again.";
    case 403: return "You do not have permission to perform this action.";
    case 404: return "The requested item could not be found.";
    case 0:   return "Unable to connect to the server. Please make sure the backend is running and try again.";
    default:  return "Something went wrong on the server. Please try again.";
  }
}

/* ---------- Session (token + cached profile) ---------- */

function saveSession(session, user) {
  try {
    if (session && session.access_token) {
      localStorage.setItem(TOKEN_KEY, session.access_token);
    }
    if (session && session.refresh_token) {
      localStorage.setItem(REFRESH_KEY, session.refresh_token);
    }
    if (user) {
      localStorage.setItem(USER_KEY, JSON.stringify(user));
    }
  } catch (err) {
    console.error("Unable to persist session:", err);
  }
}

function getAccessToken() {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function getStoredUser() {
  try {
    return JSON.parse(localStorage.getItem(USER_KEY) || "null");
  } catch {
    return null;
  }
}

function clearSession() {
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    localStorage.removeItem(REFRESH_KEY);
  } catch { /* storage unavailable — nothing to clear */ }
}

/* ---------- Silent token refresh ---------- */

/* Access tokens live only about one hour. When one expires,
   the stored refresh token is exchanged for a fresh pair via
   Supabase's token endpoint, so the user stays logged in.
   The publishable key is public by design (the same value is
   used in login/script.js). Concurrent 401s share a single
   in-flight refresh request. */

let refreshInFlight = null;

function refreshAccessToken() {
  let refreshToken = null;
  try {
    refreshToken = localStorage.getItem(REFRESH_KEY);
  } catch { /* storage unavailable */ }

  if (!refreshToken) return Promise.resolve(false);

  if (!refreshInFlight) {
    refreshInFlight = fetch(
      SUPABASE_AUTH_URL + "/auth/v1/token?grant_type=refresh_token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          apikey: SUPABASE_PUBLISHABLE_KEY,
          Authorization: "Bearer " + SUPABASE_PUBLISHABLE_KEY,
        },
        body: JSON.stringify({ refresh_token: refreshToken }),
      }
    )
      .then(async (res) => {
        if (!res.ok) return false;
        const data = await res.json().catch(() => null);
        if (!data || !data.access_token) return false;
        try {
          localStorage.setItem(TOKEN_KEY, data.access_token);
          if (data.refresh_token) {
            localStorage.setItem(REFRESH_KEY, data.refresh_token);
          }
        } catch { /* storage unavailable */ }
        return true;
      })
      .catch(() => false)
      .finally(() => {
        refreshInFlight = null;
      });
  }

  return refreshInFlight;
}

/* ---------- Shared fetch wrapper ---------- */

async function apiFetch(path, options = {}) {
  const token = getAccessToken();

  const headers = Object.assign({}, options.headers || {});
  if (token) headers["Authorization"] = "Bearer " + token;

  let requestOptions = Object.assign({}, options, { headers });
  if (options.body && typeof options.body !== "string") {
    headers["Content-Type"] = "application/json";
    requestOptions.body = JSON.stringify(options.body);
  }

  let response;
  try {
    response = await fetch(API_BASE_URL + path, requestOptions);
  } catch {
    /* fetch() only throws TypeError here: DNS failure, refused
       connection, CORS block, offline… */
    throw new ApiError(defaultStatusMessage(0), 0);
  }

  let body = null;
  try {
    body = await response.json();
  } catch {
    /* non-JSON response (empty body, HTML error page…) */
  }

  if (!response.ok) {
    /* A 401 on a request we authenticated usually means the
       access token expired. Try ONE silent refresh with the
       stored refresh token and retry the request once; only
       when that fails too do we drop the local session. */
    if (response.status === 401 && token && !options._authRetried) {
      const refreshed = await refreshAccessToken();
      if (refreshed) {
        return apiFetch(
          path,
          Object.assign({}, options, { _authRetried: true })
        );
      }
      clearSession();
    }
    throw new ApiError(
      (body && body.message) || defaultStatusMessage(response.status),
      response.status
    );
  }

  return body;
}

/* Clean, user-facing message from any thrown error. */
function apiErrorMessage(err) {
  if (err instanceof ApiError) {
    if (err.status >= 500) return defaultStatusMessage(500);
    return err.message || defaultStatusMessage(err.status);
  }
  return "Something went wrong. Please try again.";
}

/* GET /api/auth/me — the backend is the single source of
   truth for "who is logged in". Returns the profile
   { id, name, email, role, created_at } or null. */
async function fetchCurrentUser() {
  if (!getAccessToken()) return null;
  try {
    const body = await apiFetch("/api/auth/me");
    return (body && body.data && body.data.user) || null;
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      clearSession();
    }
    return null;
  }
}

/* Guard for protected pages. Verifies the session against
   the backend (never trusts the cached copy alone) and
   redirects to the login page when there is no valid one. */
async function requireAuth() {
  const user = await fetchCurrentUser();
  if (!user) {
    clearSession();
    const inPages = window.location.pathname.includes("/pages/");
    const loginUrl = (inPages ? "../login/login.html" : "login/login.html") +
      "?next=" + encodeURIComponent(window.location.href);
    window.location.href = loginUrl;
    return null;
  }
  return user;
}