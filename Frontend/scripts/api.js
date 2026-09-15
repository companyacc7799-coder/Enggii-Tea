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
  } catch { /* storage unavailable — nothing to clear */ }
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
    /* A 401 on a request we authenticated means the stored
       token is invalid or expired — drop the local session. */
    if (response.status === 401 && token) {
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