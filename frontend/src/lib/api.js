/**
 * Shared HTTP client for the Panelarr backend.
 *
 * Handles JSON encoding, error-detail extraction, and the two global
 * redirects: 401 -> /login (preserving the current location as ?next=) and
 * 403 {code: "setup_required"} -> /setup.
 */

export class ApiError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/**
 * Validate a post-login return path. Only same-origin relative paths are
 * accepted (must start with "/" and not "//" or "/\").
 *
 * @param {unknown} next Candidate path.
 * @returns {string|null} The path if safe, otherwise null.
 */
export function safeNextPath(next) {
  if (typeof next !== "string") return null;
  if (!next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) {
    return null;
  }
  if (next === "/login" || next.startsWith("/login?")) return null;
  return next;
}

/**
 * Turn a FastAPI error body into a human-readable message.
 *
 * @param {unknown} detail The `detail` field (string or validation array).
 * @param {string} fallback Message used when detail is unusable.
 * @returns {string} Display message.
 */
export function extractDetail(detail, fallback) {
  if (typeof detail === "string" && detail) return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    const msgs = detail
      .map((d) => (typeof d === "string" ? d : d?.msg))
      .filter(Boolean);
    if (msgs.length) return msgs.join("; ");
  }
  return fallback;
}

function navigateTo(url) {
  window.location.assign(url);
}

function redirectToLogin() {
  const { pathname, search, hash } = window.location;
  if (pathname === "/login") return;
  const next = safeNextPath(`${pathname}${search}${hash}`);
  navigateTo(next ? `/login?next=${encodeURIComponent(next)}` : "/login");
}

/**
 * Fetch JSON from `/api{path}`.
 *
 * @param {string} path API path (without the /api prefix).
 * @param {{body?: unknown, headers?: Record<string,string>} & RequestInit} [options]
 * @returns {Promise<any>} Parsed JSON, or null for 204.
 * @throws {ApiError} On non-2xx responses.
 */
export async function apiFetch(path, options = {}) {
  const { body, headers, ...rest } = options;
  const config = {
    ...rest,
    headers: { "Content-Type": "application/json", ...(headers || {}) },
  };
  if (body !== undefined) {
    config.body = JSON.stringify(body);
  }
  const resp = await fetch(`/api${path}`, config);
  if (!resp.ok) {
    let message = `Request failed (${resp.status})`;
    let code;
    try {
      const data = await resp.json();
      message = extractDetail(data.detail, message);
      code = data.code;
    } catch {
      // ignore parse errors
    }
    if (resp.status === 403 && code === "setup_required") {
      if (!window.location.pathname.startsWith("/setup")) navigateTo("/setup");
      throw new ApiError(403, message, code);
    }
    // Redirect to login on 401 (except for auth endpoints)
    if (resp.status === 401 && !path.startsWith("/auth/")) {
      redirectToLogin();
      throw new ApiError(401, "Authentication required", code);
    }
    throw new ApiError(resp.status, message, code);
  }
  if (resp.status === 204) return null;
  return resp.json();
}
