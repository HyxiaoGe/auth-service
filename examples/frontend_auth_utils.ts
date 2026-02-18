/**
 * Example: React/Next.js frontend integration with Auth Service
 *
 * This shows the auth utility functions your frontend projects would use.
 * Copy this file into your frontend project and customize AUTH_URL.
 */

const AUTH_URL = process.env.NEXT_PUBLIC_AUTH_URL || "http://localhost:8100";
const APP_CLIENT_ID = process.env.NEXT_PUBLIC_AUTH_CLIENT_ID || "your_app_client_id";

// ============================================================
// Token storage (in-memory for security, or HttpOnly cookie)
// ============================================================
let accessToken: string | null = null;

export function getAccessToken(): string | null {
  return accessToken;
}

export function setTokens(access: string, refresh: string) {
  accessToken = access;
  // Store refresh token in HttpOnly cookie (set by Auth Service)
  // or in localStorage as fallback for SPA
  localStorage.setItem("refresh_token", refresh);
}

export function clearTokens() {
  accessToken = null;
  localStorage.removeItem("refresh_token");
}

// ============================================================
// Auth API calls
// ============================================================

/** Email/password login */
export async function login(email: string, password: string) {
  const res = await fetch(`${AUTH_URL}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, client_id: APP_CLIENT_ID }),
  });
  if (!res.ok) throw new Error("Login failed");
  const data = await res.json();
  setTokens(data.access_token, data.refresh_token);
  return data;
}

/** Email/password registration */
export async function register(email: string, password: string, name?: string) {
  const res = await fetch(`${AUTH_URL}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, name }),
  });
  if (!res.ok) throw new Error("Registration failed");
  const data = await res.json();
  setTokens(data.access_token, data.refresh_token);
  return data;
}

/** Redirect to Google OAuth */
export function loginWithGoogle() {
  window.location.href = `${AUTH_URL}/auth/oauth/google?client_id=${APP_CLIENT_ID}`;
}

/** Redirect to GitHub OAuth */
export function loginWithGitHub() {
  window.location.href = `${AUTH_URL}/auth/oauth/github?client_id=${APP_CLIENT_ID}`;
}

/** Silent token refresh */
export async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = localStorage.getItem("refresh_token");
  if (!refreshToken) return null;

  try {
    const res = await fetch(`${AUTH_URL}/auth/token/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) {
      clearTokens();
      return null;
    }
    const data = await res.json();
    setTokens(data.access_token, data.refresh_token);
    return data.access_token;
  } catch {
    clearTokens();
    return null;
  }
}

/** Logout */
export async function logout() {
  const refreshToken = localStorage.getItem("refresh_token");
  if (refreshToken) {
    await fetch(`${AUTH_URL}/auth/token/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    }).catch(() => {});
  }
  clearTokens();
}

/** Get current user info */
export async function getUserInfo() {
  const token = getAccessToken();
  if (!token) return null;

  const res = await fetch(`${AUTH_URL}/auth/userinfo`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return null;
  return res.json();
}

// ============================================================
// Axios/Fetch interceptor for automatic token refresh
// ============================================================

/**
 * Wrapper around fetch that automatically handles token refresh on 401.
 *
 * Usage:
 *   const data = await authFetch("/api/movies/recommendations");
 */
export async function authFetch(url: string, options: RequestInit = {}) {
  const token = getAccessToken();
  const headers = {
    ...options.headers,
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  let res = await fetch(url, { ...options, headers });

  // If 401, try refreshing the token and retry once
  if (res.status === 401) {
    const newToken = await refreshAccessToken();
    if (newToken) {
      res = await fetch(url, {
        ...options,
        headers: { ...options.headers, Authorization: `Bearer ${newToken}` },
      });
    } else {
      // Refresh failed — redirect to login
      window.location.href = "/login";
    }
  }

  return res;
}
