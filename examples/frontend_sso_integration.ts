/**
 * Example: browser (Next.js / React) SSO integration with the shared auth-client-web SDK.
 *
 * Install:
 *   npm install git+https://github.com/HyxiaoGe/auth-client-web.git
 *
 * The SDK is framework-neutral and owns the whole token lifecycle: the PKCE login
 * redirect, the state-validated callback exchange, on-demand + coalesced refresh, and
 * revoke. Your app wires four call sites and mirrors {user, status} into its own store.
 *
 * This single file shows every piece; in a real app split them into modules
 * (auth-sdk.ts / sso-probe.ts / app/auth/callback/page.tsx / a login button).
 * See docs/AUTH_CONTRACT.md for the wire contract and docs/ONBOARDING.md for the steps.
 */

import {
  configure,
  login as sdkLogin,
  silentLogin,
  handleCallback,
  getAccessToken,
  fetchWithAuth,
  logout as sdkLogout,
  subscribe,
  type AuthState,
} from "auth-client-web";

// ---------------------------------------------------------------------------
// 1. configure() once, idempotently (safe to call from any call site)
// ---------------------------------------------------------------------------
const AUTH_URL = process.env.NEXT_PUBLIC_AUTH_URL || "http://localhost:8100";
const CLIENT_ID = process.env.NEXT_PUBLIC_AUTH_CLIENT_ID || "";

let configured = false;
export function configureAuth(): void {
  if (configured || typeof window === "undefined") return;
  configure({
    authUrl: AUTH_URL,
    clientId: CLIENT_ID,
    redirectUri: `${window.location.origin}/auth/callback`,
    // A fresh app can omit `storageKeys` (defaults: acw_*). A MIGRATING app passes its
    // existing localStorage keys here so already-logged-in users are not logged out.
  });
  configured = true;
}

// ---------------------------------------------------------------------------
// 2. One-shot silent SSO probe on app load (the SSO win)
// ---------------------------------------------------------------------------
const PROBED_KEY = "sso_probed";
const ACCESS_TOKEN_KEY = "acw_access_token"; // match configure()'s storageKeys if overridden

/** Reject open-redirect vectors (CWE-601): only same-origin single-slash paths. */
export function isSafeReturnPath(path: string): boolean {
  return /^\/(?!\/)/.test(path.replace(/\\/g, "/"));
}

/**
 * Call on app load. Returns true if it fired a redirect (the caller must then bail and
 * not render/initialize, because the page is navigating away).
 */
export function maybeSilentLogin(currentPath: string): boolean {
  if (typeof window === "undefined") return false;
  let s: Storage;
  try {
    s = window.sessionStorage;
  } catch {
    return false; // sessionStorage unavailable -> don't probe
  }
  if (currentPath.startsWith("/auth/callback")) return false; // never probe on the callback
  if (s.getItem(PROBED_KEY)) return false; // at most one probe per tab
  if (window.localStorage.getItem(ACCESS_TOKEN_KEY)) return false; // already have a token
  s.setItem(PROBED_KEY, "1"); // written synchronously BEFORE the redirect
  configureAuth();
  void silentLogin(); // top-level redirect to /auth/authorize?prompt=none
  return true;
}

/** Call on logout so the next load does not immediately silent-login back in. */
export function markSsoProbed(): void {
  try {
    window.sessionStorage.setItem(PROBED_KEY, "1");
  } catch {
    /* ignore */
  }
}

// ---------------------------------------------------------------------------
// 3. Callback page (app/auth/callback/page.tsx)
// ---------------------------------------------------------------------------
//   "use client";
//   export default function CallbackPage() {
//     const router = useRouter();
//     const processed = useRef(false);
//     useEffect(() => {
//       if (processed.current) return;
//       processed.current = true;
//       completeLogin().then((to) => router.replace(to));
//     }, [router]);
//     return <p>Signing you in…</p>;
//   }
export async function completeLogin(): Promise<string> {
  configureAuth();
  const result = await handleCallback(); // validates state, exchanges code, stores tokens
  if (result.status === "authenticated") {
    // result.user is available; mirror it into your store if you are not using subscribe()
    return result.redirectPath || "/";
  }
  // login_required (expected for a cold prompt=none probe) and provider errors land here.
  // Do NOT show an error screen for "login_required" — fall back to interactive login.
  return "/";
}

// ---------------------------------------------------------------------------
// 4. Login UI
// ---------------------------------------------------------------------------
export function loginWith(provider: "google" | "github", redirectPath = "/"): void {
  configureAuth();
  void sdkLogin(provider, { redirectPath }).catch(() => {
    /* surface a toast in your UI */
  });
}

export async function logout(): Promise<void> {
  configureAuth();
  markSsoProbed();
  await sdkLogout({ redirectTo: "/" });
}

// ---------------------------------------------------------------------------
// 5. Calling protected APIs
// ---------------------------------------------------------------------------
// Easiest: use the SDK's fetchWithAuth (injects Bearer, refreshes once on 401).
export async function getProfile(): Promise<unknown> {
  configureAuth();
  const res = await fetchWithAuth("/api/profile");
  return res.json();
}
// Or, if you need a custom fetch wrapper (response envelopes, locale headers, ...),
// grab the token yourself and build the request:
export async function customCall(): Promise<unknown> {
  configureAuth();
  const token = await getAccessToken(); // null => not authenticated
  const res = await fetch("/api/profile", {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  return res.json();
}

// ---------------------------------------------------------------------------
// 6. (Optional) reactive bridge into your framework store
// ---------------------------------------------------------------------------
// subscribe() pushes {user, status} on every change (login, refresh, logout) so your
// store stays in sync without manual mirroring. Call once at startup.
export function bridgeAuthState(onChange: (s: AuthState) => void): () => void {
  configureAuth();
  return subscribe(onChange); // returns an unsubscribe fn
}
