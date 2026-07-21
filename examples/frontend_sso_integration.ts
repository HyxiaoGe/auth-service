/**
 * 浏览器（Next.js / React）接入 auth-client-web 0.4.x 的完整起点。
 *
 * 安装：
 *   npm install auth-client-web@^0.4.0
 *
 * SDK 无 UI：应用自己实现登录弹窗、邮箱/验证码输入框、加载态和错误提示。
 * 完整说明见 docs/INTEGRATION_GUIDE.md，协议字段见 docs/AUTH_CONTRACT.md。
 */

import {
  AuthClientError,
  cancelAuthorization,
  completeAuthorization,
  configure,
  fetchWithAuth,
  handleCallback,
  login as sdkLogin,
  logout as sdkLogout,
  prepareAuthorization,
  reconcileSession,
  refresh,
  resumeSession,
  subscribe,
  tokenStore,
  type AuthState,
  type AuthUser,
  type PreparedAuthorization,
} from "auth-client-web";

const AUTH_URL = process.env.NEXT_PUBLIC_AUTH_URL || "http://localhost:8100";
const CLIENT_ID = process.env.NEXT_PUBLIC_AUTH_CLIENT_ID || "";

let configured = false;

/** 只在浏览器启动时调用；不要在 SSR 阶段执行。 */
export function configureAuth(): void {
  if (configured || typeof window === "undefined") return;
  configure({
    authUrl: AUTH_URL,
    clientId: CLIENT_ID,
    redirectUri: `${window.location.origin}/auth/callback`,
  });
  configured = true;
}

/** 将 SDK 的可观察状态桥接到 Redux、Zustand、React context 等应用状态。 */
export function bridgeAuthState(onChange: (state: AuthState) => void): () => void {
  configureAuth();
  return subscribe(onChange);
}

// ---------------------------------------------------------------------------
// Google / GitHub 与回调页
// ---------------------------------------------------------------------------

export function loginWith(provider: "google" | "github", redirectPath = "/"): Promise<void> {
  configureAuth();
  return sdkLogin(provider, { redirectPath });
}

/** 在已登记的 /auth/callback 客户端页面调用一次。 */
export async function completeLoginCallback(): Promise<string> {
  configureAuth();
  const result = await handleCallback();
  if (result.status === "authenticated") return result.redirectPath || "/";
  // prompt=none 没有中央会话时会得到 unauthenticated；这是正常降级。
  return "/";
}

// ---------------------------------------------------------------------------
// 启动恢复与跨应用账户对账
// ---------------------------------------------------------------------------

export type SessionIsolation = {
  /** 中止旧请求、SSE/WebSocket，并清理用户绑定缓存和敏感路由。 */
  clearUserState: (previousUser: AuthUser | null, nextUser: AuthUser | null) => void | Promise<void>;
};

/**
 * 首次客户端挂载、窗口 focus、页面 visibilitychange 回到 visible 时调用，并由宿主防抖。
 * SDK 不会自行启动轮询。
 */
export async function restoreOrReconcileSession(isolation: SessionIsolation) {
  configureAuth();
  const resume = () => resumeSession({
    beforeCommit: ({ user }) => isolation.clearUserState(null, user),
  });
  // 不先调用 getAccessToken()；它可能 refresh 旧账户票据。reconcile 必须先对账中央 session。
  const store = tokenStore();
  const localToken = store.getAccessToken();

  if (!localToken) return resume();

  const reconcile = () => reconcileSession({
    beforeCommit: ({ previousUser, user }) => isolation.clearUserState(previousUser, user),
  });
  let result;
  try {
    result = await reconcile();
  } catch (error) {
    if (!(error instanceof AuthClientError) || error.status !== 401) throw error;
    const refreshed = await refresh();
    if (!refreshed) return resume();
    result = await reconcile();
  }
  if (result.status === "no_session") {
    await isolation.clearUserState(store.getUser<AuthUser>(), null);
    await sdkLogout();
  }
  return result;
}

// ---------------------------------------------------------------------------
// 邮箱验证码 headless 登录（应用内弹窗）
// ---------------------------------------------------------------------------

type Capabilities = {
  email_headless_login?: boolean;
};

type EmailStartResponse = {
  flow_id: string;
  csrf_token: string;
  expires_in: number;
  code_length: number;
};

type EmailSendResponse = {
  accepted: true;
  next: "verify";
  expires_in: number;
  resend_after: number;
  masked_destination: string;
};

type EmailVerifyResponse = {
  code: string;
  state: string;
  expires_in: number;
};

export type EmailLoginTransaction = {
  authorization: PreparedAuthorization;
  flowId: string;
  csrfToken: string;
  expiresIn: number;
  codeLength: number;
};

export async function emailLoginAvailable(): Promise<boolean> {
  configureAuth();
  const redirectUri = `${window.location.origin}/auth/callback`;
  const url = new URL(`${AUTH_URL}/auth/capabilities`);
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("redirect_uri", redirectUri);
  const response = await fetch(url, { credentials: "include" });
  const capabilities = await parseAuthResponse<Capabilities>(response);
  return capabilities.email_headless_login === true;
}

/** 用户打开邮箱登录交互时创建一笔新的 PKCE/state 事务。 */
export async function beginEmailLogin(redirectPath = "/"): Promise<EmailLoginTransaction> {
  configureAuth();
  const authorization = await prepareAuthorization({ redirectPath });

  try {
    const started = await fetch(`${AUTH_URL}/auth/email/headless/start`, {
      method: "POST",
      credentials: "include",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_id: authorization.clientId,
        redirect_uri: authorization.redirectUri,
        response_type: authorization.responseType,
        state: authorization.state,
        code_challenge: authorization.codeChallenge,
        code_challenge_method: authorization.codeChallengeMethod,
      }),
    }).then(parseAuthResponse<EmailStartResponse>);

    return {
      authorization,
      flowId: started.flow_id,
      csrfToken: started.csrf_token,
      expiresIn: started.expires_in,
      codeLength: started.code_length,
    };
  } catch (error) {
    cancelAuthorization(authorization.state);
    throw error;
  }
}

export async function sendEmailCode(
  transaction: EmailLoginTransaction,
  email: string,
): Promise<EmailSendResponse> {
  const response = await fetch(`${AUTH_URL}/auth/email/headless/send`, {
    method: "POST",
    credentials: "include",
    headers: {
      "content-type": "application/json",
      "x-csrf-token": transaction.csrfToken,
    },
    body: JSON.stringify({ flow_id: transaction.flowId, email }),
  });
  return parseAuthResponse<EmailSendResponse>(response);
}

export async function verifyEmailCode(transaction: EmailLoginTransaction, code: string) {
  const response = await fetch(`${AUTH_URL}/auth/email/headless/verify`, {
    method: "POST",
    credentials: "include",
    headers: {
      "content-type": "application/json",
      "x-csrf-token": transaction.csrfToken,
    },
    body: JSON.stringify({ flow_id: transaction.flowId, code }),
  });
  const verified = await parseAuthResponse<EmailVerifyResponse>(response);
  return completeAuthorization({
    authorizationCode: verified.code,
    state: verified.state,
  });
}

/** 用户主动关闭弹窗时取消当前事务，不影响其他标签页或登录事务。 */
export function cancelEmailLogin(transaction: EmailLoginTransaction): void {
  cancelAuthorization(transaction.authorization.state);
}

type AuthErrorPayload = {
  error?: string;
  error_description?: string;
  retry_after?: number;
};

async function parseAuthResponse<T>(response: Response): Promise<T> {
  const payload = (await response.json().catch(() => ({}))) as T & AuthErrorPayload;
  if (!response.ok) {
    // 产品代码应按稳定的 error / retry_after 映射本地化提示，不解析 message 文案。
    const error = new Error(payload.error || `auth request failed (${response.status})`);
    Object.assign(error, {
      code: payload.error,
      description: payload.error_description,
      retryAfter: payload.retry_after,
      status: response.status,
    });
    throw error;
  }
  return payload;
}

// ---------------------------------------------------------------------------
// 业务 API 与退出
// ---------------------------------------------------------------------------

export async function getProfile(): Promise<unknown> {
  configureAuth();
  const response = await fetchWithAuth("/api/profile");
  return response.json();
}

export async function logout(global = false): Promise<void> {
  configureAuth();
  await sdkLogout(
    global
      ? { global: true, postLogoutRedirectUri: `${window.location.origin}/auth/callback` }
      : { redirectTo: "/" },
  );
}
