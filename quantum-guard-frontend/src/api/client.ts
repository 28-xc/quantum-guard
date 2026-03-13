/**
 * 后端 API 客户端配置与错误解析。
 * - 后端 FastAPI 错误响应体格式为 { detail: string }，由 parseBackendError 统一解析。
 * - 生产环境默认基地址：https://api.xiasicong.com；本地开发可通过环境变量 VITE_API_BASE_URL 覆盖。
 * - 若基地址中包含 localhost，将自动替换为 127.0.0.1，以避免 Windows 下 IPv6 优先解析导致的连接失败。
 * - 所有业务请求必须通过 apiFetch 发起，以自动附加 JWT 并在收到 401 时执行登出逻辑；Token 的 localStorage 键名须与 getAuthToken 所用常量一致。
 */
const AUTH_TOKEN_KEY = 'quantum_guard_auth_token';

function normalizeApiBase(url: string): string {
  const u = (url ?? '').trim().replace(/localhost/gi, '127.0.0.1');
  return u.endsWith('/') ? u.slice(0, -1) : u;
}
const _base = import.meta.env.VITE_API_BASE_URL ?? 'https://api.xiasicong.com';
export const API_BASE = normalizeApiBase(_base);

/** 从 localStorage 同步读取 JWT。供路由守卫等同步上下文使用；若改为异步会导致鉴权判断时 token 尚未就绪而误判为未登录。 */
export function getAuthToken(): string | null {
  if (typeof localStorage === 'undefined') return null;
  return localStorage.getItem(AUTH_TOKEN_KEY);
}

let onUnauthorized: (() => void) | null = null;
/** 注册全局 401 处理回调。在 main.ts 中设置为：清除会话状态并重定向至登录页。 */
export function setOnUnauthorized(fn: () => void): void {
  onUnauthorized = fn;
}

/**
 * 统一请求封装：自动注入 Authorization: Bearer <token>，并在响应为 401 时调用已注册的 onUnauthorized 回调。
 * 业务层禁止直接使用 fetch，须经本函数发起请求。
 * @param timeoutMs 可选。指定后将在该毫秒数后 abort 请求，避免登录/注册等长时间挂起；例如 10000 表示 10 秒超时。
 */
export async function apiFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
  timeoutMs?: number
): Promise<Response> {
  const token = getAuthToken();
  const headers = new Headers(
    input instanceof Request ? (input as Request).headers : (init?.headers ?? {})
  );
  if (token) headers.set('Authorization', `Bearer ${token}`);

  let signal = init?.signal;
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  if (timeoutMs != null && timeoutMs > 0) {
    const controller = new AbortController();
    timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    signal = controller.signal;
  }

  const res = await fetch(input instanceof Request ? new Request(input, { headers }) : input, {
    ...init,
    headers,
    ...(signal ? { signal } : {})
  });

  if (timeoutId) clearTimeout(timeoutId);
  if (res.status === 401) {
    const url = typeof input === 'string' ? input : input instanceof Request ? input.url : (input as URL).href;
    console.error('[API] 401 Unauthorized:', url);
    onUnauthorized?.();
  }
  return res;
}

export function parseBackendError(body: string): string {
  if (!body?.trim()) return '';
  try {
    const o = JSON.parse(body) as { detail?: string | unknown };
    if (o?.detail != null) {
      return typeof o.detail === 'string' ? o.detail : String(o.detail);
    }
  } catch {
    // JSON 解析失败时返回原始字符串
  }
  return body;
}

export async function ensureOk(res: Response, scene: string): Promise<Response> {
  if (res.ok) return res;
  const text = await res.text().catch(() => '');
  const msg = parseBackendError(text) || res.statusText || `${scene}失败`;
  throw new Error(msg);
}
