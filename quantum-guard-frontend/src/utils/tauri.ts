/**
 * Tauri 环境检测：终极暴力版，专治各种 V2 环境识别失败
 */
type WindowWithTauri = Window & {
  __TAURI_IPC__?: unknown;
  __TAURI_INTERNALS__?: unknown;
  __TAURI__?: unknown;
};

export function isTauri(): boolean {
  if (typeof window === 'undefined') return false;

  const w = window as WindowWithTauri;

  // 1. 核心命脉：检查 Tauri 进程间通信接口 (只要是 Tauri 壳子，绝对有它)
  if (w.__TAURI_IPC__ !== undefined) return true;

  // 2. 检查 Tauri 暴露的其他全局对象
  if (w.__TAURI_INTERNALS__ !== undefined) return true;
  if (w.__TAURI__ !== undefined) return true;

  // 3. 最后的兜底：环境变量
  const env = typeof import.meta !== 'undefined' ? (import.meta as { env?: { TAURI_ENV_PLATFORM?: string } }).env : undefined;
  const hasEnv = env?.TAURI_ENV_PLATFORM;

  return !!hasEnv;
}
