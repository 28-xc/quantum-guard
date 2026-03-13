/**
 * 密钥存储门面层。
 * 私钥：支持两种持久化形态——零知识金库（加密后存 IndexedDB）或旧版明文存 IndexedDB；登录解密后的明文私钥仅驻留 Pinia 内存，不落盘。
 * 公钥：统一通过后端 API 获取。
 * getKeys 的解析顺序：若当前 session 中已存在对应用户的解密后私钥则直接使用；否则从 IndexedDB 读取（明文或返回 null 需先登录解密金库）。
 */
import {
  getMyPrivateKeys,
  saveMyPrivateKeys,
  deleteMyPrivateKeys
} from './secure-sandbox';
import { API_BASE, ensureOk, apiFetch } from '../api/client';
import { useSessionStore } from '../store/session';

const MY_ID_STORAGE_KEY = 'quantum_guard_my_id';

export type StoredKeys = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  fingerprint: string;
  dsaPublicKey?: Uint8Array;
  dsaPrivateKey?: Uint8Array;
};

export function bytesToBase64(u8: Uint8Array): string {
  const chunkSize = 0x8000;
  let binary = '';
  for (let i = 0; i < u8.length; i += chunkSize) {
    const chunk = u8.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const bin = atob(base64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function makeFingerprint(publicKey: Uint8Array): string {
  return Array.from(publicKey.slice(0, 16))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':')
    .toUpperCase();
}

function getCurrentUserId(): string {
  return (typeof localStorage !== 'undefined' ? localStorage.getItem(MY_ID_STORAGE_KEY) : null) ?? '';
}

/** 持久化密钥：将 KEM 与 DSA 私钥写入本地 MyPrivateKeys；公钥通过 POST /keys/upload 上传至后端。私钥仅存本地，不得随任何请求发送。 */
export async function saveKeys(
  userId: string,
  kemPublicKey: Uint8Array,
  kemPrivateKey: Uint8Array,
  dsaPublicKey: Uint8Array,
  dsaPrivateKey: Uint8Array
): Promise<void> {
  const u = userId.trim();
  if (!u) throw new Error('userId 不能为空');
  await saveMyPrivateKeys(u, kemPrivateKey, dsaPrivateKey);
  await ensureOk(
    await apiFetch(`${API_BASE}/keys/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: u,
        kem_public_key: bytesToBase64(kemPublicKey),
        dsa_public_key: bytesToBase64(dsaPublicKey)
      })
    }),
    '公钥登记'
  );
}

/**
 * 获取指定用户的密钥对。优先使用 Pinia 中已解密的会话私钥；若无则从 IndexedDB 读取明文私钥（旧版）或返回 null（新版金库须先登录解密）。
 * 公钥始终通过 API 拉取。返回 null 表示无可用私钥；抛出异常通常表示网络或后端请求失败。
 */
export async function getKeys(userId?: string): Promise<StoredKeys | null> {
  const uid = (userId ?? getCurrentUserId()).trim();
  if (!uid) return null;

  const session = useSessionStore();
  if (session.currentUserId === uid && session.kemPrivateKey && session.dsaPrivateKey) {
    try {
      const res = await apiFetch(`${API_BASE}/keys/${encodeURIComponent(uid)}`);
      if (!res.ok) {
        if (res.status === 404) return null;
        await ensureOk(res, '拉取公钥');
      }
      const data = (await res.json()) as { kem_public_key?: string; dsa_public_key?: string };
      const kemB64 = data.kem_public_key;
      if (!kemB64) return null;
      const publicKey = base64ToBytes(kemB64);
      return {
        publicKey,
        privateKey: session.kemPrivateKey,
        fingerprint: makeFingerprint(publicKey),
        dsaPublicKey: data.dsa_public_key ? base64ToBytes(data.dsa_public_key) : undefined,
        dsaPrivateKey: session.dsaPrivateKey
      };
    } catch (e) {
      console.error('[KeyStorage] 拉取公钥失败（网络或后端异常）', e);
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('fetch') || msg.includes('Failed to fetch') || msg.includes('NetworkError')) {
        throw new Error('拉取公钥失败：无法连接后端（请确认后端已启动且 API 地址正确）');
      }
      throw e;
    }
  }

  const record = await getMyPrivateKeys(uid);
  if (!record?.kem_private_key || !record?.dsa_private_key) return null;

  try {
    const res = await apiFetch(`${API_BASE}/keys/${encodeURIComponent(uid)}`);
    if (!res.ok) {
      if (res.status === 404) return null;
      await ensureOk(res, '拉取公钥');
    }
    const data = (await res.json()) as {
      kem_public_key?: string;
      dsa_public_key?: string;
    };
    const kemB64 = data.kem_public_key;
    if (!kemB64) return null;

    const publicKey = base64ToBytes(kemB64);
    const fingerprint = makeFingerprint(publicKey);
    const result: StoredKeys = {
      publicKey,
      privateKey: record.kem_private_key,
      fingerprint
    };
    if (data.dsa_public_key) {
      result.dsaPublicKey = base64ToBytes(data.dsa_public_key);
      result.dsaPrivateKey = record.dsa_private_key;
    }
    return result;
  } catch (e) {
    console.error('[KeyStorage] 拉取公钥失败（网络或后端异常）', e);
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes('fetch') || msg.includes('Failed to fetch') || msg.includes('NetworkError')) {
      throw new Error('拉取公钥失败：无法连接后端（请确认后端已启动且 API 地址正确）');
    }
    throw e;
  }
}

/** 清除本地持久化的私钥。若传入 userId 则仅删除该用户记录；否则删除当前登录用户（从 localStorage 读取）对应的记录。 */
export async function clearKeys(userId?: string): Promise<void> {
  const uid = (userId ?? getCurrentUserId()).trim();
  if (!uid) return;
  await deleteMyPrivateKeys(uid);
}

/** 命名空间导出，兼容既有调用方通过 KeyStorage.getKeys 等形式的访问。 */
export const KeyStorage = {
  saveKeys,
  getKeys,
  clearKeys
};
