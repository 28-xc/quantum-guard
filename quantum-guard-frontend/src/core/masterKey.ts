/**
 * 主密钥（MK）：MK 加密/解密、本机金库与密码盒逻辑。
 * 设计见 docs/KEY_AND_AUTH_REDESIGN.md。
 */
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

const MK_LENGTH = 32;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const PBKDF2_ITERATIONS = 100_000;
/** 密码盒 KDF 迭代数（与注册时 buildPasswordBox 一致） */
export const PASSWORD_BOX_KDF_ITERATIONS = 150_000;
const AAD_VERSION = 'v1';
const MK_LOCAL_INFO = 'mk_local';
const ASYM_PRIV_INFO = 'asym_priv_v1';

const encoder = new TextEncoder();

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(u8.length);
  copy.set(u8);
  return copy.buffer;
}

/** 将 Uint8Array 转为 base64（用于与 Tauri Rust 通信）。 */
function uint8ArrayToBase64(u8: Uint8Array): string {
  return btoa(String.fromCharCode(...Array.from(u8)));
}

/** 与后端一致：UTF-8 编码后若超过 64 字节则用 SHA-256 摘要（32 字节）作为有效密码，避免前后端不一致导致解密失败。 */
function getPasswordBytes(password: string): Uint8Array {
  const raw = encoder.encode(password);
  if (raw.length > 64) return sha256(raw);
  return raw;
}

/**
 * 使用 PBKDF2-HMAC-SHA256 从密码+盐派生 AES-256 密钥。
 * 密码会先经 getPasswordBytes 规范化（超 64 字节则 SHA-256），与后端 bcrypt 规范一致。
 * 在 Tauri 桌面/Android 下优先调用 Rust 执行，避免前端 10 万次迭代卡顿；纯 Web 下回退到 WebCrypto。
 */
export async function getAesKeyFromPassword(
  password: string,
  salt: Uint8Array,
  iterations: number
): Promise<CryptoKey> {
  const pwdBytes = getPasswordBytes(password);
  if (typeof window !== 'undefined') {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const saltB64 = uint8ArrayToBase64(salt);
      const keyB64 = await invoke<string>('derive_key_pbkdf2', {
        password_base64: uint8ArrayToBase64(pwdBytes),
        salt_base64: saltB64,
        iterations: Math.max(1, iterations)
      });
      const keyBytes = Uint8Array.from(atob(keyB64), (c) => c.charCodeAt(0));
      return crypto.subtle.importKey(
        'raw',
        toArrayBuffer(keyBytes),
        'AES-GCM',
        false,
        ['encrypt', 'decrypt']
      );
    } catch {
      /* 非 Tauri 或 invoke 失败，走 WebCrypto */
    }
  }
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(pwdBytes),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: toArrayBuffer(salt),
      iterations: Math.max(1, iterations)
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/** 用零覆写敏感 buffer，用后即焚。 */
export function zeroBuffer(buf: Uint8Array): void {
  if (buf && buf.byteLength > 0) buf.fill(0);
}

/**
 * 构建密码盒：用密码经 PBKDF2(15 万次)+AES-GCM 加密 MK，返回 salt 与密文的 base64。
 * 与注册/忘记密码上传云端的格式一致；Tauri 下 KDF 由 Rust 执行。
 */
export async function buildPasswordBox(
  mk: Uint8Array,
  password: string
): Promise<{ saltB64: string; mkEncryptedB64: string }> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const aesKey = await getAesKeyFromPassword(password, salt, PASSWORD_BOX_KDF_ITERATIONS);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv), tagLength: 128 },
    aesKey,
    toArrayBuffer(mk)
  );
  const combined = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), IV_LENGTH);
  return {
    saltB64: uint8ArrayToBase64(salt),
    mkEncryptedB64: uint8ArrayToBase64(combined)
  };
}

/** 生成 256-bit 主密钥。 */
export function generateMK(): Uint8Array {
  const out = new Uint8Array(MK_LENGTH);
  crypto.getRandomValues(out);
  return out;
}

/** 使用 PBKDF2(密码)+AES-GCM 加密 MK，AAD = user_id + mk_local + v1。返回 salt+iv+ciphertext 的 Uint8Array。Tauri 下 KDF 由 Rust 执行。 */
export async function encryptMKWithPassword(
  mk: Uint8Array,
  password: string,
  userId: string
): Promise<{ blob: Uint8Array; salt: Uint8Array; iv: Uint8Array }> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const aesKey = await getAesKeyFromPassword(password, salt, PBKDF2_ITERATIONS);
  const aad = encoder.encode(userId + MK_LOCAL_INFO + AAD_VERSION);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv), tagLength: 128, additionalData: aad },
    aesKey,
    toArrayBuffer(mk)
  );
  const blob = new Uint8Array(SALT_LENGTH + IV_LENGTH + ciphertext.byteLength);
  blob.set(salt, 0);
  blob.set(iv, SALT_LENGTH);
  blob.set(new Uint8Array(ciphertext), SALT_LENGTH + IV_LENGTH);
  return { blob, salt, iv };
}

/** 使用密码解密 MK_encrypted_local，校验 AAD。Tauri 下 KDF 由 Rust 执行。 */
export async function decryptMKWithPassword(
  blob: Uint8Array,
  password: string,
  userId: string
): Promise<Uint8Array> {
  if (blob.length < SALT_LENGTH + IV_LENGTH + 16) throw new Error('MK 密文格式无效');
  const salt = blob.subarray(0, SALT_LENGTH);
  const iv = blob.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const ciphertext = blob.subarray(SALT_LENGTH + IV_LENGTH);
  const aesKey = await getAesKeyFromPassword(password, salt, PBKDF2_ITERATIONS);
  const aad = encoder.encode(userId + MK_LOCAL_INFO + AAD_VERSION);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv), tagLength: 128, additionalData: aad },
    aesKey,
    toArrayBuffer(ciphertext)
  );
  return new Uint8Array(plain);
}

/**
 * 从密码盒解密得到 MK。格式：mk_encrypted_by_password = base64(IV_12bytes || AES-GCM_ciphertext)，
 * salt 为 password_box_salt（base64）。KDF：PBKDF2-SHA256(salt, password, PASSWORD_BOX_KDF_ITERATIONS)。Tauri 下 KDF 由 Rust 执行。
 */
export async function decryptMKFromPasswordBox(
  saltB64: string,
  mkEncryptedB64: string,
  password: string
): Promise<Uint8Array> {
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const raw = Uint8Array.from(atob(mkEncryptedB64), (c) => c.charCodeAt(0));
  if (raw.length < IV_LENGTH + 16) throw new Error('密码盒 MK 密文格式无效');
  const iv = raw.subarray(0, IV_LENGTH);
  const ciphertext = raw.subarray(IV_LENGTH);
  const aesKey = await getAesKeyFromPassword(password, salt, PASSWORD_BOX_KDF_ITERATIONS);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv), tagLength: 128 },
    aesKey,
    toArrayBuffer(ciphertext)
  );
  return new Uint8Array(plain);
}

/** 使用 MK 派生密钥并 AES-GCM 加密 KEM+DSA 私钥包。 */
export async function encryptAsymWithMK(
  kemPrivateKey: Uint8Array,
  dsaPrivateKey: Uint8Array,
  mk: Uint8Array
): Promise<Uint8Array> {
  const key = hkdf(sha256, mk, undefined, encoder.encode(ASYM_PRIV_INFO), 32);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const aesKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(new Uint8Array(key)),
    'AES-GCM',
    false,
    ['encrypt', 'decrypt']
  );
  const payload = new Uint8Array(4 + kemPrivateKey.byteLength + dsaPrivateKey.byteLength);
  new DataView(payload.buffer).setUint32(0, kemPrivateKey.byteLength, false);
  payload.set(kemPrivateKey, 4);
  payload.set(dsaPrivateKey, 4 + kemPrivateKey.byteLength);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv), tagLength: 128 },
    aesKey,
    toArrayBuffer(payload)
  );
  const out = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ciphertext), IV_LENGTH);
  key.fill(0);
  return out;
}

/** 使用 MK 解密 asym_priv_encrypted 得到 KEM 与 DSA 私钥。 */
export async function decryptAsymWithMK(
  encrypted: Uint8Array,
  mk: Uint8Array
): Promise<{ kemPrivateKey: Uint8Array; dsaPrivateKey: Uint8Array }> {
  if (encrypted.length < IV_LENGTH + 16) throw new Error('asym 密文格式无效');
  const key = hkdf(sha256, mk, undefined, encoder.encode(ASYM_PRIV_INFO), 32);
  const iv = encrypted.subarray(0, IV_LENGTH);
  const ciphertext = encrypted.subarray(IV_LENGTH);
  const aesKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(new Uint8Array(key)),
    'AES-GCM',
    false,
    ['encrypt', 'decrypt']
  );
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv), tagLength: 128 },
    aesKey,
    toArrayBuffer(ciphertext)
  );
  const raw = new Uint8Array(plain);
  const kemLen = new DataView(raw.buffer).getUint32(0, false);
  const kemPrivateKey = raw.subarray(4, 4 + kemLen);
  const dsaPrivateKey = raw.subarray(4 + kemLen);
  key.fill(0);
  return {
    kemPrivateKey: new Uint8Array(kemPrivateKey),
    dsaPrivateKey: new Uint8Array(dsaPrivateKey)
  };
}

