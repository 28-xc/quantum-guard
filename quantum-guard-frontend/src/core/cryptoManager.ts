/**
 * 零知识本地金库：以用户密码经 PBKDF2 派生 AES 密钥，对 ML-KEM/ML-DSA 私钥加密后存入 IndexedDB；
 * 解密仅在登录时执行一次，解密所得明文私钥仅驻留内存，不落盘。
 * 密码规范与后端一致：UTF-8 超 64 字节时用 SHA-256 摘要作为有效密码。
 */
import { sha256 } from '@noble/hashes/sha2.js';

const PBKDF2_ITERATIONS = 100_000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const AES_KEY_LENGTH = 256;

const encoder = new TextEncoder();

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(u8.length);
  copy.set(u8);
  return copy.buffer;
}

function getPasswordBytes(password: string): Uint8Array {
  const raw = encoder.encode(password);
  if (raw.length > 64) return sha256(raw);
  return raw;
}

/** 使用 PBKDF2-SHA256、100000 次迭代，从密码与 salt 派生出 256 位 AES 密钥；密码先经 getPasswordBytes 规范化。 */
export async function deriveAesKeyFromPassword(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const pwdBytes = getPasswordBytes(password);
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    toArrayBuffer(pwdBytes),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );
  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: toArrayBuffer(salt),
      iterations: PBKDF2_ITERATIONS
    },
    keyMaterial,
    { name: 'AES-GCM', length: AES_KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

/** 将 ML-KEM 与 ML-DSA 私钥打包后加密，返回密文、salt 与 iv；三者须一并存入 IndexedDB。 */
export async function encryptPrivateKeys(
  kemPrivateKey: Uint8Array,
  dsaPrivateKey: Uint8Array,
  password: string
): Promise<{ encrypted: Uint8Array; salt: Uint8Array; iv: Uint8Array }> {
  const salt = window.crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const aesKey = await deriveAesKeyFromPassword(password, salt);

  const kemLen = kemPrivateKey.byteLength;
  const payload = new Uint8Array(4 + kemLen + dsaPrivateKey.byteLength);
  new DataView(payload.buffer).setUint32(0, kemLen, false);
  payload.set(kemPrivateKey, 4);
  payload.set(dsaPrivateKey, 4 + kemLen);

  const ciphertext = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv), tagLength: 128 },
    aesKey,
    toArrayBuffer(payload)
  );

  return {
    encrypted: new Uint8Array(ciphertext),
    salt,
    iv
  };
}

/**
 * 使用从 IndexedDB 读取的密文、salt 与 iv，以密码派生密钥并解密。若密码错误或数据遭篡改将抛出 DOMException，
 * 调用方须清除 Token 并提示用户。
 */
export async function decryptPrivateKeys(
  encrypted: Uint8Array,
  salt: Uint8Array,
  iv: Uint8Array,
  password: string
): Promise<{ kemPrivateKey: Uint8Array; dsaPrivateKey: Uint8Array }> {
  const aesKey = await deriveAesKeyFromPassword(password, salt);
  const plain = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv), tagLength: 128 },
    aesKey,
    toArrayBuffer(encrypted)
  );
  const raw = new Uint8Array(plain);
  const kemLen = new DataView(raw.buffer).getUint32(0, false);
  const kemPrivateKey = raw.subarray(4, 4 + kemLen);
  const dsaPrivateKey = raw.subarray(4 + kemLen);
  return {
    kemPrivateKey: new Uint8Array(kemPrivateKey),
    dsaPrivateKey: new Uint8Array(dsaPrivateKey)
  };
}

