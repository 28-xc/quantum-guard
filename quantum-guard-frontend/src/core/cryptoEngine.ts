/**
 * 核心加密套件生成模块。基于接收方 ML-KEM 公钥执行 KEM 封装，经 HKDF 派生出文件级 AES 密钥与 fileId，供后续分块加密使用。
 */
import { KemEngine } from './kem-engine';

const MLKEM768_PUBLIC_KEY_BYTES = 1184;
const SHARED_SECRET_BYTES = 32;
const AES_KEY_BITS = 256;

const encoder = new TextEncoder();
const HKDF_SALT = encoder.encode('QuantumGuard-HKDF-Salt-v1');
const HKDF_INFO_PREFIX = 'QuantumGuard-AES-GCM-v1:';

/** 将 Uint8Array 复制为独立 ArrayBuffer，以满足 Web Crypto API 入参要求并避免调用方修改同一缓冲区。 */
function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(u8.length);
  copy.set(u8);
  return copy.buffer;
}

/** 将 ArrayBuffer 转为 Uint8Array 视图，便于长度校验与后续处理。 */
function toUint8Array(ab: ArrayBuffer): Uint8Array {
  return new Uint8Array(ab);
}

function assertUint8Array(name: string, v: unknown): asserts v is Uint8Array {
  if (!(v instanceof Uint8Array)) {
    throw new Error(`${name} 必须是 Uint8Array`);
  }
}

function assertLength(name: string, u8: Uint8Array, expected: number): void {
  if (u8.byteLength !== expected) {
    throw new Error(`${name} 长度非法: ${u8.byteLength}，期望 ${expected} 字节`);
  }
}

export interface EncryptionSuite {
  /** 经 HKDF 派生得到的 AES-256-GCM 密钥，用于后续分块加密。 */
  aesKey: CryptoKey;
  /** KEM 封装得到的密文，随元数据交付接收方，用于解封出相同共享密钥。 */
  kemCiphertext: Uint8Array;
  /** 全局唯一文件标识，参与 HKDF info 绑定，确保每文件独立密钥。 */
  fileId: string;
}

/**
 * 根据接收方 ML-KEM 公钥生成加密套件。流程：① KEM 封装得到 sharedSecret 与密文；② 生成全局唯一 fileId；
 * ③ 以 sharedSecret 与 fileId 为输入经 HKDF 派生 AES 密钥（密钥分离，不直接使用 KEM 共享秘密加密）。
 */
export async function generateEncryptionSuite(
  receiverKemPublicKey: Uint8Array
): Promise<EncryptionSuite> {
  assertUint8Array('receiverKemPublicKey', receiverKemPublicKey);
  assertLength('receiverKemPublicKey', receiverKemPublicKey, MLKEM768_PUBLIC_KEY_BYTES);

  // 1) KEM 封装
  const { ciphertext: kemCiphertext, sharedSecret } = await KemEngine.encapsulateSecret(
    receiverKemPublicKey
  );
  assertLength('sharedSecret', sharedSecret, SHARED_SECRET_BYTES);
  assertUint8Array('kemCiphertext', kemCiphertext);

  const fileId = crypto.randomUUID();

  // 2) HKDF 派生 AES-256 密钥
  const info = encoder.encode(HKDF_INFO_PREFIX + fileId);
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    toArrayBuffer(sharedSecret),
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );

  const derivedBits = await window.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: toArrayBuffer(HKDF_SALT),
      info: toArrayBuffer(info)
    },
    keyMaterial,
    AES_KEY_BITS
  );

  const derivedKeyBytes = toUint8Array(derivedBits);
  if (derivedKeyBytes.byteLength !== AES_KEY_BITS / 8) {
    throw new Error(`HKDF 派生长度异常: ${derivedKeyBytes.byteLength}，期望 ${AES_KEY_BITS / 8}`);
  }

  const aesKey = await window.crypto.subtle.importKey(
    'raw',
    derivedBits,
    { name: 'AES-GCM', length: AES_KEY_BITS },
    false,
    ['encrypt', 'decrypt']
  );

  return {
    aesKey,
    kemCiphertext: new Uint8Array(kemCiphertext),
    fileId
  };
}

const AES_KEY_BITS_EXPORT = 256;

/**
 * 接收方解密时使用：以解封得到的 sharedSecret 与 fileId 为输入，经与发送方相同的 HKDF 参数派生出一致的 AES-GCM 密钥。
 */
export async function deriveAesKeyFromSharedSecretAndFileId(
  sharedSecret: Uint8Array,
  fileId: string
): Promise<CryptoKey> {
  if (!(sharedSecret instanceof Uint8Array) || sharedSecret.byteLength !== 32) {
    throw new Error('sharedSecret 必须为 32 字节 Uint8Array');
  }
  if (!fileId || typeof fileId !== 'string') {
    throw new Error('fileId 必须为非空字符串');
  }
  const info = encoder.encode(HKDF_INFO_PREFIX + fileId);
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    toArrayBuffer(sharedSecret),
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );
  const derivedBits = await window.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: toArrayBuffer(HKDF_SALT),
      info: toArrayBuffer(info)
    },
    keyMaterial,
    AES_KEY_BITS_EXPORT
  );
  return window.crypto.subtle.importKey(
    'raw',
    derivedBits,
    { name: 'AES-GCM', length: AES_KEY_BITS_EXPORT },
    true,
    ['decrypt', 'encrypt']
  );
}
