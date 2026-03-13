// 与 uploadService 一致：5MB 分块，单块解密与 IPC 更快
export const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB

const AES_GCM_IV_LENGTH = 12; // 96-bit
const AES_GCM_TAG_LENGTH = 128; // bits
const encoder = new TextEncoder();

/** HKDF 固定盐，用于从 KEM 共享秘密派生 AES 密钥，符合 NIST 密钥分离建议。 */
const HKDF_SALT = encoder.encode('QuantumGuard-HKDF-Salt-v1');
const HKDF_INFO_PREFIX = 'QuantumGuard-AES-GCM-v1:';

/** 将 Uint8Array 复制为独立 ArrayBuffer，以满足 Web Crypto 入参并避免部分环境下类型不兼容。 */
function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(u8.length);
  copy.set(u8);
  return copy.buffer;
}

/** 当前标准 AAD：fileId_chunkIndex，与 UPLOAD_SERVICE_AAD_FORMAT 一致 */
function buildAad(fileId: string, chunkIndex: number): Uint8Array {
  if (!fileId || typeof fileId !== 'string') throw new Error('fileId must be non-empty string');
  if (!Number.isInteger(chunkIndex) || chunkIndex < 0) {
    throw new Error('chunkIndex must be a non-negative integer');
  }
  return encoder.encode(`${fileId}_${chunkIndex}`);
}

/** 旧版 AAD（历史文件兼容）：fileId:chunk:chunkIndex */
function buildAadLegacy(fileId: string, chunkIndex: number): Uint8Array {
  if (!fileId || typeof fileId !== 'string') throw new Error('fileId must be non-empty string');
  if (!Number.isInteger(chunkIndex) || chunkIndex < 0) {
    throw new Error('chunkIndex must be a non-negative integer');
  }
  return encoder.encode(`${fileId}:chunk:${chunkIndex}`);
}

function assertSharedSecret(secret: Uint8Array): void {
  if (!(secret instanceof Uint8Array)) throw new Error('sharedSecret must be Uint8Array');
  if (secret.byteLength !== 32) {
    throw new Error(`sharedSecret must be 32 bytes for AES-256, got ${secret.byteLength}`);
  }
}

function assertIv(iv: Uint8Array): void {
  if (!(iv instanceof Uint8Array)) throw new Error('iv must be Uint8Array');
  if (iv.byteLength !== AES_GCM_IV_LENGTH) {
    throw new Error(`iv must be ${AES_GCM_IV_LENGTH} bytes, got ${iv.byteLength}`);
  }
}

export class CryptoStream {
  /** 从 KEM 共享秘密经 HKDF-SHA256 派生 AES-256 密钥；info 绑定 fileId，使同一共享秘密在不同文件中得到不同密钥。 */
  public static async deriveAesKey(sharedSecret: Uint8Array, fileId: string): Promise<CryptoKey> {
    assertSharedSecret(sharedSecret);
    if (!fileId || typeof fileId !== 'string') {
      throw new Error('fileId must be non-empty string');
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
      256
    );

    const derivedKey = new Uint8Array(derivedBits);
    return CryptoStream.importAesKey(derivedKey);
  }

  /** 将 32 字节原始密钥导入为 AES-GCM CryptoKey，供内部派生后使用。 */
  public static async importAesKey(sharedSecret: Uint8Array): Promise<CryptoKey> {
    assertSharedSecret(sharedSecret);

    const rawKeyBuffer = toArrayBuffer(sharedSecret);

    return window.crypto.subtle.importKey(
      'raw',
      rawKeyBuffer,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  public static async encryptChunk(
    chunkData: ArrayBuffer,
    aesKey: CryptoKey,
    fileId: string,
    chunkIndex: number
  ): Promise<{ ciphertext: ArrayBuffer; iv: Uint8Array }> {
    if (!(chunkData instanceof ArrayBuffer)) {
      throw new Error('chunkData must be ArrayBuffer');
    }

    const iv = window.crypto.getRandomValues(new Uint8Array(AES_GCM_IV_LENGTH));
    assertIv(iv);

    const ivBuffer = toArrayBuffer(iv);
    const aadBuffer = toArrayBuffer(buildAad(fileId, chunkIndex));

    const ciphertext = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: ivBuffer,
        additionalData: aadBuffer,
        tagLength: AES_GCM_TAG_LENGTH
      },
      aesKey,
      chunkData
    );

    return { ciphertext, iv };
  }

  public static async decryptChunk(
    encryptedData: ArrayBuffer,
    aesKey: CryptoKey,
    iv: Uint8Array,
    fileId: string,
    chunkIndex: number
  ): Promise<ArrayBuffer> {
    if (!(encryptedData instanceof ArrayBuffer)) {
      throw new Error('encryptedData must be ArrayBuffer');
    }
    assertIv(iv);

    const ivBuffer = toArrayBuffer(iv);

    const tryDecrypt = (aad: Uint8Array) =>
      window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: ivBuffer,
          additionalData: toArrayBuffer(aad),
          tagLength: AES_GCM_TAG_LENGTH
        },
        aesKey,
        encryptedData
      );

    try {
      return await tryDecrypt(buildAad(fileId, chunkIndex));
    } catch (e: unknown) {
      const err = e as { name?: string; message?: string };
      const isOpError = err?.name === 'OperationError' || String(err?.message ?? '').includes('decrypt');
      if (isOpError) {
        try {
          return await tryDecrypt(buildAadLegacy(fileId, chunkIndex));
        } catch {
          throw e;
        }
      }
      throw e;
    }
  }
}
