/** 抗量子密钥封装引擎：ML-KEM-768，实现依据 NIST FIPS 203，依赖 mlkem 库。 */
import { MlKem768 } from 'mlkem';

const MLKEM768_PUBLIC_KEY_BYTES = 1184;
const MLKEM768_PRIVATE_KEY_BYTES = 2400;
const MLKEM768_CIPHERTEXT_BYTES = 1088;
const SHARED_SECRET_BYTES = 32;

const kem = new MlKem768();

/** 兼容运行环境可能不提供 Error.cause 的 TypeScript/库用法。 */
type ErrorWithCause = Error & { cause?: unknown };

function createError(message: string, cause?: unknown): Error {
  const err: ErrorWithCause = new Error(message);
  if (cause !== undefined) {
    err.cause = cause;
  }
  return err;
}

function toPlainUint8Array(input: Uint8Array): Uint8Array {
  const out = new Uint8Array(input.byteLength);
  out.set(input);
  return out;
}

function assertUint8Array(name: string, v: Uint8Array): void {
  if (!(v instanceof Uint8Array)) {
    throw new Error(`${name} 必须是 Uint8Array`);
  }
}

function assertLength(name: string, v: Uint8Array, expected: number): void {
  if (v.byteLength !== expected) {
    throw new Error(`${name} 长度非法: ${v.byteLength}，期望 ${expected} 字节`);
  }
}

export class KemEngine {
  /** 生成 ML-KEM-768 密钥对。 */
  public static async generateKeyPair(): Promise<{
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  }> {
    try {
      const [pkRaw, skRaw] = await kem.generateKeyPair();

      const publicKey = toPlainUint8Array(new Uint8Array(pkRaw));
      const privateKey = toPlainUint8Array(new Uint8Array(skRaw));

      assertLength('publicKey', publicKey, MLKEM768_PUBLIC_KEY_BYTES);
      assertLength('privateKey', privateKey, MLKEM768_PRIVATE_KEY_BYTES);

      return { publicKey, privateKey };
    } catch (error) {
      console.error('🚨 密钥生成失败:', error);
      throw createError('密钥生成失败，请检查运行环境或 mlkem 初始化状态', error);
    }
  }

  /** 发送方调用：以接收方公钥执行封装，输出密文与 32 字节共享密钥。 */
  public static async encapsulateSecret(publicKey: Uint8Array): Promise<{
    ciphertext: Uint8Array;
    sharedSecret: Uint8Array;
  }> {
    assertUint8Array('publicKey', publicKey);
    assertLength('publicKey', publicKey, MLKEM768_PUBLIC_KEY_BYTES);

    try {
      const normalizedPk = toPlainUint8Array(publicKey);
      const [ciphertextRaw, sharedSecretRaw] = await kem.encap(normalizedPk);

      const ciphertext = toPlainUint8Array(new Uint8Array(ciphertextRaw));
      const sharedSecret = toPlainUint8Array(new Uint8Array(sharedSecretRaw));

      assertLength('ciphertext', ciphertext, MLKEM768_CIPHERTEXT_BYTES);
      assertLength('sharedSecret', sharedSecret, SHARED_SECRET_BYTES);

      return { ciphertext, sharedSecret };
    } catch (error) {
      throw createError('密钥封装失败，请检查公钥格式与长度', error);
    }
  }

  /** 接收方调用：以密文与己方私钥执行解封，输出 32 字节共享密钥。 */
  public static async decapsulateSecret(
    ciphertext: Uint8Array,
    privateKey: Uint8Array
  ): Promise<Uint8Array> {
    assertUint8Array('ciphertext', ciphertext);
    assertUint8Array('privateKey', privateKey);
    assertLength('ciphertext', ciphertext, MLKEM768_CIPHERTEXT_BYTES);
    assertLength('privateKey', privateKey, MLKEM768_PRIVATE_KEY_BYTES);

    try {
      const normalizedCt = toPlainUint8Array(ciphertext);
      const normalizedSk = toPlainUint8Array(privateKey);

      const sharedSecretRaw = await kem.decap(normalizedCt, normalizedSk);
      const sharedSecret = toPlainUint8Array(new Uint8Array(sharedSecretRaw));

      assertLength('sharedSecret', sharedSecret, SHARED_SECRET_BYTES);
      return sharedSecret;
    } catch (error) {
      throw createError('密钥解封失败，密文可能被篡改或私钥不匹配', error);
    }
  }
}
