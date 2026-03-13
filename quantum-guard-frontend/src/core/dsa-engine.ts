/** 抗量子数字签名引擎：ML-DSA-65，实现依据 NIST FIPS 204，基于 @noble/post-quantum，安全级别 192 位。 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

function toPlainUint8Array(input: Uint8Array): Uint8Array {
  const out = new Uint8Array(input.byteLength);
  out.set(input);
  return out;
}

export class DsaEngine {
  /** 生成 ML-DSA 密钥对，用于签名与验签。 */
  public static generateKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    const keys = ml_dsa65.keygen();
    return {
      publicKey: toPlainUint8Array(keys.publicKey),
      privateKey: toPlainUint8Array(keys.secretKey)
    };
  }

  // 用私钥对消息签名
  public static sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
    return toPlainUint8Array(ml_dsa65.sign(message, privateKey));
  }

  /** 使用公钥验证签名，返回验证结果。 */
  public static verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array
  ): boolean {
    return ml_dsa65.verify(signature, message, publicKey);
  }
}
