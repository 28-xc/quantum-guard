/**
 * 本地密钥初始化：注册时生成 ML-KEM 与 ML-DSA 两对密钥，私钥写入 IndexedDB MyPrivateKeys，公钥通过 API 登记至后端。
 */
import { KemEngine } from './kem-engine';
import { DsaEngine } from './dsa-engine';
import { KeyStorage } from './key-storage';

export interface InitResult {
  userId: string;
}

/** 为指定 user_id 生成两对抗量子密钥对，私钥仅持久化于本地 IndexedDB，公钥上传至后端；私钥不得随任何请求发送。 */
export async function initializeLocalKeys(userId: string): Promise<InitResult> {
  const u = userId.trim();
  if (!u) throw new Error('userId 不能为空');

  const kemPair = await KemEngine.generateKeyPair();
  const dsaPair = DsaEngine.generateKeyPair();

  await KeyStorage.saveKeys(
    u,
    kemPair.publicKey,
    kemPair.privateKey,
    dsaPair.publicKey,
    dsaPair.privateKey
  );

  return { userId: u };
}
