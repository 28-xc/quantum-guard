/**
 * 本地安全沙箱：基于 idb 封装的 IndexedDB 访问层。
 * - MyPrivateKeys：以 user_id 为主键，存储当前用户的 ML-KEM 与 ML-DSA 私钥（明文或金库加密形态）。
 * - ContactFingerprints：以 contact_id 为主键，存储联系人公钥指纹，用于 TOFU（Trust On First Use）首次使用时的带外核验。
 */
import { openDB, type DBSchema, type IDBPDatabase } from 'idb';

const DB_NAME = 'QuantumGuardSandbox';
const DB_VERSION = 1;

export interface MyPrivateKeysRecord {
  user_id: string;
  kem_private_key?: Uint8Array;
  dsa_private_key?: Uint8Array;
  /** v1 金库：加密后的私钥密文、salt 与 iv。 */
  encrypted_private_keys?: Uint8Array;
  salt?: Uint8Array;
  iv?: Uint8Array;
  /** v2 主密钥方案：格式标识。 */
  format?: 'v1' | 'v2';
  /** v2：密码加密的 MK（salt+iv+ciphertext）。 */
  mk_encrypted_local?: Uint8Array;
  /** v2：MK 加密的 KEM+DSA 私钥包。 */
  asym_priv_encrypted?: Uint8Array;
  updated_at: number;
}

export interface ContactFingerprintsRecord {
  contact_id: string;
  kem_fingerprint: string;
  dsa_fingerprint?: string;
  updated_at: number;
}

interface SandboxDBSchema extends DBSchema {
  MyPrivateKeys: {
    key: string;
    value: MyPrivateKeysRecord;
  };
  ContactFingerprints: {
    key: string;
    value: ContactFingerprintsRecord;
  };
}

let dbPromise: Promise<IDBPDatabase<SandboxDBSchema>> | null = null;

function getDB(): Promise<IDBPDatabase<SandboxDBSchema>> {
  if (!dbPromise) {
    dbPromise = openDB<SandboxDBSchema>(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains('MyPrivateKeys')) {
          db.createObjectStore('MyPrivateKeys', { keyPath: 'user_id' });
        }
        if (!db.objectStoreNames.contains('ContactFingerprints')) {
          db.createObjectStore('ContactFingerprints', { keyPath: 'contact_id' });
        }
      }
    });
  }
  return dbPromise;
}

/** 将当前用户的 ML-KEM 与 ML-DSA 私钥以明文形式写入 MyPrivateKeys，主键为 user_id。 */
export async function saveMyPrivateKeys(
  userId: string,
  kemPrivateKey: Uint8Array,
  dsaPrivateKey: Uint8Array
): Promise<void> {
  const u = userId.trim();
  if (!u) throw new Error('userId 不能为空');
  const db = await getDB();
  const record: MyPrivateKeysRecord = {
    user_id: u,
    kem_private_key: new Uint8Array(kemPrivateKey),
    dsa_private_key: new Uint8Array(dsaPrivateKey),
    updated_at: Date.now()
  };
  await db.put('MyPrivateKeys', record);
}

/** 读取指定用户的私钥记录，仅支持旧版明文存储格式；若为金库加密存储须使用 getEncryptedPrivateKeys。 */
export async function getMyPrivateKeys(userId: string): Promise<MyPrivateKeysRecord | null> {
  const u = userId.trim();
  if (!u) return null;
  const db = await getDB();
  const record = await db.get('MyPrivateKeys', u);
  if (!record || record.encrypted_private_keys != null) return null;
  if (record.kem_private_key && record.dsa_private_key) return record;
  return null;
}

/** 零知识金库：将已加密的私钥密文、salt 与 iv 写入 MyPrivateKeys；禁止写入明文私钥。 */
export async function saveEncryptedPrivateKeys(
  userId: string,
  encrypted: Uint8Array,
  salt: Uint8Array,
  iv: Uint8Array
): Promise<void> {
  const u = userId.trim();
  if (!u) throw new Error('userId 不能为空');
  const db = await getDB();
  await db.put('MyPrivateKeys', {
    user_id: u,
    encrypted_private_keys: new Uint8Array(encrypted),
    salt: new Uint8Array(salt),
    iv: new Uint8Array(iv),
    updated_at: Date.now()
  });
}

/** 零知识金库 v1：读取加密私钥、salt 与 iv；解密须在 cryptoManager 中基于用户密码完成。 */
export async function getEncryptedPrivateKeys(
  userId: string
): Promise<{ encrypted: Uint8Array; salt: Uint8Array; iv: Uint8Array } | null> {
  const u = userId.trim();
  if (!u) return null;
  const db = await getDB();
  const record = await db.get('MyPrivateKeys', u);
  if (!record) return null;
  if (record.format === 'v2') return null;
  if (!record.encrypted_private_keys?.byteLength || !record.salt || !record.iv) return null;
  return {
    encrypted: record.encrypted_private_keys,
    salt: record.salt,
    iv: record.iv
  };
}

/** v2 主密钥方案：写入 MK_encrypted_local 与 asym_priv_encrypted。 */
export async function saveKeyBackupV2(
  userId: string,
  mkEncryptedLocal: Uint8Array,
  asymPrivEncrypted: Uint8Array
): Promise<void> {
  const u = userId.trim();
  if (!u) throw new Error('userId 不能为空');
  const db = await getDB();
  await db.put('MyPrivateKeys', {
    user_id: u,
    format: 'v2',
    mk_encrypted_local: new Uint8Array(mkEncryptedLocal),
    asym_priv_encrypted: new Uint8Array(asymPrivEncrypted),
    updated_at: Date.now()
  });
}

/** v2 主密钥方案：读取 MK_encrypted_local 与 asym_priv_encrypted；无则返回 null。 */
export async function getKeyBackupV2(
  userId: string
): Promise<{ mkEncryptedLocal: Uint8Array; asymPrivEncrypted: Uint8Array } | null> {
  const u = userId.trim();
  if (!u) return null;
  const db = await getDB();
  const record = await db.get('MyPrivateKeys', u);
  if (!record || record.format !== 'v2' || !record.mk_encrypted_local?.byteLength || !record.asym_priv_encrypted?.byteLength) {
    return null;
  }
  return {
    mkEncryptedLocal: record.mk_encrypted_local,
    asymPrivEncrypted: record.asym_priv_encrypted
  };
}

/** 删除指定用户在 MyPrivateKeys 中的记录。 */
export async function deleteMyPrivateKeys(userId: string): Promise<void> {
  const u = userId.trim();
  if (!u) return;
  const db = await getDB();
  await db.delete('MyPrivateKeys', u);
}

/** 保存联系人公钥指纹，用于 TOFU 首次使用时的带外核验。 */
export async function saveContactFingerprint(
  contactId: string,
  kemFingerprint: string,
  dsaFingerprint?: string
): Promise<void> {
  const c = contactId.trim();
  if (!c) throw new Error('contact_id 不能为空');
  const db = await getDB();
  const record: ContactFingerprintsRecord = {
    contact_id: c,
    kem_fingerprint: kemFingerprint.trim(),
    dsa_fingerprint: dsaFingerprint?.trim(),
    updated_at: Date.now()
  };
  await db.put('ContactFingerprints', record);
}

/** 根据 contact_id 读取联系人公钥指纹记录。 */
export async function getContactFingerprint(
  contactId: string
): Promise<ContactFingerprintsRecord | null> {
  const c = contactId.trim();
  if (!c) return null;
  const db = await getDB();
  return (await db.get('ContactFingerprints', c)) ?? null;
}

/** 删除指定联系人在 ContactFingerprints 中的指纹记录。 */
export async function deleteContactFingerprint(contactId: string): Promise<void> {
  const c = contactId.trim();
  if (!c) return;
  const db = await getDB();
  await db.delete('ContactFingerprints', c);
}
