/**
 * 文件发送业务流：拉取接收方 KEM 公钥 → 生成加密套件 → 分块 AES-GCM 加密（每块绑定 AAD 防篡改与重排）→ 逐块上传 → 终态签名并调用 finalize 提交元数据。
 * 针对大文件，采用“边读边加密 + 流式哈希”的设计，避免一次性加载整个文件导致 OOM。
 */
import { API_BASE, ensureOk, apiFetch } from '../api/client';
import { generateEncryptionSuite, type EncryptionSuite } from '../core/cryptoEngine';
import { DsaEngine } from '../core/dsa-engine';
import { KeyStorage } from '../core/key-storage';
import jsSHA from 'jssha';

// 5MB 分块：单块解密与 Tauri IPC 更快，实测大文件总耗时优于 20MB（355 块快于 90 块）
const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB
const UPLOAD_MAX_CONCURRENCY = 3; // 严格并发上限，按需读取+加密+上传，禁止预加密堆积
const AES_GCM_IV_LENGTH = 12;
const AES_GCM_TAG_LENGTH = 128; // bits

const encoder = new TextEncoder();

const CHUNK_UPLOAD_PATH = '/files/upload_chunk';
const FINALIZE_PATH = '/files/finalize';

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(u8.length);
  copy.set(u8);
  return copy.buffer;
}

function base64FromBytes(u8: Uint8Array): string {
  const chunkSize = 0x8000;
  let binary = '';
  for (let i = 0; i < u8.length; i += chunkSize) {
    const chunk = u8.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

export interface UploadParams {
  file: File;
  senderId: string;
  receiverId: string;
  onProgress?: (loaded: number, total: number, chunkIndex: number) => void;
}

/** AAD 格式为 fileId_chunkIndex，确保分块顺序或内容被篡改时解密失败；接收端须使用相同格式。 */
export const UPLOAD_SERVICE_AAD_FORMAT = (fileId: string, chunkIndex: number) =>
  `${fileId}_${chunkIndex}`;

/** 对单分块执行 AES-256-GCM 加密，AAD 绑定 fileId 与 chunkIndex。 */
async function encryptChunkWithAad(
  chunkData: ArrayBuffer,
  aesKey: CryptoKey,
  fileId: string,
  chunkIndex: number
): Promise<{ ciphertext: ArrayBuffer; iv: Uint8Array }> {
  const iv = window.crypto.getRandomValues(new Uint8Array(AES_GCM_IV_LENGTH));
  const aad = encoder.encode(UPLOAD_SERVICE_AAD_FORMAT(fileId, chunkIndex));

  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(iv),
      additionalData: toArrayBuffer(aad),
      tagLength: AES_GCM_TAG_LENGTH
    },
    aesKey,
    chunkData
  );

  return { ciphertext, iv };
}

async function fetchReceiverKemPublicKey(receiverId: string): Promise<Uint8Array> {
  const res = await ensureOk(
    await apiFetch(`${API_BASE}/keys/${encodeURIComponent(receiverId)}`),
    '拉取接收方公钥'
  );
  const data = (await res.json()) as { kem_public_key?: string };
  const b64 = data.kem_public_key;
  if (!b64) throw new Error('服务端未返回 kem_public_key');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** 上传单分块：请求体为 12 字节 IV 与密文拼接；Form 字段包含 file_id、chunk_index 及文件二进制。 */
async function uploadChunk(
  fileId: string,
  chunkIndex: number,
  payload: Uint8Array
): Promise<void> {
  const fd = new FormData();
  fd.append('file_id', fileId);
  fd.append('chunk_index', String(chunkIndex));
  fd.append('file', new Blob([new Uint8Array(payload)]), `chunk.${chunkIndex}`);
  await ensureOk(
    await apiFetch(`${API_BASE}${CHUNK_UPLOAD_PATH}`, { method: 'POST', body: fd }),
    `上传分块 ${chunkIndex}`
  );
}

/** 构造待签消息：按顺序拼接 fileId、kemCiphertext、fileHash，供 ML-DSA 签名。 */
function buildMessageToSign(
  fileId: string,
  kemCiphertext: Uint8Array,
  fileHash: Uint8Array
): Uint8Array {
  const fileIdBytes = encoder.encode(fileId);
  const out = new Uint8Array(fileIdBytes.length + kemCiphertext.length + fileHash.length);
  out.set(fileIdBytes, 0);
  out.set(kemCiphertext, fileIdBytes.length);
  out.set(fileHash, fileIdBytes.length + kemCiphertext.length);
  return out;
}

export async function runUpload(params: UploadParams): Promise<{
  fileId: string;
  totalChunks: number;
}> {
  const { file, senderId, receiverId, onProgress } = params;
  const sender = senderId.trim();
  const receiver = receiverId.trim();
  if (!sender || !receiver) throw new Error('senderId / receiverId 不能为空');
  if (file.size === 0) throw new Error('文件为空');

  const receiverKemPk = await fetchReceiverKemPublicKey(receiver);
  const suite: EncryptionSuite = await generateEncryptionSuite(receiverKemPk);
  const { aesKey, kemCiphertext, fileId } = suite;

  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  if (totalChunks <= 0) throw new Error('分块数为 0');

  // 使用 jsSHA 进行“边读边 hash”，避免一次性加载整个文件导致 OOM。
  const hasher = new jsSHA('SHA-256', 'ARRAYBUFFER');

  /**
   * 原子任务：仅当池子允许时才执行。
   * 1. 从 File 读取单块 Buffer  2. 生成 IV 并 AES-GCM 加密  3. 上传  4. 返回后局部变量释放，不保留引用。
   */
  async function runAtomicChunkTask(chunkIndex: number): Promise<void> {
    const start = chunkIndex * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, file.size);
    const chunkBlob = file.slice(start, end);
    const chunkData = await chunkBlob.arrayBuffer();

    // 流式更新整文件哈希（与下载端行为对齐）
    hasher.update(chunkData);

    const { ciphertext, iv } = await encryptChunkWithAad(
      chunkData,
      aesKey,
      fileId,
      chunkIndex
    );

    const payload = new Uint8Array(iv.length + ciphertext.byteLength);
    payload.set(iv, 0);
    payload.set(new Uint8Array(ciphertext), iv.length);

    await uploadChunk(fileId, chunkIndex, payload);

    const loaded = Math.min((chunkIndex + 1) * CHUNK_SIZE, file.size);
    onProgress?.(loaded, file.size, chunkIndex);
  }

  /**
   * 并发控制池：最多 UPLOAD_MAX_CONCURRENCY 个任务在飞；池满时 Promise.race 等一个完成再发车。
   */
  const inFlight = new Set<Promise<void>>();

  function addToPool(p: Promise<void>): void {
    const wrapped = p.finally(() => {
      inFlight.delete(wrapped);
    });
    inFlight.add(wrapped);
  }

  for (let i = 0; i < totalChunks; i++) {
    while (inFlight.size >= UPLOAD_MAX_CONCURRENCY) {
      await Promise.race(inFlight);
    }
    addToPool(runAtomicChunkTask(i));
  }

  await Promise.all(inFlight);

  const myKeys = await KeyStorage.getKeys(sender);
  if (!myKeys?.dsaPrivateKey) throw new Error('发送方 ML-DSA 私钥不存在，请先登录');

  // 在所有分块处理完后获取最终 SHA-256 文件哈希
  const fileHash = new Uint8Array(hasher.getHash('ARRAYBUFFER'));

  const messageToSign = buildMessageToSign(fileId, kemCiphertext, fileHash);
  const signature = DsaEngine.sign(messageToSign, myKeys.dsaPrivateKey);

  const kemCiphertextB64 = base64FromBytes(kemCiphertext);
  const senderSignatureB64 = base64FromBytes(signature);

  const finalFd = new FormData();
  finalFd.append('file_id', fileId);
  finalFd.append('sender_id', sender);
  finalFd.append('receiver_id', receiver);
  finalFd.append('total_chunks', String(totalChunks));
  finalFd.append('global_signature', kemCiphertextB64);
  finalFd.append('kem_ciphertext', kemCiphertextB64);
  finalFd.append('sender_signature', senderSignatureB64);
  finalFd.append('file_name', file.name);
  finalFd.append('file_size', String(file.size));

  await ensureOk(
    await apiFetch(`${API_BASE}${FINALIZE_PATH}`, { method: 'POST', body: finalFd }),
    '终态登记 Finalize'
  );

  return { fileId, totalChunks };
}
