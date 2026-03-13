<script setup lang="ts">
/* eslint-disable @typescript-eslint/no-explicit-any */
import { ref } from 'vue';
import { useSessionStore } from '../store/session';
import { KemEngine } from '../core/kem-engine';
import { CryptoStream, CHUNK_SIZE } from '../core/crypto-stream';
import { API_BASE, parseBackendError, apiFetch } from '../api/client';

const session = useSessionStore();
const emit = defineEmits<{ (e: 'success', fileId: string): void }>();

const selectedFile = ref<File | null>(null);
const isUploading = ref(false);
const progress = ref(0);
const statusText = ref('');

const MAX_RETRY = 3;
const UPLOAD_MAX_CONCURRENCY = 3;
const AUDIT_MAX_LINES = 120;
const auditLog = ref<string[]>([]);

function log(msg: string) {
  auditLog.value = [...auditLog.value, msg].slice(-AUDIT_MAX_LINES);
}

function formatSize(bytes: number): string {
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function ivPreview(iv: Uint8Array, max = 6): string {
  const arr = Array.from(iv.slice(0, max)).join(', ');
  return iv.length > max ? `[${arr}, ...] (${iv.length} Bytes)` : `[${arr}] (${iv.length} Bytes)`;
}

function handleFileSelect(e: Event) {
  const target = e.target as HTMLInputElement;
  selectedFile.value = target.files?.item(0) ?? null;
  statusText.value = '';
  progress.value = 0;
  auditLog.value = [];
}

/** 二进制转 Base64：按块处理避免大数组 spread 导致栈溢出，与解码端约定一致。 */
function bytesToBase64(input: ArrayBuffer | Uint8Array): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const chunkSize = 0x8000; // 32KB
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithRetry(
  input: RequestInfo | URL,
  init: RequestInit,
  maxRetry = MAX_RETRY
): Promise<Response> {
  let lastError: unknown;

  for (let attempt = 1; attempt <= maxRetry; attempt++) {
    try {
      const res = await apiFetch(input, init);

      if (!res.ok) {
        const bodyText = await res.text().catch(() => '');
        const msg = parseBackendError(bodyText) || res.statusText || '请求失败';
        throw new Error(msg);
      }

      return res;
    } catch (err) {
      lastError = err;
      if (attempt < maxRetry) {
        await sleep(300 * 2 ** (attempt - 1)); // 指数退避
      }
    }
  }

  throw lastError instanceof Error ? lastError : new Error('网络请求失败');
}

async function startUpload() {
  if (!selectedFile.value) {
    statusText.value = '请先选择文件';
    return;
  }
  if (!session.targetPublicKey) {
    statusText.value = '目标公钥不存在';
    return;
  }
  if (!session.currentUserId || !session.targetUserId) {
    statusText.value = '用户会话信息不完整';
    return;
  }

  isUploading.value = true;
  progress.value = 0;
  auditLog.value = [];

  const file = selectedFile.value;
  const fileId = crypto.randomUUID();
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

  try {
    log(`[系统日志] 正在截获文件流... 大小: ${formatSize(file.size)} (${totalChunks} 物理块)`);
    statusText.value = '1/4 封装抗量子密钥...';

    log('[量子引擎] 发起 ML-KEM-768 密钥封装 (Encap)...');
    const { ciphertext: kemCipher, sharedSecret } =
      await KemEngine.encapsulateSecret(session.targetPublicKey);
    log(`[量子引擎] 生成 ${kemCipher.byteLength} Bytes 全局签名密文 (Ciphertext)`);
    log(`[量子引擎] 提取 ${sharedSecret.byteLength} Bytes 共享真随机密钥 (Shared Secret)`);

    statusText.value = '2/4 初始化对称密钥...';
    log('[对称引擎] HKDF-SHA256 派生 AES-256-GCM 密钥 (绑定 file_id)...');
    const aesKey = await CryptoStream.deriveAesKey(sharedSecret, fileId);

    if (totalChunks === 0) {
      throw new Error('文件为空，无法上传');
    }

    const fileIdShort = fileId.substring(0, 8) + '...';
    let completed = 0;

    /** 原子任务：读单块 → 加密 → 上传 → 释放引用，仅当池子有空位时才执行 */
    async function runAtomicChunkTask(i: number): Promise<void> {
      statusText.value = `3/4 加密上传分块: ${i + 1}/${totalChunks}`;
      log(`[对称引擎] 注入 AAD: fileId_${fileIdShort}chunk_${i}`);
      const chunk = await file
        .slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE)
        .arrayBuffer();
      const { ciphertext, iv } = await CryptoStream.encryptChunk(chunk, aesKey, fileId, i);
      log(`[对称引擎] 生成随机 IV: ${ivPreview(iv)}`);
      const payload = new Uint8Array(iv.length + ciphertext.byteLength);
      payload.set(iv, 0);
      payload.set(new Uint8Array(ciphertext), iv.length);

      const fd = new FormData();
      fd.append('file_id', fileId);
      fd.append('chunk_index', i.toString());
      fd.append('file', new Blob([new Uint8Array(payload)]), `${file.name}.part.${i}`);
      await fetchWithRetry(`${API_BASE}/files/upload_chunk`, { method: 'POST', body: fd });
      log(`[网络层] 物理块 ${i} 落盘完毕 (${payload.byteLength} Bytes)`);
      completed += 1;
      progress.value = Math.round((completed / totalChunks) * 100);
    }

    /** 并发池：最多 3 个在飞，池满时 Promise.race 等一个完成再发车 */
    const inFlight = new Set<Promise<void>>();
    function addToPool(p: Promise<void>) {
      const wrapped = p.finally(() => { inFlight.delete(wrapped); });
      inFlight.add(wrapped);
    }
    for (let i = 0; i < totalChunks; i++) {
      while (inFlight.size >= UPLOAD_MAX_CONCURRENCY) {
        await Promise.race(inFlight);
      }
      addToPool(runAtomicChunkTask(i));
    }
    await Promise.all(inFlight);

    statusText.value = '4/4 登记元数据...';
    log('[系统日志] 登记元数据 (file_id, global_signature, sender/receiver)...');
    const sigB64 = bytesToBase64(kemCipher);

    const finalFd = new FormData();
    finalFd.append('file_id', fileId);
    finalFd.append('sender_id', session.currentUserId);
    finalFd.append('receiver_id', session.targetUserId);
    finalFd.append('total_chunks', totalChunks.toString());
    finalFd.append('global_signature', sigB64);
    finalFd.append('kem_ciphertext', sigB64); // 完整 KEM 密文写入 Text 列，避免 global_signature 被 String(1024) 截断
    finalFd.append('file_name', file.name);
    finalFd.append('file_size', file.size.toString());

    await fetchWithRetry(`${API_BASE}/files/finalize`, {
      method: 'POST',
      body: finalFd
    });

    log('[系统日志] ✅ 传输完成，密文已落盘。');
    statusText.value = '✅ 传输完成！';
    emit('success', fileId);
  } catch (e: any) {
    log(`[系统日志] 🚨 异常: ${e?.message ?? '未知错误'}`);
    statusText.value = `🚨 失败: ${e?.message ?? '未知错误'}`;
  } finally {
    isUploading.value = false;
  }
}
</script>

<template>
  <div class="secure-uploader">
    <input type="file" :disabled="isUploading" @change="handleFileSelect" />
    <button :disabled="isUploading || !selectedFile" @click="startUpload">
      {{ isUploading ? '上传中...' : '开始上传' }}
    </button>

    <div v-if="statusText" class="status">{{ statusText }}</div>

    <div class="progress-wrap" v-if="isUploading || progress > 0">
      <progress :value="progress" max="100"></progress>
      <span>{{ progress }}%</span>
    </div>

    <div class="crypto-console" v-if="auditLog.length > 0">
      <div class="crypto-console-title">⚡ 硬核密码学控制台 · 实时审计日志</div>
      <div class="crypto-console-body">
        <div v-for="(line, idx) in auditLog" :key="idx" class="crypto-console-line">{{ line }}</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.secure-uploader {
  display: grid;
  gap: 12px;
  max-width: 560px;
}

.secure-uploader input[type="file"] {
  padding: 10px;
  color: #e2e8f0;
  background: rgba(15, 23, 42, 0.8);
  border: 1px solid rgba(34, 211, 238, 0.3);
  border-radius: 8px;
  font-size: 0.95rem;
}

.secure-uploader button {
  padding: 12px 20px;
  font-weight: 600;
  background: linear-gradient(135deg, #22d3ee 0%, #06b6d4 100%);
  color: #0a0e17;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
  box-shadow: 0 0 20px rgba(34, 211, 238, 0.25);
}

.secure-uploader button:hover:not(:disabled) {
  box-shadow: 0 0 28px rgba(34, 211, 238, 0.35);
  transform: translateY(-1px);
}

.secure-uploader button:disabled {
  background: rgba(100, 116, 139, 0.5);
  color: #94a3b8;
  cursor: not-allowed;
  box-shadow: none;
}

.status {
  font-size: 14px;
  line-height: 1.5;
  color: rgba(34, 211, 238, 0.95);
}

.progress-wrap {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #94a3b8;
}

progress {
  width: 100%;
  height: 8px;
  border-radius: 4px;
  background: rgba(15, 23, 42, 0.8);
}

progress::-webkit-progress-bar {
  background: rgba(15, 23, 42, 0.8);
  border-radius: 4px;
}

progress::-webkit-progress-value {
  background: linear-gradient(90deg, #22d3ee, #06b6d4);
  border-radius: 4px;
}

.crypto-console {
  margin-top: 16px;
  border: 1px solid rgba(34, 211, 238, 0.35);
  border-radius: 8px;
  overflow: hidden;
  background: #0d1117;
  box-shadow: 0 0 24px rgba(0, 255, 136, 0.08), inset 0 0 0 1px rgba(0, 255, 136, 0.06);
}

.crypto-console-title {
  padding: 8px 12px;
  font-size: 0.75rem;
  font-weight: 700;
  color: #7ee787;
  background: rgba(0, 0, 0, 0.4);
  border-bottom: 1px solid rgba(126, 231, 135, 0.25);
  letter-spacing: 0.05em;
}

.crypto-console-body {
  max-height: 220px;
  overflow-y: auto;
  padding: 10px 12px;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 0.8rem;
  line-height: 1.5;
  color: #7ee787;
  background: #0d1117;
}

.crypto-console-line {
  word-break: break-all;
}
</style>

