<template>
  <div class="file-downloader">
    <div class="header-row">
      <h3>📥 接收收件箱</h3>
      <button @click="fetchFiles" :disabled="isFetching" class="refresh-btn">
        {{ isFetching ? '刷新中...' : '🔄 刷新' }}
      </button>
    </div>

    <p v-if="globalMessage" class="global-msg">{{ globalMessage }}</p>

    <div v-if="files.length === 0 && !isFetching" class="empty">
      暂无可接收文件
    </div>

    <div v-for="file in files" :key="file.file_id" class="file-card">
      <p class="file-meta-line">
        <span class="tracking-row">
          📦 追踪号: <code class="tracking-id">{{ file.file_id }}</code>
          <button
            type="button"
            class="copy-tracking-btn"
            title="复制追踪号"
            @click="copyTrackingId(file.file_id)"
          >
            {{ copyDoneId === file.file_id ? '已复制' : '复制' }}
          </button>
        </span>
        | 来自: <strong>{{ file.sender_id }}</strong>
        | 分块: {{ file.total_chunks }}
        | 登记时间: {{ formatTimeToSecond(file.created_at) }}
      </p>

      <button
        class="dl-btn"
        @click="decryptAndDownload(file)"
        :disabled="activeFileId !== null"
      >
        {{ activeFileId === file.file_id ? '解密中...' : '🔓 本地零信任解密' }}
      </button>

      <div v-if="activeFileId === file.file_id" class="status-msg">
        <div>{{ statusText }}</div>
        <div v-if="progress > 0">进度: {{ progress }}%</div>
      </div>
    </div>

    <div v-if="totalItems > 0" class="pagination-row">
      <button
        type="button"
        class="page-btn"
        :disabled="currentPage <= 1"
        @click="goPage(currentPage - 1)"
      >
        上一页
      </button>
      <span class="page-info">当前第 {{ currentPage }} 页 / 共 {{ totalPages }} 页</span>
      <button
        type="button"
        class="page-btn"
        :disabled="currentPage >= totalPages"
        @click="goPage(currentPage + 1)"
      >
        下一页
      </button>
    </div>

    <div class="crypto-console" v-if="auditLog.length > 0">
      <div class="crypto-console-title">⚡ 控制台 · 实时审计日志</div>
      <div class="crypto-console-body">
        <div v-for="(line, idx) in auditLog" :key="idx" class="crypto-console-line">{{ line }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
/* eslint-disable @typescript-eslint/no-explicit-any */
import { ref, computed, watch } from 'vue';
import { KeyStorage } from '../core/key-storage';
import { KemEngine } from '../core/kem-engine';
import { CryptoStream } from '../core/crypto-stream';
import { deriveAesKeyFromSharedSecretAndFileId } from '../core/cryptoEngine';
import { API_BASE, ensureOk, apiFetch, getAuthToken } from '../api/client';
import { saveDecryptedFile } from '../utils/saveFile';
import { isTauri } from '../utils/tauri'; // 保留了你这一版最新的优化写法

/** 分块转 Base64 并定期 yield，避免长时间阻塞主线程（用于 Tauri 流式 IPC） */
async function arrayBufferToBase64(buf: ArrayBuffer): Promise<string> {
  const bytes = new Uint8Array(buf);
  const chunkSize = 32768;
  const yieldEvery = 4;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const sub = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    binary += String.fromCharCode.apply(null, sub as unknown as number[]);
    if ((i / chunkSize + 1) % yieldEvery === 0) await new Promise<void>((r) => setTimeout(r, 0));
  }
  return btoa(binary);
}

const MLKEM768_CIPHERTEXT_BYTES = 1088;

type InboxFile = {
  file_id: string;
  sender_id: string;
  receiver_id?: string;
  total_chunks: number;
  global_signature: string; // Base64 的 KEM 密文（可能被 DB 截断）
  kem_ciphertext?: string | null; // 完整 Base64，优先使用
  file_name?: string;
  file_size?: number;
  created_at?: string; // ISO 格式，来自列表 API
};

const props = defineProps<{ myId: string }>();

const files = ref<InboxFile[]>([]);
const currentPage = ref(1);
const pageSize = ref(10);
const totalItems = ref(0);
const activeFileId = ref<string | null>(null);
const progress = ref(0);
const statusText = ref('');
const globalMessage = ref('');
const isFetching = ref(false);

const totalPages = computed(() =>
  totalItems.value <= 0 ? 1 : Math.ceil(totalItems.value / pageSize.value)
);

const copyDoneId = ref<string | null>(null);
const AUDIT_MAX_LINES = 120;

async function copyTrackingId(fileId: string) {
  try {
    await navigator.clipboard.writeText(fileId);
    copyDoneId.value = fileId;
    setTimeout(() => { copyDoneId.value = null; }, 2000);
  } catch {
    /* ignore */
  }
}
const auditLog = ref<string[]>([]);

// 审计日志时间戳，精确到秒
function nowStr(): string {
  const d = new Date();
  const y = d.getFullYear();
  const M = String(d.getMonth() + 1).padStart(2, '0');
  const D = String(d.getDate()).padStart(2, '0');
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const s = String(d.getSeconds()).padStart(2, '0');
  return `${y}-${M}-${D} ${h}:${m}:${s}`;
}

/** 将后端返回的 ISO 8601 时间格式化为“精确到秒”的显示字符串，采用中国时区 (UTC+8)；无 Z 或时区后缀时按 UTC 解析后转换。 */
function formatTimeToSecond(iso?: string | null): string {
  if (!iso) return '—';
  try {
    let isoStr = iso.trim();
    // 后端存储为 UTC，响应可能无 Z 后缀，按 UTC 解析后转为北京时间
    if (isoStr && !/Z|[+-]\d{2}:?\d{2}$/.test(isoStr)) {
      isoStr = isoStr.replace(/\.\d+$/, '') + 'Z';
    }
    const d = new Date(isoStr);
    if (Number.isNaN(d.getTime())) return '—';
    const formatter = new Intl.DateTimeFormat('zh-CN', {
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    });
    const parts = formatter.formatToParts(d);
    const get = (type: Intl.DateTimeFormatPart['type']) => parts.find((p) => p.type === type)?.value ?? '';
    const y = get('year');
    const M = get('month').padStart(2, '0');
    const D = get('day').padStart(2, '0');
    const h = get('hour').padStart(2, '0');
    const m = get('minute').padStart(2, '0');
    const s = get('second').padStart(2, '0');
    return `${y}-${M}-${D} ${h}:${m}:${s}`;
  } catch {
    return '—';
  }
}

function log(msg: string) {
  const line = `[${nowStr()}] ${msg}`;
  auditLog.value = [...auditLog.value, line].slice(-AUDIT_MAX_LINES);
}

function formatSize(bytes: number): string {
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

/** Base64 解码为 Uint8Array，与上传端 bytesToBase64 编码方式一致。 */
function base64ToBytes(base64: string): Uint8Array {
  const binStr = atob(base64);
  const out = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) out[i] = binStr.charCodeAt(i);
  return out;
}

async function fetchFiles() {
  if (!props.myId) return;

  isFetching.value = true;
  globalMessage.value = '';

  try {
    const params = new URLSearchParams({
      page: String(currentPage.value),
      size: String(pageSize.value)
    });
    const res = await ensureOk(
      await apiFetch(
        `${API_BASE}/files/list/${encodeURIComponent(props.myId)}?${params}`
      ),
      '拉取文件列表'
    );
    const data = await res.json().catch(() => ({}));

    const list: InboxFile[] = Array.isArray(data?.items) ? data.items : [];
    files.value = list;
    totalItems.value = typeof data?.total === 'number' ? data.total : 0;
  } catch (e: any) {
    globalMessage.value = `🚨 ${e?.message ?? '拉取列表失败'}`;
  } finally {
    isFetching.value = false;
  }
}

function goPage(page: number) {
  if (page < 1 || page > totalPages.value) return;
  currentPage.value = page;
  fetchFiles();
}

// 登录后 myId 由父组件异步注入，onMounted 时可能尚未就绪，故通过 watch 在 myId 可用时拉取收件箱
watch(
  () => props.myId,
  (newId) => {
    if (newId) fetchFiles();
  },
  { immediate: true }
);

async function decryptAndDownload(file: InboxFile) {
  activeFileId.value = file.file_id;
  progress.value = 0;
  statusText.value = '';
  auditLog.value = [];
  const fileIdShort = file.file_id.substring(0, 8) + '...';

  try {
    log(`[系统日志] 开始零信任解密流程 · file_id: ${fileIdShort}`);
    statusText.value = '1/5 正在提取私钥与元数据...';
    log('[系统日志] 正在加载本地私钥 (IndexedDB)...');
    const keys = await KeyStorage.getKeys();
    if (!keys?.privateKey) throw new Error('本地私钥丢失');

    // 优先从 transfer meta 接口取 file_id / kem_ciphertext，与 downloadService 完全一致，避免列表与下载端不一致
    let fileIdForCrypto = (file.file_id || '').trim();
    let kemB64 = (file.kem_ciphertext && file.kem_ciphertext.trim()) || file.global_signature || '';
    let totalChunksFromMeta = Number(file.total_chunks);
    try {
      const metaRes = await apiFetch(
        `${API_BASE}/api/transfer/download/${encodeURIComponent(fileIdForCrypto)}/meta`
      );
      if (metaRes.ok) {
        const meta = (await metaRes.json()) as { file_id?: string; kem_ciphertext?: string; total_chunks?: number };
        if (meta.file_id) fileIdForCrypto = (meta.file_id || '').trim();
        if (meta.kem_ciphertext) kemB64 = (meta.kem_ciphertext || '').trim();
        if (typeof meta.total_chunks === 'number' && meta.total_chunks > 0) totalChunksFromMeta = meta.total_chunks;
        log('[系统日志] 已使用 transfer meta 元数据');
      }
    } catch {
      /* 使用列表数据 */
    }

    statusText.value = '2/5 解封抗量子密钥封装...';
    if (!kemB64?.trim()) throw new Error('缺少 KEM 密文 (kem_ciphertext / global_signature)');
    const kemCipher = base64ToBytes(kemB64.trim());
    if (kemCipher.byteLength !== MLKEM768_CIPHERTEXT_BYTES) {
      throw new Error(
        `KEM 密文长度异常(当前 ${kemCipher.byteLength}，应为 ${MLKEM768_CIPHERTEXT_BYTES})，可能被截断，无法解密。请让发送方重新发送或检查后端 global_signature 字段长度限制。`
      );
    }
    log(`[量子引擎] 发起 ML-KEM-768 密钥解封 (Decap)... 密文长度: ${kemCipher.byteLength} Bytes`);
    const secret = await KemEngine.decapsulateSecret(kemCipher, keys.privateKey);
    log(`[量子引擎] 还原 ${secret.byteLength} Bytes 共享密钥 (Shared Secret)`);
    log('[对称引擎] HKDF-SHA256 派生 AES-256-GCM 密钥 (绑定 file_id，与 downloadService 一致)...');
    const aesKey = await deriveAesKeyFromSharedSecretAndFileId(secret, fileIdForCrypto);

    const total = Number(totalChunksFromMeta) || Number(file.total_chunks);
    if (!Number.isFinite(total) || total <= 0) throw new Error('total_chunks 非法');

    // 解密后文件名使用加密时的原名（来自元数据/列表）
    const outputName =
      file.file_name?.trim() ||
      `QuantumGuard_Decrypted_${file.file_id.substring(0, 5)}.bin`;

    const keyState = { aesKey, usedLegacyKey: false };
    const sizeState = { totalBytes: 0 };

    // Tauri：单次调用 Rust 并行流水线（3 路拉取+解密+顺序写盘），前端只传参数并监听进度
    if (isTauri()) {
      const { save } = await import('@tauri-apps/plugin-dialog');
      const { invoke } = await import('@tauri-apps/api/core');
      const { listen } = await import('@tauri-apps/api/event');
      statusText.value = '3/5 请选择保存位置...';
      log('[系统日志] 请选择保存路径（先选路径再解密落盘，避免大文件卡死）');
      let path = await save({
        defaultPath: outputName,
        filters: [{ name: 'All Files', extensions: ['*'] }]
      });
      if (path == null || path === '') {
        log('[系统日志] 用户取消另存为。');
        statusText.value = '已取消保存';
        return;
      }
      // Android 上 save 返回 content:// URI，不能直接交给 Rust 的 File::create。
      // 对于这种情况，改为在前端使用 @tauri-apps/plugin-fs 直接对 content URI 进行流式写入，
      // 解密逻辑与浏览器分支一致，但落盘由 Android 的 ContentResolver 完成，真正保存到用户选定的位置。
      if (path.startsWith('content:')) {
        log('[系统日志] 检测到 Android 内容 URI，使用 plugin-fs writeFile(ReadableStream) 一次性写入以正确提交到 DocumentProvider');
        const { writeFile } = await import('@tauri-apps/plugin-fs');
        const expectedPlain = typeof file.file_size === 'number' && file.file_size >= 0 ? file.file_size : null;
        sizeState.totalBytes = 0;
        let nextChunkIndex = 0;
        const stream = new ReadableStream<Uint8Array>({
          async pull(controller) {
            const i = nextChunkIndex;
            if (i >= total) {
              controller.close();
              return;
            }
            log(`[网络层] 准备下载分块 ${i}（Android 内容 URI）`);
            const res = await ensureOk(
              await apiFetch(
                `${API_BASE}/files/download/${encodeURIComponent(file.file_id)}/chunk/${i}`
              ),
              `下载分块 ${i}`
            );
            const buf = await res.arrayBuffer();
            if (buf.byteLength < 13) {
              controller.error(new Error(`分块长度异常: chunk=${i}, size=${buf.byteLength}`));
              return;
            }
            const iv = new Uint8Array(buf.slice(0, 12));
            const ciphertext = buf.slice(12);
            let plain: ArrayBuffer;
            try {
              plain = await CryptoStream.decryptChunk(
                ciphertext,
                keyState.aesKey,
                iv,
                fileIdForCrypto,
                i
              );
            } catch (e: any) {
              if (
                i === 0 &&
                !keyState.usedLegacyKey &&
                (e?.name === 'OperationError' || String(e?.message || '').includes('decrypt'))
              ) {
                log('[对称引擎] 使用兼容模式（旧版直接密钥）重试...');
                keyState.aesKey = await CryptoStream.importAesKey(secret);
                keyState.usedLegacyKey = true;
                plain = await CryptoStream.decryptChunk(
                  ciphertext,
                  keyState.aesKey,
                  iv,
                  fileIdForCrypto,
                  i
                );
              } else {
                controller.error(e);
                return;
              }
            }
            sizeState.totalBytes += plain.byteLength;
            nextChunkIndex = i + 1;
            const current = nextChunkIndex;
            progress.value = total > 0 ? Math.round((current / total) * 100) : 0;
            statusText.value = `4/5 解密落盘中 (${current}/${total})...`;
            log(`[网络层] 物理块 ${i} 已写入`);
            controller.enqueue(new Uint8Array(plain));
            await new Promise<void>((r) => setTimeout(r, 0));
          }
        });
        statusText.value = '4/5 正在拉取并解密落盘（Android 内容 URI）...';
        await writeFile(path, stream, { create: true });
        if (expectedPlain !== null) {
          if (sizeState.totalBytes === expectedPlain) {
            log(
              `[系统日志] 明文总长校验: 期望 ${expectedPlain} Bytes，实际 ${sizeState.totalBytes} Bytes`
            );
          } else {
            log(
              `[系统日志] 提示: 写入 ${sizeState.totalBytes} Bytes，元数据 file_size=${expectedPlain}，已按实际写入完成`
            );
          }
        }
        log(`[系统日志] ✅ 解密成功，文件已落盘。路径：${path}`);
        statusText.value = `✅ 解密成功！已保存到：${path}`;
        return;
      }
      statusText.value = '4/5 正在拉取并解密落盘（Rust 并行流水线 3 路）...';
      log('[网络层] Rust 侧并行拉取+解密+顺序写盘，前端单次调用 stream_decrypt_batch');
      const token = getAuthToken();
      const authHeader = token ? `Bearer ${token}` : '';
      const unlistenProgress = await listen<[number, number]>('decrypt-progress', (ev) => {
        const [current, totalChunks] = ev.payload;
        progress.value = totalChunks > 0 ? Math.round((current / totalChunks) * 100) : 0;
        statusText.value = `4/5 解密落盘中 (${current}/${totalChunks})...`;
        // 每写完一块打一条日志，与旧版「物理块 X 已写入」一致，便于审计
        if (current > 0) log(`[网络层] 物理块 ${current - 1} 已写入`);
      });
      const runBatch = async (keyBytes: number[]) => {
        const expectedPlain = typeof file.file_size === 'number' && file.file_size >= 0 ? file.file_size : null;
        return await invoke<number[]>('stream_decrypt_batch', {
          path,
          aesKey: keyBytes,
          fileId: fileIdForCrypto,
          baseUrl: API_BASE,
          authHeader,
          totalChunks: total,
          expectedPlainSize: expectedPlain
        });
      };
      const rawKey = await crypto.subtle.exportKey('raw', keyState.aesKey);
      const aesKeyArr = Array.from(new Uint8Array(rawKey));
      try {
        await runBatch(aesKeyArr);
      } catch (e: any) {
        const msg = String(e?.message ?? e ?? '');
        if (!keyState.usedLegacyKey && (msg.includes('解密失败') || msg.includes('块 0 '))) {
          log('[对称引擎] 使用兼容模式（旧版直接密钥）重试...');
          keyState.aesKey = await CryptoStream.importAesKey(secret);
          keyState.usedLegacyKey = true;
          const legacyKey = await crypto.subtle.exportKey('raw', keyState.aesKey);
          await runBatch(Array.from(new Uint8Array(legacyKey)));
        } else {
          throw e;
        }
      } finally {
        unlistenProgress();
      }
      const plainSize = typeof file.file_size === 'number' && file.file_size >= 0 ? file.file_size : null;
      if (plainSize !== null) {
        const expectedBlobSize = plainSize + total * 28;
        log(`[系统日志] 密文总长校验: 期望 ${expectedBlobSize} Bytes（明文 ${plainSize} + ${total}×28）`);
      }
      log(`[系统日志] ✅ 解密成功，文件已落盘。路径：${path}`);
      statusText.value = `✅ 解密成功！已保存到：${path}`;
      return;
    }

    // 浏览器：流式写盘 + 3 并发，避免全量进内存
    statusText.value = '3/5 请选择保存位置...';
    log('[网络层] 流式写盘 + 3 并发，解密一块写一块');
    const MAX_DOWNLOAD_CONCURRENCY = 3;

    type QueueItem =
      | { ok: true; index: number; data: ArrayBuffer }
      | { ok: false; error: Error };
    const queue: QueueItem[] = [];
    let resolveWait: ((item: QueueItem) => void) | null = null;
    function enqueue(item: QueueItem) {
      queue.push(item);
      if (resolveWait && queue.length > 0) {
        const r = resolveWait;
        resolveWait = null;
        r(queue.shift()!);
      }
    }
    function dequeue(): Promise<QueueItem> {
      return new Promise((r) => {
        if (queue.length > 0) return r(queue.shift()!);
        resolveWait = r;
      });
    }
    // 先弹窗选保存位置，再拿到 WritableStream
    let writer: WritableStreamDefaultWriter<Uint8Array>;
    if (typeof window !== 'undefined' && 'showSaveFilePicker' in window) {
      const handle = await (window as any).showSaveFilePicker({ suggestedName: outputName });
      const writable = await handle.createWritable();
      writer = writable.getWriter();
    } else {
      const streamsaver = (await import('streamsaver')).default;
      const ws = streamsaver.createWriteStream(outputName);
      writer = ws.getWriter();
    }
    statusText.value = '4/5 正在拉取并解密（3 并发 + 流式写盘）...';

    let nextIndexToFetch = 0;
    const pending = new Map<number, ArrayBuffer>();
    let nextToWrite = 0;

    async function writerLoop() {
      while (nextToWrite < total) {
        const item = await dequeue();
        if (!item.ok) throw item.error;
        const { index, data } = item;
        if (index === nextToWrite) {
          await writer.write(new Uint8Array(data));
          sizeState.totalBytes += data.byteLength;
          nextToWrite++;
          while (pending.has(nextToWrite)) {
            const d = pending.get(nextToWrite)!;
            pending.delete(nextToWrite);
            await writer.write(new Uint8Array(d));
            sizeState.totalBytes += d.byteLength;
            nextToWrite++;
          }
          progress.value = total > 0 ? Math.round((nextToWrite / total) * 100) : 0;
          statusText.value = `4/5 解密落盘中 (${nextToWrite}/${total})...`;
        } else {
          pending.set(index, data);
        }
      }
      await writer.close();
    }

    async function runOneTask(): Promise<void> {
      while (true) {
        const i = nextIndexToFetch++;
        if (i >= total) break;
        try {
          const res = await ensureOk(
            await apiFetch(
              `${API_BASE}/files/download/${encodeURIComponent(file.file_id)}/chunk/${i}`
            ),
            `下载分块 ${i}`
          );
          const buf = await res.arrayBuffer();
          if (buf.byteLength < 13) {
            enqueue({ ok: false, error: new Error(`分块长度异常: chunk=${i}, size=${buf.byteLength}`) });
            break;
          }
          const iv = new Uint8Array(buf.slice(0, 12));
          const ciphertext = buf.slice(12);
          let plain: ArrayBuffer;
          try {
            plain = await CryptoStream.decryptChunk(ciphertext, keyState.aesKey, iv, fileIdForCrypto, i);
          } catch (e: any) {
            if (i === 0 && !keyState.usedLegacyKey && (e?.name === 'OperationError' || String(e?.message || '').includes('decrypt'))) {
              log('[对称引擎] 使用兼容模式（旧版直接密钥）重试...');
              keyState.aesKey = await CryptoStream.importAesKey(secret);
              keyState.usedLegacyKey = true;
              plain = await CryptoStream.decryptChunk(ciphertext, keyState.aesKey, iv, fileIdForCrypto, i);
            } else {
              throw e;
            }
          }
          enqueue({ ok: true, index: i, data: plain });
        } catch (e: any) {
          enqueue({ ok: false, error: e instanceof Error ? e : new Error(String(e)) });
          break;
        }
        await new Promise<void>((r) => setTimeout(r, 0));
      }
    }

    const writerPromise = writerLoop();
    const tasks = Array.from({ length: MAX_DOWNLOAD_CONCURRENCY }, () => runOneTask());
    await Promise.all([writerPromise, ...tasks]);

    const plainSize = typeof file.file_size === 'number' && file.file_size >= 0 ? file.file_size : null;
    if (plainSize !== null) {
      const expectedBlobSize = plainSize + total * 28;
      if (sizeState.totalBytes !== expectedBlobSize) {
        throw new Error(
          `密文长度异常: 期望 ${expectedBlobSize} Bytes，实际 ${sizeState.totalBytes} Bytes`
        );
      }
    }

    log('[系统日志] ✅ 解密成功，文件已流式落盘。');
    statusText.value = '✅ 解密成功！';
  } catch (e: any) {
    // Tauri invoke 失败时错误可能在 message / payload / args[0]，统一取出可读文案
    const raw =
      e?.message ??
      (typeof e?.payload === 'string' ? e.payload : e?.args?.[0]) ??
      (e?.name && e?.name !== 'Error' ? e.name : null) ??
      (e != null ? String(e) : '');
    const msg = typeof raw === 'string' && raw.trim() ? raw.trim() : '未知错误';
    const hint =
      msg === 'OperationError' || (e?.name === 'OperationError')
        ? ' (AES-GCM 校验失败: 密钥/IV/AAD 不匹配或密文被篡改/分块错位)'
        : '';
    log(`[系统日志] 🚨 异常: ${msg}${hint}`);
    statusText.value = `🚨 拦截威胁: ${msg}${hint}`;
  } finally {
    // 修复 Bug 2：将延迟重置状态的时间加长到 3000ms (3秒)，防止解密成功提示转瞬即逝
    setTimeout(() => {
      activeFileId.value = null;
      progress.value = 0;
    }, 3000);
  }
}
</script>

<style scoped>
.file-downloader {
  margin-top: 20px;
  border-top: 1px dashed #ccc;
  padding-top: 10px;
}

.header-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-row h3 {
  color: #e2e8f0;
  margin: 0;
}

.refresh-btn {
  padding: 8px 14px;
  background: rgba(34, 211, 238, 0.15);
  border: 1px solid rgba(34, 211, 238, 0.4);
  border-radius: 8px;
  color: #22d3ee;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.refresh-btn:hover:not(:disabled) {
  background: rgba(34, 211, 238, 0.25);
  box-shadow: 0 0 16px rgba(34, 211, 238, 0.2);
}

.global-msg {
  margin-top: 8px;
  color: #f87171;
  font-size: 13px;
}

.empty {
  margin-top: 10px;
  color: #94a3b8;
  font-size: 14px;
}

.file-card {
  border: 1px solid rgba(34, 211, 238, 0.2);
  padding: 14px;
  margin-top: 10px;
  border-radius: 10px;
  background: rgba(15, 23, 42, 0.4);
  backdrop-filter: blur(8px);
}

.file-card p {
  color: #e2e8f0;
  margin: 0 0 10px;
}
.file-meta-line {
  word-break: break-all;
}
.tracking-row {
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
}
.tracking-id {
  font-family: ui-monospace, monospace;
  font-size: 0.9em;
  background: rgba(0,0,0,0.2);
  padding: 2px 6px;
  border-radius: 4px;
}
.copy-tracking-btn {
  padding: 2px 8px;
  font-size: 0.8rem;
  color: #22d3ee;
  background: rgba(34, 211, 238, 0.15);
  border: 1px solid rgba(34, 211, 238, 0.4);
  border-radius: 4px;
  cursor: pointer;
}
.copy-tracking-btn:hover { background: rgba(34, 211, 238, 0.25); }

.dl-btn {
  background: linear-gradient(135deg, #34d399 0%, #10b981 100%);
  color: #0a0e17;
  border: none;
  padding: 10px 16px;
  border-radius: 8px;
  width: 100%;
  cursor: pointer;
  font-weight: 600;
  transition: all 0.2s;
  box-shadow: 0 0 16px rgba(52, 211, 153, 0.2);
}

.dl-btn:hover:not(:disabled) {
  box-shadow: 0 0 24px rgba(52, 211, 153, 0.3);
  transform: translateY(-1px);
}

.dl-btn:disabled {
  opacity: 0.7;
  cursor: not-allowed;
  box-shadow: none;
}

.status-msg {
  font-size: 0.82em;
  color: #94a3b8;
  margin-top: 6px;
  text-align: center;
  line-height: 1.5;
}

.pagination-row {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 16px;
  margin-top: 16px;
  padding: 10px 0;
}
.page-btn {
  padding: 8px 16px;
  font-size: 0.9rem;
  color: #22d3ee;
  background: rgba(34, 211, 238, 0.15);
  border: 1px solid rgba(34, 211, 238, 0.4);
  border-radius: 8px;
  cursor: pointer;
}
.page-btn:hover:not(:disabled) {
  background: rgba(34, 211, 238, 0.25);
}
.page-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.page-info {
  color: #94a3b8;
  font-size: 0.9rem;
}

.crypto-console {
  margin-top: 20px;
  border: 1px solid rgba(52, 211, 153, 0.35);
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
