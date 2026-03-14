<template>
  <div class="sender-view">
    <h2>🚀 安全发送舱 (Sender)</h2>

    <div class="card glass-card" v-if="!session.targetPublicKey">
      <h3>1. 锁定通信目标</h3>
      <p class="subtitle">请输入双方 ID 以获取接收方的抗量子公钥</p>

      <label class="field-label">发送方 ID (您的账号)</label>
      <input
        v-model.trim="myId"
        :placeholder="myId ? '' : '加载中...'"
        readonly
        maxlength="64"
        class="tech-input tech-input-locked"
        title="发送方身份已锁定为当前登录账号，不可修改"
      />
      <label class="field-label">接收方 ID (目标账号)</label>
      <input
        v-model.trim="targetId"
        placeholder="例如: Bob"
        :disabled="isFetching"
        maxlength="64"
        class="tech-input"
      />

      <button class="primary-btn" @click="fetchTargetKey" :disabled="isFetching">
        {{ isFetching ? '⏳ 正在获取对方公钥...' : '获取并解析对方公钥' }}
      </button>

      <p v-if="statusText" class="status-text">{{ statusText }}</p>
      <p v-if="errorText" class="error-text">🚨 {{ errorText }}</p>
    </div>

    <div class="card glass-card" v-if="session.targetPublicKey && !session.isTofuVerified">
      <h3>2. TOFU 信任验证 (极度关键)</h3>
      <p class="warning">
        ⚠️ 防御 MITM (中间人) 攻击：请通过电话、微信或其他带外信道，与对方核对以下安全指纹！
      </p>

      <div class="fingerprint-box">
        {{ session.targetFingerprint }}
      </div>

      <div class="action-group">
        <button class="safe-btn" @click="confirmTofu">✅ 指纹完全一致，授权信任</button>
        <button class="danger-btn" @click="rejectTofu">❌ 指纹不符，立刻阻断连接</button>
      </div>
    </div>

    <div class="card glass-card" v-if="session.isTofuVerified">
      <h3>3. 极速加密传输信道</h3>
      <p class="success-text">
        🔒 安全通道已锁定。当前目标: <strong>{{ session.targetUserId }}</strong>
        <button type="button" class="switch-target-btn" @click="switchRecipient">更换接收方</button>
      </p>
      <p v-if="lastSentFileId" class="sent-tracking-hint">
        ✅ 本次发送追踪号: <code class="sent-tracking-id">{{ lastSentFileId }}</code>
        <button type="button" class="copy-tracking-btn" @click="copySentId(lastSentFileId)">复制</button>
      </p>
      <FileUploader @success="onUploadSuccess" />
    </div>

    <div class="card glass-card sent-inbox-card" v-if="myId">
      <div class="sent-inbox-header">
        <h3>📤 已发送记录（发件箱）</h3>
        <button type="button" class="refresh-btn" :disabled="sentLoading" @click="fetchSentList">
          {{ sentLoading ? '刷新中...' : '🔄 刷新' }}
        </button>
      </div>
      <p v-if="sentItems.length === 0 && !sentLoading" class="empty-hint">暂无已发送文件</p>
      <div v-for="item in sentItems" :key="item.file_id" class="sent-item">
        <p class="sent-meta">
          <span class="sent-name">{{ item.file_name || '（无文件名）' }}</span>
          <span class="sent-tracking-row">
            追踪号: <code>{{ item.file_id }}</code>
            <button type="button" class="copy-tracking-btn" @click="copySentId(item.file_id)">复制</button>
          </span>
          接收方: <strong>{{ item.receiver_id }}</strong>
          · 发送时间: {{ formatSentTime(item.created_at) }}
        </p>
      </div>
      <div v-if="sentTotal > 0" class="sent-pagination">
        <button type="button" class="page-btn" :disabled="sentPage <= 1" @click="goSentPage(sentPage - 1)">上一页</button>
        <span class="page-info">第 {{ sentPage }} / {{ sentTotalPages }} 页</span>
        <button type="button" class="page-btn" :disabled="sentPage >= sentTotalPages" @click="goSentPage(sentPage + 1)">下一页</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import FileUploader from '../components/FileUploader.vue';
import { KeyStorage } from '../core/key-storage';
import { useSessionStore } from '../store/session';
import { API_BASE, ensureOk, apiFetch } from '../api/client';

const MY_ID_STORAGE_KEY = 'quantum_guard_my_id';
const router = useRouter();

type KeyLookupResponse = {
  user_id: string;
  kem_public_key: string;
  dsa_public_key?: string;
};

function makeFingerprint(kemPublicKeyBytes: Uint8Array): string {
  return Array.from(kemPublicKeyBytes.slice(0, 16))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':')
    .toUpperCase();
}

const session = useSessionStore();

onMounted(async () => {
  const keys = await KeyStorage.getKeys();
  const storedId = (localStorage.getItem(MY_ID_STORAGE_KEY) ?? '').trim();
  if (!keys || !storedId) {
    await router.replace('/');
    return;
  }
  myId.value = storedId;
  session.setCurrentUser(storedId);
  fetchSentList();
});

// 发送方 ID 仅从登录状态读取，界面只读，禁止编辑

const myId = ref(
  typeof localStorage !== 'undefined' ? (localStorage.getItem(MY_ID_STORAGE_KEY) ?? '').trim() : ''
);
const targetId = ref('');
const isFetching = ref(false);
const statusText = ref('');
const errorText = ref('');

type SentItem = { file_id: string; sender_id: string; receiver_id: string; file_name?: string; file_size?: number; created_at?: string };
const sentItems = ref<SentItem[]>([]);
const sentPage = ref(1);
const sentSize = ref(10);
const sentTotal = ref(0);
const sentLoading = ref(false);
const lastSentFileId = ref<string | null>(null);
const sentTotalPages = computed(() => sentTotal.value <= 0 ? 1 : Math.ceil(sentTotal.value / sentSize.value));

function formatSentTime(iso?: string | null): string {
  if (!iso) return '—';
  try {
    const d = new Date(iso.trim().replace(/\.\d+$/, '') + (iso.includes('Z') || /\d{2}:\d{2}$/.test(iso) ? '' : 'Z'));
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  } catch { return '—'; }
}

async function fetchSentList() {
  sentLoading.value = true;
  try {
    const params = new URLSearchParams({ page: String(sentPage.value), size: String(sentSize.value) });
    const res = await apiFetch(`${API_BASE}/files/sent?${params}`);
    if (!res.ok) {
      if (res.status === 401) return;
      await ensureOk(res, '发件箱');
    }
    const data = await res.json().catch(() => ({}));
    sentItems.value = Array.isArray(data?.items) ? data.items : [];
    sentTotal.value = typeof data?.total === 'number' ? data.total : 0;
  } catch {
    sentItems.value = [];
  } finally {
    sentLoading.value = false;
  }
}

function goSentPage(p: number) {
  if (p < 1 || p > sentTotalPages.value) return;
  sentPage.value = p;
  fetchSentList();
}

function onUploadSuccess(fileId: string) {
  lastSentFileId.value = fileId;
  fetchSentList();
}

/** 更换接收方：清空当前目标与 TOFU 状态，回到步骤 1 重新选择接收方，无需退出登录。 */
function switchRecipient() {
  session.destroySession();
  targetId.value = '';
  statusText.value = '';
  errorText.value = '';
}

async function copySentId(id: string) {
  try {
    await navigator.clipboard.writeText(id);
  } catch { /* ignore */ }
}

/** Base64 解码为 Uint8Array。 */
function base64ToBytes(base64: string): Uint8Array {
  const bin = window.atob(base64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function ensureIds(): { me: string; target: string } {
  const me = myId.value.trim();
  const target = targetId.value.trim();

  if (!me || !target) {
    throw new Error('请输入完整的 ID');
  }
  if (me === target) {
    throw new Error('发送方与接收方 ID 不能相同');
  }

  return { me, target };
}

async function fetchTargetKey() {
  errorText.value = '';
  statusText.value = '';

  let ids: { me: string; target: string };
  try {
    ids = ensureIds();
  } catch (e: unknown) {
    errorText.value = e instanceof Error ? e.message : 'ID 校验失败';
    return;
  }

  isFetching.value = true;
  try {
    statusText.value = '1/2 正在向服务器请求接收方公钥...';

    const res = await ensureOk(
      await apiFetch(`${API_BASE}/keys/${encodeURIComponent(ids.target)}`),
      '获取接收方公钥'
    );

    const data = (await res.json()) as KeyLookupResponse;
    if (!data?.kem_public_key || !data?.user_id) {
      throw new Error('服务端返回数据不完整');
    }

    statusText.value = '2/2 正在解析公钥并建立候选会话...';
    const bytes = base64ToBytes(data.kem_public_key);
    const fingerprint = makeFingerprint(bytes);

    session.setCurrentUser(ids.me);
    session.setTarget(data.user_id, bytes, fingerprint);

    statusText.value = '已获取目标公钥，请进行 TOFU 指纹核验。';
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : '获取目标公钥失败';
    errorText.value = msg;
  } finally {
    isFetching.value = false;
  }
}

function confirmTofu() {
  try {
    session.verifyTofu();
  } catch (e: unknown) {
    errorText.value = e instanceof Error ? e.message : 'TOFU 确认失败';
  }
}

function rejectTofu() {
  session.destroySession();
  alert('🛡️ 已阻断可能受到中间人篡改的连接，安全上下文已销毁。');
}
</script>

<style scoped>
.sender-view {
  max-width: 650px;
  margin: 40px auto;
  padding: 20px;
  font-family: system-ui, sans-serif;
}

h2 {
  color: #e2e8f0;
  text-align: center;
  margin-bottom: 30px;
  font-weight: 700;
  text-shadow: 0 0 20px rgba(34, 211, 238, 0.2);
}

.glass-card {
  background: rgba(15, 23, 42, 0.6);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid rgba(34, 211, 238, 0.2);
  box-shadow: 0 0 40px rgba(34, 211, 238, 0.06), inset 0 1px 0 rgba(255, 255, 255, 0.05);
}

.card {
  padding: 25px;
  margin-bottom: 20px;
  border-radius: 14px;
}

h3 {
  margin-top: 0;
  color: #f1f5f9;
  border-bottom: 1px solid rgba(34, 211, 238, 0.3);
  padding-bottom: 10px;
}

.subtitle {
  color: rgba(148, 163, 184, 0.95);
  font-size: 0.9em;
  margin-bottom: 15px;
}

.field-label {
  display: block;
  font-size: 0.875rem;
  color: rgba(148, 163, 184, 0.9);
  margin-bottom: 6px;
  margin-top: 4px;
}
.field-label:first-of-type {
  margin-top: 0;
}

.tech-input,
input {
  display: block;
  width: 100%;
  margin-bottom: 15px;
  padding: 12px 14px;
  border: 1px solid rgba(34, 211, 238, 0.3);
  border-radius: 8px;
  box-sizing: border-box;
  font-size: 1em;
  background: rgba(15, 23, 42, 0.8);
  color: #f1f5f9;
}

.tech-input::placeholder,
input::placeholder {
  color: rgba(148, 163, 184, 0.6);
}

.tech-input:focus,
input:focus {
  outline: none;
  border-color: rgba(34, 211, 238, 0.6);
  box-shadow: 0 0 0 2px rgba(34, 211, 238, 0.15);
}

.tech-input-locked {
  background: rgba(30, 41, 59, 0.9);
  color: rgba(148, 163, 184, 0.95);
  border-color: rgba(71, 85, 105, 0.5);
  cursor: not-allowed;
}
.tech-input-locked:focus {
  border-color: rgba(71, 85, 105, 0.5);
  box-shadow: none;
}

button {
  padding: 12px 20px;
  cursor: pointer;
  border: none;
  border-radius: 8px;
  font-weight: bold;
  transition: all 0.2s;
}

.primary-btn {
  background: linear-gradient(135deg, #22d3ee 0%, #06b6d4 100%);
  color: #0a0e17;
  width: 100%;
  font-size: 1.05em;
  box-shadow: 0 0 20px rgba(34, 211, 238, 0.3);
}

.primary-btn:hover:not(:disabled) {
  box-shadow: 0 0 28px rgba(34, 211, 238, 0.4);
  transform: translateY(-1px);
}

.primary-btn:disabled {
  background: rgba(100, 116, 139, 0.5);
  color: #94a3b8;
  cursor: not-allowed;
  box-shadow: none;
}

.warning {
  color: #f87171;
  font-weight: bold;
  font-size: 0.95em;
}

.success-text {
  color: #34d399;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
}

.switch-target-btn {
  margin-left: 8px;
  padding: 6px 12px;
  font-size: 0.85em;
  font-weight: 600;
  background: rgba(148, 163, 184, 0.2);
  color: #94a3b8;
  border: 1px solid rgba(148, 163, 184, 0.4);
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.switch-target-btn:hover {
  background: rgba(148, 163, 184, 0.3);
  color: #e2e8f0;
  border-color: rgba(148, 163, 184, 0.5);
}

.fingerprint-box {
  background: rgba(15, 23, 42, 0.95);
  color: #34d399;
  padding: 20px;
  font-family: 'Courier New', ui-monospace, monospace;
  text-align: center;
  font-size: 1.1em;
  letter-spacing: 3px;
  margin: 20px 0;
  border-radius: 8px;
  word-break: break-all;
  border: 1px solid rgba(52, 211, 153, 0.3);
  box-shadow: 0 0 20px rgba(52, 211, 153, 0.1);
}

.action-group {
  display: flex;
  gap: 15px;
}

.safe-btn {
  background: linear-gradient(135deg, #34d399 0%, #10b981 100%);
  color: #0a0e17;
  flex: 1;
  font-weight: 700;
}

.safe-btn:hover {
  box-shadow: 0 0 24px rgba(52, 211, 153, 0.4);
  transform: translateY(-1px);
}

.danger-btn {
  background: rgba(248, 113, 113, 0.2);
  color: #fca5a5;
  flex: 1;
  border: 1px solid rgba(248, 113, 113, 0.4);
  font-weight: 700;
}

.danger-btn:hover {
  background: rgba(248, 113, 113, 0.3);
  border-color: rgba(248, 113, 113, 0.6);
  transform: translateY(-1px);
}

.status-text {
  margin-top: 12px;
  color: rgba(34, 211, 238, 0.95);
  font-size: 0.92em;
}

.error-text {
  margin-top: 10px;
  color: #f87171;
  font-size: 0.92em;
}

.sent-tracking-hint {
  margin: 10px 0;
  padding: 10px 12px;
  background: rgba(52, 211, 153, 0.1);
  border: 1px solid rgba(52, 211, 153, 0.3);
  border-radius: 8px;
  color: #34d399;
  font-size: 0.9rem;
}
.sent-tracking-id { font-family: ui-monospace, monospace; margin: 0 4px; }
.sent-inbox-card .refresh-btn {
  padding: 6px 12px;
  font-size: 0.9rem;
  color: #22d3ee;
  background: rgba(34, 211, 238, 0.15);
  border: 1px solid rgba(34, 211, 238, 0.4);
  border-radius: 8px;
  cursor: pointer;
}
.sent-inbox-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}
.sent-inbox-header h3 { margin: 0; }
.empty-hint { color: #94a3b8; font-size: 0.9rem; margin: 12px 0; }
.sent-item {
  border: 1px solid rgba(34, 211, 238, 0.2);
  padding: 12px;
  margin-bottom: 10px;
  border-radius: 8px;
  background: rgba(15, 23, 42, 0.4);
}
.sent-meta { margin: 0; font-size: 0.9rem; color: #e2e8f0; word-break: break-all; }
.sent-name { font-weight: 600; display: block; margin-bottom: 4px; }
.sent-tracking-row { display: inline-flex; align-items: center; gap: 6px; margin-right: 8px; }
.sent-tracking-row code { font-size: 0.85em; background: rgba(0,0,0,0.2); padding: 2px 6px; border-radius: 4px; }
.sent-inbox-card .copy-tracking-btn {
  padding: 2px 8px;
  font-size: 0.8rem;
  color: #22d3ee;
  background: rgba(34, 211, 238, 0.15);
  border: 1px solid rgba(34, 211, 238, 0.4);
  border-radius: 4px;
  cursor: pointer;
}
.sent-pagination {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  margin-top: 16px;
  padding-top: 12px;
  border-top: 1px solid rgba(34, 211, 238, 0.2);
}
.sent-pagination .page-btn {
  padding: 6px 14px;
  font-size: 0.9rem;
  color: #22d3ee;
  background: rgba(34, 211, 238, 0.15);
  border: 1px solid rgba(34, 211, 238, 0.4);
  border-radius: 8px;
  cursor: pointer;
}
.sent-pagination .page-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.sent-pagination .page-info { color: #94a3b8; font-size: 0.9rem; }
</style>
