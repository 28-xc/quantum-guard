<template>
  <div class="receiver-view">
    <h2>🛡️ 安全接收舱</h2>
    <p class="receiver-desc">使用您已登录的唯一账号接收文件</p>

    <div class="card glass-card">
      <h3>✅ 防御阵地已就绪</h3>
      <p class="success-text">您的私钥已安全锁定在本地 IndexedDB。服务器仅掌握您的公钥。</p>

      <div class="info-group">
        <label>您的全球唯一 ID：</label>
        <div class="value-box">{{ myId }}</div>
      </div>

      <div class="info-group">
        <label>您的安全指纹 (请通过电话读给发送方听)：</label>
        <div class="fingerprint-box">{{ localFingerprint }}</div>
      </div>

      <div class="toolbar">
        <button class="ghost-btn" @click="openResetConfirm" :disabled="isResetting">
          ♻️ 重置本地身份（将退出并清除密钥，需重新注册）
        </button>
      </div>

      <FileDownloader :myId="myId" />
    </div>

    <Teleport to="body">
      <div v-if="showResetConfirm" class="reset-overlay" @click.self="closeResetConfirm">
        <div class="reset-modal">
          <h3 class="reset-title">重置本地身份</h3>
          <p class="reset-text">
            确定重置本地身份吗？将清除本地密钥并退出，需在首页重新注册。
          </p>
          <div class="reset-actions">
            <button
              type="button"
              class="reset-btn primary"
              @click="confirmResetIdentity"
              :disabled="isResetting"
            >
              确定
            </button>
            <button
              type="button"
              class="reset-btn"
              @click="closeResetConfirm"
              :disabled="isResetting"
            >
              取消
            </button>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import FileDownloader from '../components/FileDownloader.vue';
import { KeyStorage } from '../core/key-storage';
import { useSessionStore } from '../store/session';

const MY_ID_STORAGE_KEY = 'quantum_guard_my_id';

const router = useRouter();
const session = useSessionStore();

const myId = ref('');
const localFingerprint = ref('');
const isResetting = ref(false);
const showResetConfirm = ref(false);

onMounted(async () => {
  try {
    const keys = await KeyStorage.getKeys();
    const storedId = (localStorage.getItem(MY_ID_STORAGE_KEY) ?? '').trim();
    if (!keys || !storedId) {
      await router.replace('/');
      return;
    }
    myId.value = storedId;
    localFingerprint.value = keys.fingerprint;
    session.setCurrentUser(storedId);
  } catch {
    await router.replace('/');
  }
});

function openResetConfirm() {
  showResetConfirm.value = true;
}

function closeResetConfirm() {
  if (isResetting.value) return;
  showResetConfirm.value = false;
}

async function confirmResetIdentity() {
  if (isResetting.value) return;
  isResetting.value = true;
  showResetConfirm.value = false;
  const uid = myId.value.trim();
  try {
    if (uid) await KeyStorage.clearKeys(uid);
  } catch (e) {
    console.warn('[重置本地身份] 清除 IndexedDB 密钥失败，继续执行登出与跳转', e);
  }
  localStorage.removeItem(MY_ID_STORAGE_KEY);
  session.resetAll();
  await router.replace('/');
  isResetting.value = false;
}
</script>

<style scoped>
.receiver-view {
  max-width: 650px;
  margin: 40px auto;
  padding: 20px;
  font-family: system-ui, sans-serif;
}

h2 {
  color: #e2e8f0;
  text-align: center;
  margin-bottom: 8px;
  font-weight: 700;
  text-shadow: 0 0 20px rgba(34, 211, 238, 0.2);
}

.receiver-desc {
  color: #94a3b8;
  text-align: center;
  font-size: 0.95rem;
  margin: 0 0 30px;
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
  border-radius: 14px;
}

h3 {
  margin-top: 0;
  color: #f1f5f9;
  border-bottom: 1px solid rgba(34, 211, 238, 0.3);
  padding-bottom: 10px;
}

.success-text {
  color: #34d399;
  font-weight: bold;
  margin-bottom: 20px;
}

.info-group {
  margin-bottom: 15px;
}

.info-group label {
  display: block;
  color: #94a3b8;
  font-weight: bold;
  margin-bottom: 5px;
}

.value-box {
  background: rgba(15, 23, 42, 0.8);
  padding: 10px 14px;
  border-radius: 8px;
  color: #e2e8f0;
  border: 1px solid rgba(34, 211, 238, 0.2);
}

.fingerprint-box {
  background: rgba(15, 23, 42, 0.95);
  color: #34d399;
  padding: 15px;
  font-family: 'Courier New', ui-monospace, monospace;
  text-align: center;
  font-size: 1.05em;
  letter-spacing: 2px;
  border-radius: 8px;
  word-break: break-all;
  border: 1px solid rgba(52, 211, 153, 0.3);
  box-shadow: 0 0 20px rgba(52, 211, 153, 0.1);
}

.toolbar {
  margin: 8px 0 16px;
  display: flex;
  justify-content: flex-end;
}

.reset-overlay {
  position: fixed;
  inset: 0;
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(6px);
}

.reset-modal {
  max-width: 420px;
  width: 100%;
  padding: 20px 22px 18px;
  border-radius: 14px;
  background: rgba(15, 23, 42, 0.98);
  border: 1px solid rgba(34, 211, 238, 0.5);
  box-shadow: 0 22px 60px rgba(15, 23, 42, 0.9);
}

.reset-title {
  margin: 0 0 8px;
  font-size: 1.05rem;
  color: #e2e8f0;
}

.reset-text {
  margin: 0 0 18px;
  font-size: 0.9rem;
  color: #cbd5f5;
}

.reset-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

.reset-btn {
  min-width: 84px;
  padding: 7px 14px;
  border-radius: 999px;
  border: 1px solid rgba(148, 163, 184, 0.6);
  background: transparent;
  color: #e5e7eb;
  font-size: 0.9rem;
  cursor: pointer;
  transition: all 0.18s ease-out;
}

.reset-btn.primary {
  border-color: rgba(248, 113, 113, 0.85);
  background: linear-gradient(135deg, rgba(248, 113, 113, 0.22), rgba(239, 68, 68, 0.32));
  color: #fee2e2;
}

.reset-btn:hover:not(:disabled) {
  border-color: rgba(148, 163, 184, 0.9);
  background: rgba(30, 64, 175, 0.3);
}

.reset-btn.primary:hover:not(:disabled) {
  border-color: rgba(248, 113, 113, 1);
  background: linear-gradient(135deg, rgba(248, 113, 113, 0.35), rgba(239, 68, 68, 0.5));
}

.reset-btn:disabled {
  opacity: 0.7;
  cursor: default;
}

.ghost-btn {
  background: rgba(34, 211, 238, 0.1);
  color: #e2e8f0;
  border: 1px solid rgba(34, 211, 238, 0.3);
  padding: 10px 16px;
  border-radius: 8px;
  cursor: pointer;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.ghost-btn:hover:not(:disabled) {
  background: rgba(34, 211, 238, 0.2);
  border-color: rgba(34, 211, 238, 0.5);
}

.ghost-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
</style>
