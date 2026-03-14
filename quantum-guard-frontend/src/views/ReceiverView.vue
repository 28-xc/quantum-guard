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

      <FileDownloader :myId="myId" />
    </div>
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
</style>
