<template>
  <div class="app-wrap">
    <div class="app-bg" aria-hidden="true">
      <div class="grid-overlay" aria-hidden="true"></div>
    </div>
    <template v-if="showMainLayout">
      <header class="app-header">
        <h1 class="app-title">🛡️ QuantumGuard</h1>
        <p class="app-subtitle">零信任 · 抗量子端到端加密</p>
        <SecurityDashboard />
        <nav class="nav-tabs" aria-label="主导航">
          <RouterLink to="/receiver" class="nav-btn">📡 接收舱</RouterLink>
          <RouterLink to="/sender" class="nav-btn">🚀 发送舱</RouterLink>
          <button type="button" class="nav-btn nav-btn-secondary" @click="openBindEmailModal">
            {{ bindEmailLabel }}
          </button>
          <button type="button" class="nav-btn nav-btn-secondary" @click="openChangePasswordModal">
            修改密码
          </button>
          <RouterLink to="/" class="nav-btn exit">退出</RouterLink>
        </nav>
      </header>
      <main class="app-main">
        <RouterView />
      </main>

      <Teleport to="body">
        <div v-if="showChangePasswordModal" class="cp-overlay" @click.self="showChangePasswordModal = false">
          <div class="cp-modal glass-card">
            <h3 class="cp-title">修改密码</h3>
            <p class="cp-hint">
              将向您的绑定邮箱{{ emailMasked ? ` ${emailMasked} ` : '' }}发送验证码。
            </p>
            <form @submit.prevent="submitChangePassword" class="cp-form">
              <label class="cp-field-label">当前密码</label>
              <input
                v-model="cpCurrentPassword"
                type="password"
                class="cp-input"
                placeholder="当前登录密码（用于重加密本地金库）"
                :disabled="cpLoading"
                autocomplete="current-password"
              />
              <div class="cp-code-row">
                <input
                  v-model.trim="cpCode"
                  type="text"
                  class="cp-input"
                  placeholder="验证码"
                  maxlength="6"
                  :disabled="cpLoading"
                />
                <button
                  type="button"
                  class="cp-btn-secondary"
                  :disabled="cpCodeCooldown > 0 || cpLoading"
                  @click="sendChangePasswordCode"
                >
                  {{ cpCodeCooldown > 0 ? `${cpCodeCooldown}s 后重试` : '获取验证码' }}
                </button>
              </div>
              <label class="cp-field-label">新密码</label>
              <div class="cp-password-wrap">
                <input
                  v-model="cpNewPassword"
                  :type="cpShowNewPwd ? 'text' : 'password'"
                  class="cp-input"
                  placeholder="新密码"
                  :disabled="cpLoading"
                  autocomplete="new-password"
                />
                <button
                  type="button"
                  class="cp-eye-btn"
                  :aria-label="cpShowNewPwd ? '隐藏' : '显示'"
                  @click="cpShowNewPwd = !cpShowNewPwd"
                >
                  <svg v-if="cpShowNewPwd" class="cp-eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" /><line x1="1" y1="1" x2="23" y2="23" />
                  </svg>
                  <svg v-else class="cp-eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" />
                  </svg>
                </button>
              </div>
              <label class="cp-field-label">确认新密码</label>
              <div class="cp-password-wrap">
                <input
                  v-model="cpConfirmPassword"
                  :type="cpShowConfirmPwd ? 'text' : 'password'"
                  class="cp-input"
                  placeholder="再次输入新密码"
                  :disabled="cpLoading"
                  autocomplete="new-password"
                />
                <button
                  type="button"
                  class="cp-eye-btn"
                  :aria-label="cpShowConfirmPwd ? '隐藏' : '显示'"
                  @click="cpShowConfirmPwd = !cpShowConfirmPwd"
                >
                  <svg v-if="cpShowConfirmPwd" class="cp-eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" /><line x1="1" y1="1" x2="23" y2="23" />
                  </svg>
                  <svg v-else class="cp-eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" />
                  </svg>
                </button>
              </div>
              <p v-if="cpError" class="cp-error">{{ cpError }}</p>
              <p v-if="cpStatus" class="cp-status">{{ cpStatus }}</p>
              <div class="cp-actions">
                <button type="button" class="cp-btn-secondary" @click="showChangePasswordModal = false">取消</button>
                <button type="submit" class="cp-btn-primary" :disabled="cpLoading">
                  {{ cpLoading ? '提交中...' : '确认修改' }}
                </button>
              </div>
            </form>
          </div>
        </div>
      </Teleport>

      <Teleport to="body">
        <div v-if="showBindEmailModal" class="cp-overlay" @click.self="showBindEmailModal = false">
          <div class="cp-modal glass-card">
            <h3 class="cp-title">{{ emailMaskedForBind ? '修改绑定邮箱' : '绑定邮箱' }}</h3>
            <p class="cp-hint">
              当前账号：
              <strong>{{ session.currentUserId || '（未登录）' }}</strong>
              <span v-if="emailMaskedForBind">
                ，已绑定邮箱 {{ emailMaskedForBind }}，修改后将以新邮箱用于新设备验证与忘记密码。
              </span>
              <span v-else>，尚未绑定安全邮箱，可在此补绑。</span>
            </p>
            <form @submit.prevent="submitBindEmail" class="cp-form">
              <label class="cp-field-label">邮箱地址</label>
              <input
                v-model.trim="bindEmail"
                type="email"
                class="cp-input"
                placeholder="安全邮箱"
                :disabled="bindLoading"
                autocomplete="email"
              />
              <div class="cp-code-row">
                <input
                  v-model.trim="bindCode"
                  type="text"
                  class="cp-input"
                  placeholder="验证码"
                  maxlength="6"
                  :disabled="bindLoading"
                />
                <button
                  type="button"
                  class="cp-btn-secondary"
                  :disabled="bindCodeCooldown > 0 || bindLoading || !bindEmail"
                  @click="sendBindEmailCode"
                >
                  {{ bindCodeCooldown > 0 ? `${bindCodeCooldown}s 后重试` : '获取验证码' }}
                </button>
              </div>
              <p v-if="bindError" class="cp-error">{{ bindError }}</p>
              <p v-if="bindStatus" class="cp-status">{{ bindStatus }}</p>
              <div class="cp-actions">
                <button type="button" class="cp-btn-secondary" @click="showBindEmailModal = false">取消</button>
                <button type="submit" class="cp-btn-primary" :disabled="bindLoading">
                  {{ bindLoading ? '提交中...' : (emailMaskedForBind ? '确认修改邮箱' : '确认绑定邮箱') }}
                </button>
              </div>
            </form>
          </div>
        </div>
      </Teleport>

    </template>
    <template v-else>
      <RouterView />
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { RouterLink, RouterView } from 'vue-router';
import SecurityDashboard from './components/SecurityDashboard.vue';
import { useSessionStore } from './store/session';
import { API_BASE, apiFetch, ensureOk } from './api/client';
import { encryptPrivateKeys, decryptPrivateKeys } from './core/cryptoManager';
import {
  getKeyBackupV2,
  saveKeyBackupV2,
  getEncryptedPrivateKeys,
  saveEncryptedPrivateKeys
} from './core/secure-sandbox';
import { decryptMKWithPassword, encryptMKWithPassword, zeroBuffer } from './core/masterKey';

const route = useRoute();
const router = useRouter();
const session = useSessionStore();
const showMainLayout = computed(
  () =>
    route.path !== '/' &&
    route.path !== '/login' &&
    route.path !== '/register'
);

const showChangePasswordModal = ref(false);
const emailMasked = ref<string | null>(null);
const cpCurrentPassword = ref('');
const cpCode = ref('');
const cpNewPassword = ref('');
const cpConfirmPassword = ref('');
const cpShowNewPwd = ref(false);
const cpShowConfirmPwd = ref(false);
const cpCodeCooldown = ref(0);
const cpLoading = ref(false);
const cpError = ref('');
const cpStatus = ref('');
let cpCodeTimer: ReturnType<typeof setInterval> | null = null;
watch(cpCodeCooldown, (v) => {
  if (v <= 0 && cpCodeTimer) {
    clearInterval(cpCodeTimer);
    cpCodeTimer = null;
  }
});

const showBindEmailModal = ref(false);
const emailMaskedForBind = ref<string | null>(null);
const bindEmail = ref('');
const bindCode = ref('');
const bindCodeCooldown = ref(0);
const bindLoading = ref(false);
const bindError = ref('');
const bindStatus = ref('');
let bindCodeTimer: ReturnType<typeof setInterval> | null = null;

const bindEmailLabel = computed(() =>
  emailMaskedForBind.value ? '修改绑定邮箱' : '绑定邮箱'
);

watch(bindCodeCooldown, (v) => {
  if (v <= 0 && bindCodeTimer) {
    clearInterval(bindCodeTimer);
    bindCodeTimer = null;
  }
});


function openChangePasswordModal() {
  showChangePasswordModal.value = true;
  cpCurrentPassword.value = '';
  cpCode.value = '';
  cpNewPassword.value = '';
  cpConfirmPassword.value = '';
  cpError.value = '';
  cpStatus.value = '';
  emailMasked.value = null;
  (async () => {
    try {
      const res = await apiFetch(`${API_BASE}/api/auth/me`);
      if (res.ok) {
        const data = (await res.json()) as { email_masked?: string };
        emailMasked.value = data.email_masked ?? null;
      }
    } catch {
      /* ignore */
    }
  })();
}

function openBindEmailModal() {
  showBindEmailModal.value = true;
  bindEmail.value = '';
  bindCode.value = '';
  bindError.value = '';
  bindStatus.value = '';
  emailMaskedForBind.value = null;
  (async () => {
    try {
      const res = await apiFetch(`${API_BASE}/api/auth/me`);
      if (res.ok) {
        const data = (await res.json()) as { email?: string; email_masked?: string };
        emailMaskedForBind.value = (data.email_masked || data.email || '').trim() || null;
        if (data.email) {
          bindEmail.value = data.email;
        }
      }
    } catch {
      /* ignore */
    }
  })();
}

async function sendChangePasswordCode() {
  if (cpCodeCooldown.value > 0) return;
  cpError.value = '';
  cpStatus.value = '';
  try {
    await ensureOk(
      await apiFetch(`${API_BASE}/api/auth/send-code-change-password`, { method: 'POST' }),
      '发送验证码'
    );
    cpCodeCooldown.value = 60;
    cpStatus.value = '验证码已发送，请查收邮箱';
    cpCodeTimer = setInterval(() => {
      cpCodeCooldown.value--;
      if (cpCodeCooldown.value <= 0 && cpCodeTimer) {
        clearInterval(cpCodeTimer);
        cpCodeTimer = null;
      }
    }, 1000);
  } catch (e: unknown) {
    cpError.value = e instanceof Error ? e.message : '发送验证码失败';
  }
}

async function sendBindEmailCode() {
  if (bindCodeCooldown.value > 0 || bindLoading.value) return;
  bindError.value = '';
  bindStatus.value = '';
  const email = bindEmail.value.trim();
  if (!email) {
    bindError.value = '请先填写要绑定的邮箱';
    return;
  }
  try {
    await ensureOk(
      await apiFetch(`${API_BASE}/api/auth/me/send-bind-email-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      }),
      '发送绑定邮箱验证码'
    );
    bindCodeCooldown.value = 60;
    bindStatus.value = '验证码已发送，请查收邮箱';
    bindCodeTimer = setInterval(() => {
      bindCodeCooldown.value--;
      if (bindCodeCooldown.value <= 0 && bindCodeTimer) {
        clearInterval(bindCodeTimer);
        bindCodeTimer = null;
      }
    }, 1000);
  } catch (e: unknown) {
    bindError.value = e instanceof Error ? e.message : '发送验证码失败';
  }
}

async function submitBindEmail() {
  bindError.value = '';
  bindStatus.value = '';
  const email = bindEmail.value.trim();
  const code = bindCode.value.trim();
  if (!email) {
    bindError.value = '邮箱不能为空';
    return;
  }
  if (!code || code.length !== 6) {
    bindError.value = '请填写 6 位验证码';
    return;
  }
  bindLoading.value = true;
  try {
    const res = await ensureOk(
      await apiFetch(`${API_BASE}/api/auth/me/confirm-bind-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code })
      }),
      '绑定邮箱'
    );
    const data = (await res.json()) as { email?: string };
    const e = (data.email || email).trim();
    emailMaskedForBind.value = e ? `${e[0]}***@${e.split('@')[1]}` : null;
    bindStatus.value = '邮箱绑定成功';
    // 轻微延迟后关闭弹窗，避免用户错觉未成功
    setTimeout(() => {
      showBindEmailModal.value = false;
    }, 800);
  } catch (e: unknown) {
    bindError.value = e instanceof Error ? e.message : '绑定邮箱失败';
  } finally {
    bindLoading.value = false;
  }
}
async function submitChangePassword() {
  cpError.value = '';
  cpStatus.value = '';
  const currentPwd = cpCurrentPassword.value;
  const code = cpCode.value.trim();
  const newPwd = cpNewPassword.value;
  const confirm = cpConfirmPassword.value;
  if (!currentPwd) {
    cpError.value = '请输入当前密码';
    return;
  }
  if (!code || code.length !== 6) {
    cpError.value = '请输入 6 位验证码';
    return;
  }
  if (!newPwd) {
    cpError.value = '请输入新密码';
    return;
  }
  if (newPwd !== confirm) {
    cpError.value = '两次输入的新密码不一致';
    return;
  }
  const myId = session.currentUserId || (typeof localStorage !== 'undefined' ? localStorage.getItem('quantum_guard_my_id') : null) || '';
  if (!myId) {
    cpError.value = '无法获取当前用户，请重新登录';
    return;
  }
  cpLoading.value = true;
  try {
    const vaultV2 = await getKeyBackupV2(myId);
    const vaultV1 = vaultV2 ? null : await getEncryptedPrivateKeys(myId);
    if (vaultV2) {
      cpStatus.value = '正在用新密码重加密本地金库...';
      const mk = await decryptMKWithPassword(vaultV2.mkEncryptedLocal, currentPwd, myId);
      const { blob: mkEncryptedLocal } = await encryptMKWithPassword(mk, newPwd, myId);
      zeroBuffer(mk);
      await saveKeyBackupV2(myId, mkEncryptedLocal, vaultV2.asymPrivEncrypted);
    } else if (vaultV1) {
      cpStatus.value = '正在用新密码重加密本地金库...';
      const { kemPrivateKey, dsaPrivateKey } = await decryptPrivateKeys(
        vaultV1.encrypted,
        vaultV1.salt,
        vaultV1.iv,
        currentPwd
      );
      const { encrypted, salt, iv } = await encryptPrivateKeys(kemPrivateKey, dsaPrivateKey, newPwd);
      await saveEncryptedPrivateKeys(myId, encrypted, salt, iv);
    }
    const res = await apiFetch(`${API_BASE}/api/auth/change-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, new_password: newPwd })
    });
    await ensureOk(res, '修改密码');
    alert('密码修改成功，请使用新密码重新登录');
    session.resetAll();
    showChangePasswordModal.value = false;
    router.replace('/login');
  } catch (e: unknown) {
    cpError.value = e instanceof Error ? e.message : '修改密码失败';
  } finally {
    cpLoading.value = false;
  }
}
</script>

<style>
:root {
  --bg-dark: #0a0e17;
  --glow-cyan: rgba(34, 211, 238, 0.5);
  --glow-cyan-dim: rgba(34, 211, 238, 0.15);
  --text-primary: #f1f5f9;
  --text-muted: #94a3b8;
  --border-cyan: rgba(34, 211, 238, 0.3);
}

*,
*::before,
*::after {
  box-sizing: border-box;
}

html,
body,
#app {
  margin: 0;
  min-height: 100%;
  background: var(--bg-dark);
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  color: var(--text-primary);
}

.app-wrap {
  position: relative;
  min-height: 100vh;
  overflow-x: hidden;
}

.app-bg {
  position: fixed;
  inset: 0;
  z-index: 0;
  background: #060910;
  pointer-events: none;
}

.app-bg::before {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(
    135deg,
    #0a0e17 0%,
    #0f1729 25%,
    #0d1b2a 50%,
    #0f1729 75%,
    #0a0e17 100%
  );
  background-size: 400% 400%;
  animation: app-gradient 18s ease-in-out infinite;
  opacity: 1;
}

.app-bg::after {
  content: '';
  position: absolute;
  inset: 0;
  background:
    radial-gradient(ellipse 80% 50% at 20% 20%, rgba(34, 211, 238, 0.12) 0%, transparent 50%),
    radial-gradient(ellipse 60% 80% at 80% 80%, rgba(139, 92, 246, 0.08) 0%, transparent 50%),
    radial-gradient(ellipse 70% 40% at 50% 100%, rgba(34, 211, 238, 0.06) 0%, transparent 45%);
  animation: app-glow 12s ease-in-out infinite alternate;
}

/* 科技感网格线（低对比，置于光晕之上） */
.app-bg .grid-overlay {
  position: absolute;
  inset: 0;
  z-index: 1;
  background-image:
    linear-gradient(rgba(34, 211, 238, 0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(34, 211, 238, 0.04) 1px, transparent 1px);
  background-size: 56px 56px;
  animation: grid-pulse 8s ease-in-out infinite;
  pointer-events: none;
}

@keyframes app-gradient {
  0%, 100% { background-position: 0% 50%; }
  33% { background-position: 100% 30%; }
  66% { background-position: 50% 100%; }
}

@keyframes app-glow {
  0% { opacity: 0.7; }
  100% { opacity: 1; }
}

@keyframes grid-pulse {
  0%, 100% { opacity: 0.6; }
  50% { opacity: 1; }
}

.app-header {
  position: relative;
  z-index: 1;
  text-align: center;
  padding: 24px 16px 20px;
  max-width: 900px;
  margin: 0 auto;
}

.app-title {
  font-size: clamp(1.4rem, 3vw, 1.8rem);
  font-weight: 800;
  color: var(--text-primary);
  margin: 0 0 4px;
  text-shadow: 0 0 30px var(--glow-cyan-dim);
}

.app-subtitle {
  color: var(--text-muted);
  font-size: 0.9rem;
  font-weight: 600;
  margin: 0 0 16px;
  letter-spacing: 0.08em;
}

.nav-tabs {
  display: flex;
  justify-content: center;
  gap: 12px;
  margin-top: 16px;
  flex-wrap: wrap;
}

.nav-btn {
  display: inline-block;
  padding: 10px 18px;
  border: 1px solid var(--border-cyan);
  background: rgba(15, 23, 42, 0.6);
  backdrop-filter: blur(8px);
  border-radius: 10px;
  font-weight: 600;
  color: var(--text-primary);
  text-decoration: none;
  transition: all 0.2s;
  font-size: 0.95rem;
}

.nav-btn:hover {
  background: rgba(34, 211, 238, 0.1);
  border-color: rgba(34, 211, 238, 0.5);
  box-shadow: 0 0 20px var(--glow-cyan-dim);
  transform: translateY(-1px);
}

.nav-btn.router-link-active {
  background: linear-gradient(135deg, rgba(34, 211, 238, 0.25) 0%, rgba(6, 182, 212, 0.2) 100%);
  border-color: rgba(34, 211, 238, 0.6);
  color: #fff;
  box-shadow: 0 0 24px var(--glow-cyan-dim);
}

.nav-btn.exit {
  border-color: rgba(248, 113, 113, 0.4);
  color: #fca5a5;
}

.nav-btn.exit:hover {
  background: rgba(248, 113, 113, 0.1);
  border-color: rgba(248, 113, 113, 0.6);
}

.nav-btn-secondary {
  border-color: rgba(148, 163, 184, 0.4);
  color: var(--text-muted);
}
.nav-btn-secondary:hover {
  background: rgba(148, 163, 184, 0.08);
  border-color: rgba(148, 163, 184, 0.5);
  color: var(--text-primary);
}

.cp-overlay {
  position: fixed;
  inset: 0;
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
}
.cp-modal {
  width: 100%;
  max-width: 400px;
  padding: 24px;
  border-radius: 14px;
  border: 1px solid var(--border-cyan);
}
.cp-modal.glass-card {
  background: rgba(15, 23, 42, 0.95);
  backdrop-filter: blur(16px);
}
.cp-title {
  margin: 0 0 8px;
  font-size: 1.25rem;
  color: var(--text-primary);
}
.cp-hint {
  margin: 0 0 20px;
  font-size: 0.9rem;
  color: var(--text-muted);
  line-height: 1.5;
}
.cp-form {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.cp-field-label {
  font-size: 0.875rem;
  color: var(--text-muted);
  margin-bottom: 2px;
}
.cp-code-row {
  display: flex;
  gap: 8px;
}
.cp-code-row .cp-input { flex: 1; }
.cp-input {
  width: 100%;
  padding: 12px 14px;
  font-size: 1rem;
  color: var(--text-primary);
  background: rgba(15, 23, 42, 0.9);
  border: 1px solid var(--border-cyan);
  border-radius: 8px;
  box-sizing: border-box;
}
.cp-input::placeholder { color: rgba(148, 163, 184, 0.6); }
.cp-input:focus {
  outline: none;
  border-color: rgba(34, 211, 238, 0.6);
}
.cp-password-wrap {
  position: relative;
  width: 100%;
}
.cp-password-wrap .cp-input { padding-right: 44px; }
.cp-eye-btn {
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translateY(-50%);
  width: 32px;
  height: 32px;
  padding: 0;
  border: none;
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
}
.cp-eye-btn:hover { color: #22d3ee; background: rgba(34, 211, 238, 0.1); }
.cp-eye-icon { width: 20px; height: 20px; pointer-events: none; }
.cp-btn-secondary {
  padding: 10px 16px;
  font-size: 0.9rem;
  font-weight: 600;
  color: #22d3ee;
  background: rgba(34, 211, 238, 0.15);
  border: 1px solid rgba(34, 211, 238, 0.4);
  border-radius: 8px;
  cursor: pointer;
  white-space: nowrap;
}
.cp-btn-secondary:hover:not(:disabled) { background: rgba(34, 211, 238, 0.25); }
.cp-btn-secondary:disabled { opacity: 0.6; cursor: not-allowed; }
.cp-btn-primary {
  padding: 12px 20px;
  font-size: 1rem;
  font-weight: 700;
  color: #0a0e17;
  background: linear-gradient(135deg, #22d3ee 0%, #06b6d4 100%);
  border: none;
  border-radius: 8px;
  cursor: pointer;
}
.cp-btn-primary:hover:not(:disabled) { box-shadow: 0 0 20px rgba(34, 211, 238, 0.4); }
.cp-btn-primary:disabled { opacity: 0.7; cursor: not-allowed; }
.cp-error { margin: 0; font-size: 0.9rem; color: #f87171; }
.cp-status { margin: 0; font-size: 0.9rem; color: #22d3ee; }
.cp-actions {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
  margin-top: 8px;
}
.cp-actions .cp-btn-primary { flex: 1; }

.recovery-backup-modal .recovery-code-box {
  background: rgba(15, 23, 42, 0.9);
  border: 1px solid var(--border-cyan);
  border-radius: 10px;
  padding: 14px 16px;
  margin: 12px 0;
  word-break: break-all;
}
.recovery-backup-modal .recovery-words {
  font-family: ui-monospace, monospace;
  font-size: 0.95rem;
  color: #22d3ee;
  line-height: 1.6;
}

.app-main {
  position: relative;
  z-index: 1;
  max-width: 900px;
  margin: 0 auto;
  padding: 0 16px 40px;
}

@media (max-width: 640px) {
  .app-header { padding: 20px 12px 16px; }
  .nav-btn { width: 100%; max-width: 320px; }
}
</style>
