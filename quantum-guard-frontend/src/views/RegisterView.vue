<template>
  <div class="register-page">
    <div class="register-bg" aria-hidden="true"></div>
    <div class="register-card glass">
      <h1 class="register-title">✨ 注册</h1>
      <p class="register-hint">账号 + 强密码 + 安全邮箱，生成抗量子密钥并加密存入本地金库</p>
      <form @submit.prevent="doRegister" class="register-form">
        <input
          v-model.trim="userId"
          type="text"
          class="tech-input"
          placeholder="账号 (user_id)"
          maxlength="64"
          :disabled="isGenerating"
          autocomplete="username"
        />
        <div class="password-wrap">
          <input
            v-model="password"
            type="password"
            class="tech-input"
            placeholder="密码（至少 8 位，建议包含字母和数字）"
            :disabled="isGenerating"
            autocomplete="new-password"
          />
        </div>
        <div class="password-wrap">
          <input
            v-model="confirmPassword"
            type="password"
            class="tech-input"
            placeholder="确认密码"
            :disabled="isGenerating"
            autocomplete="new-password"
          />
        </div>

        <div class="email-panel">
          <div class="email-panel-inner">
            <input
              v-model.trim="email"
              type="email"
              class="tech-input"
              placeholder="安全邮箱（选填）"
              title="验证码将发送到此邮箱"
              :disabled="isGenerating"
            />
            <p class="email-send-hint">验证码将发送到上方填写的邮箱</p>
            <div class="code-row">
              <input
                v-model.trim="code"
                type="text"
                class="tech-input code-input"
                placeholder="邮箱验证码"
                maxlength="6"
                :disabled="isGenerating"
              />
              <button
                type="button"
                class="secondary-btn"
                :disabled="codeCooldown > 0 || isGenerating || !email"
                @click="sendCode"
              >
                {{ codeCooldown > 0 ? `${codeCooldown}s 后重试` : '获取验证码' }}
              </button>
            </div>
            <p class="email-hint">（可选）用于新设备验证与忘记密码</p>
          </div>
        </div>

        <button type="submit" class="primary-btn" :disabled="isGenerating">
          {{ isGenerating ? '⏳ 正在生成密钥并登记...' : '注册并生成密钥' }}
        </button>
      </form>
      <p v-if="statusText" class="status-text">{{ statusText }}</p>
      <p v-if="alreadyHint" class="already-hint">
        {{ alreadyHint }}
        <RouterLink to="/login" class="already-login-link">去登录</RouterLink>
      </p>
      <p v-if="errorText" class="error-text">{{ errorText }}</p>
      <RouterLink to="/login" class="login-link">已有账号？去登录</RouterLink>
      <RouterLink to="/" class="back-link">← 返回首页</RouterLink>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import { useRouter, RouterLink } from 'vue-router';
import { KemEngine } from '../core/kem-engine';
import { DsaEngine } from '../core/dsa-engine';
import {
  generateMK,
  encryptMKWithPassword,
  encryptAsymWithMK,
  buildPasswordBox,
  zeroBuffer
} from '../core/masterKey';
import { saveKeyBackupV2 } from '../core/secure-sandbox';
import { bytesToBase64 } from '../core/key-storage';
import { useSessionStore } from '../store/session';
import { API_BASE, ensureOk, apiFetch } from '../api/client';

const router = useRouter();
const session = useSessionStore();

const userId = ref('');
const password = ref('');
const confirmPassword = ref('');
const email = ref('');
const code = ref('');
const codeCooldown = ref(0);
const isGenerating = ref(false);
const statusText = ref('');
const errorText = ref('');
const alreadyHint = ref('');

let codeCooldownTimer: ReturnType<typeof setInterval> | null = null;

watch(codeCooldown, (v) => {
  if (v <= 0 && codeCooldownTimer) {
    clearInterval(codeCooldownTimer);
    codeCooldownTimer = null;
  }
});

async function sendCode() {
  const e = email.value.trim().toLowerCase();
  if (!e || !e.includes('@')) {
    errorText.value = '请填写有效邮箱';
    return;
  }
  if (codeCooldown.value > 0) return;
  errorText.value = '';
  try {
    await ensureOk(
      await apiFetch(`${API_BASE}/api/auth/send-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: e })
      }),
      '发送验证码'
    );
    codeCooldown.value = 60;
    codeCooldownTimer = setInterval(() => {
      codeCooldown.value--;
      if (codeCooldown.value <= 0 && codeCooldownTimer) {
        clearInterval(codeCooldownTimer);
        codeCooldownTimer = null;
      }
    }, 1000);
    statusText.value = '验证码已发送，请查收邮件';
  } catch (err: unknown) {
    errorText.value = err instanceof Error ? err.message : '发送验证码失败';
  }
}

function validatePasswordStrength(pwd: string): string | null {
  if (pwd.length < 8) return '密码至少需 8 位';
  const hasLetter = /[A-Za-z]/.test(pwd);
  const hasDigit = /\d/.test(pwd);
  if (!hasLetter || !hasDigit) return '建议包含字母和数字，以提高安全性';
  return null;
}

async function doRegister() {
  errorText.value = '';
  statusText.value = '';
  alreadyHint.value = '';
  const uid = userId.value.trim();
  const pwd = password.value;
  const confirm = confirmPassword.value;
  const mail = email.value.trim().toLowerCase();
  const mailCode = code.value.trim();

  if (!uid) {
    errorText.value = '请先输入账号';
    return;
  }
  if (!pwd) {
    errorText.value = '请先输入密码';
    return;
  }
  const pwdHint = validatePasswordStrength(pwd);
  if (pwdHint) {
    errorText.value = pwdHint;
    return;
  }
  if (pwd !== confirm) {
    errorText.value = '两次输入的密码不一致';
    return;
  }
  const hasEmail = !!(mail && mail.includes('@'));
  if (hasEmail && (!mailCode || mailCode.length !== 6)) {
    errorText.value = '请填写 6 位邮箱验证码';
    return;
  }

  const REGISTER_TIMEOUT_MS = 10000;
  isGenerating.value = true;
  let mk: Uint8Array | null = null;
  try {
    statusText.value = '正在生成主密钥与密钥对...';
    mk = generateMK();
    const kemPair = await KemEngine.generateKeyPair();
    const dsaPair = DsaEngine.generateKeyPair();

    statusText.value = '正在加密并写入本地金库...';
    const { blob: mkEncryptedLocal } = await encryptMKWithPassword(mk, pwd, uid);
    const asymPrivEncrypted = await encryptAsymWithMK(kemPair.privateKey, dsaPair.privateKey, mk);
    await saveKeyBackupV2(uid, mkEncryptedLocal, asymPrivEncrypted);

    statusText.value = '正在构建密码盒...';
    const { saltB64, mkEncryptedB64 } = await buildPasswordBox(mk, pwd);
    const asymPrivEncryptedBase64 = btoa(String.fromCharCode(...Array.from(asymPrivEncrypted)));

    statusText.value = '正在向服务器登记账号...';
    const body: Record<string, string> = {
      user_id: uid,
      password: pwd,
      kem_public_key: bytesToBase64(kemPair.publicKey),
      dsa_public_key: bytesToBase64(dsaPair.publicKey),
      asym_priv_encrypted: asymPrivEncryptedBase64,
      password_box_salt: saltB64,
      mk_encrypted_by_password: mkEncryptedB64
    };
    if (hasEmail) {
      body.email = mail;
      body.code = mailCode!;
    }
    const res = await apiFetch(`${API_BASE}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }, REGISTER_TIMEOUT_MS);
    if (!res.ok) {
      const errData = await res.json().catch(() => ({})) as { detail?: string };
      const detail = (errData.detail ?? res.statusText ?? '').toString();
      if (res.status === 400 && (detail.includes('已存在') || detail.includes('已注册'))) {
        alreadyHint.value = '该账号已注册，请直接登录';
        return;
      }
      await ensureOk(res, '注册');
    }

    statusText.value = '正在自动登录...';
    const loginRes = await apiFetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: uid, password: pwd })
    }, REGISTER_TIMEOUT_MS);
    const loginData = await loginRes.json().catch(() => ({})) as { token?: string; detail?: string };
    if (!loginRes.ok || !loginData.token) {
      throw new Error((loginData.detail as string) || '登录获取 Token 失败，请手动登录');
    }
    const token = loginData.token as string;
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('quantum_guard_auth_token', token);
      localStorage.setItem('quantum_guard_my_id', uid);
    }
    session.setSessionAfterLogin(token, uid, kemPair.privateKey, dsaPair.privateKey);
    zeroBuffer(mk);
    mk = null;
    statusText.value = '注册成功，正在进入接收舱...';
    await router.replace('/receiver');
  } catch (e: unknown) {
    console.error('[DEBUG] 发生致命错误（注册）:', e);
    if (e instanceof Error && e.stack) console.error(e.stack);
    const msg = e instanceof Error ? e.message : '注册失败';
    errorText.value = msg;
    alert(msg || '网络或系统错误');
  } finally {
    if (mk) {
      zeroBuffer(mk);
    }
    isGenerating.value = false;
  }
}
</script>

<style scoped>
.register-page {
  position: relative;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  overflow: hidden;
}

.register-bg {
  position: absolute;
  inset: 0;
  background: linear-gradient(
    135deg,
    #0a0e17 0%,
    #0d1321 40%,
    #0f1729 70%,
    #0a0e17 100%
  );
  background-size: 400% 400%;
  animation: gradient-shift 12s ease infinite;
}

.register-bg::before {
  content: '';
  position: absolute;
  inset: 0;
  background: radial-gradient(
    ellipse 70% 50% at 50% 20%,
    rgba(34, 211, 238, 0.06) 0%,
    transparent 50%
  );
}

@keyframes gradient-shift {
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
}

.glass {
  background: rgba(15, 23, 42, 0.6);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid rgba(34, 211, 238, 0.2);
  box-shadow: 0 0 40px rgba(34, 211, 238, 0.08), inset 0 1px 0 rgba(255, 255, 255, 0.05);
}

.register-card {
  position: relative;
  z-index: 1;
  width: 100%;
  max-width: 400px;
  padding: 32px;
  border-radius: 16px;
}

.register-title {
  font-size: 1.5rem;
  font-weight: 700;
  color: #f1f5f9;
  margin: 0 0 8px;
}

.register-hint {
  color: rgba(148, 163, 184, 0.95);
  font-size: 0.9rem;
  margin: 0 0 24px;
  line-height: 1.5;
}

.register-form {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.tech-input {
  width: 100%;
  padding: 14px 16px;
  font-size: 1rem;
  color: #f1f5f9;
  background: rgba(15, 23, 42, 0.8);
  border: 1px solid rgba(34, 211, 238, 0.3);
  border-radius: 10px;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
  box-sizing: border-box;
}

.tech-input::placeholder {
  color: rgba(148, 163, 184, 0.6);
}

.tech-input:focus {
  border-color: rgba(34, 211, 238, 0.7);
  box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.15);
}

.password-wrap {
  width: 100%;
}

.email-panel {
  border: 1px solid rgba(34, 211, 238, 0.25);
  border-radius: 10px;
  padding: 12px;
  background: rgba(15, 23, 42, 0.4);
}

.email-panel-toggle {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: rgba(148, 163, 184, 0.95);
  font-size: 0.9rem;
}

.email-panel-toggle input {
  width: auto;
}

.email-panel-inner {
  margin-top: 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.email-send-hint {
  margin: -4px 0 0 0;
  font-size: 0.75rem;
  color: rgba(148, 163, 184, 0.65);
  line-height: 1.3;
}

.email-hint {
  margin: 0;
  font-size: 0.8rem;
  color: rgba(148, 163, 184, 0.7);
  line-height: 1.3;
}

.code-row {
  display: flex;
  gap: 8px;
}

.code-input {
  flex: 1;
}

.secondary-btn {
  padding: 14px 16px;
  font-size: 0.9rem;
  font-weight: 600;
  color: #22d3ee;
  background: rgba(34, 211, 238, 0.15);
  border: 1px solid rgba(34, 211, 238, 0.4);
  border-radius: 10px;
  cursor: pointer;
  white-space: nowrap;
}

.secondary-btn:hover:not(:disabled) {
  background: rgba(34, 211, 238, 0.25);
}

.secondary-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.primary-btn {
  display: block;
  padding: 14px 24px;
  font-size: 1rem;
  font-weight: 700;
  color: #0a0e17;
  background: linear-gradient(135deg, #22d3ee 0%, #06b6d4 100%);
  border: none;
  border-radius: 10px;
  cursor: pointer;
  transition: transform 0.2s, box-shadow 0.2s;
  text-align: center;
  text-decoration: none;
}

.primary-btn:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 0 24px rgba(34, 211, 238, 0.4);
}

.primary-btn:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.status-text {
  margin-top: 12px;
  color: rgba(34, 211, 238, 0.95);
  font-size: 0.9rem;
}

.already-hint {
  margin-top: 12px;
  color: #34d399;
  font-size: 0.95rem;
  font-weight: 500;
}

.already-login-link {
  margin-left: 6px;
  color: #22d3ee;
  font-weight: 600;
  text-decoration: none;
}

.already-login-link:hover {
  text-decoration: underline;
}

.error-text {
  margin-top: 10px;
  color: #f87171;
  font-size: 0.9rem;
}

.login-link {
  display: inline-block;
  margin-top: 16px;
  color: rgba(34, 211, 238, 0.95);
  font-size: 0.9rem;
  text-decoration: none;
}

.login-link:hover {
  color: #22d3ee;
  text-decoration: underline;
}

.back-link {
  display: inline-block;
  margin-top: 20px;
  color: rgba(148, 163, 184, 0.9);
  font-size: 0.9rem;
  text-decoration: none;
}

.back-link:hover {
  color: #e2e8f0;
}

.recovery-overlay {
  position: fixed;
  inset: 0;
  z-index: 9999;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(0, 0, 0, 0.7);
  padding: 20px;
}

.recovery-modal {
  width: 100%;
  max-width: 480px;
  padding: 24px;
  border-radius: 16px;
}

.recovery-title {
  font-size: 1.25rem;
  font-weight: 700;
  color: #f1f5f9;
  margin: 0 0 12px;
}

.recovery-desc {
  font-size: 0.9rem;
  color: rgba(148, 163, 184, 0.95);
  line-height: 1.5;
  margin: 0 0 16px;
}

.recovery-code-box {
  background: rgba(15, 23, 42, 0.9);
  border: 1px solid rgba(34, 211, 238, 0.3);
  border-radius: 10px;
  padding: 14px 16px;
  margin-bottom: 16px;
  word-break: break-all;
}

.recovery-words {
  font-family: ui-monospace, monospace;
  font-size: 0.95rem;
  color: #22d3ee;
  line-height: 1.6;
}

.recovery-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  align-items: stretch;
}

.recovery-actions .primary-btn,
.recovery-actions .secondary-btn {
  min-height: 44px;
}

.recovery-btn-copy {
  flex: 0 0 auto;
  min-width: 72px;
}

.recovery-btn-cancel {
  flex: 0 0 auto;
  min-width: 64px;
  white-space: nowrap;
}

.recovery-btn-confirm {
  flex: 1 1 auto;
  min-width: 140px;
  white-space: nowrap;
}

.recovery-actions-hint {
  width: 100%;
  margin: 8px 0 0;
  font-size: 0.8rem;
  color: rgba(148, 163, 184, 0.85);
  line-height: 1.4;
}
</style>
