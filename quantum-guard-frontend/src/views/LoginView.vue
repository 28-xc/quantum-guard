<template>
  <div class="login-page">
    <div class="login-bg" aria-hidden="true"></div>
    <div class="login-card glass">
      <h1 class="login-title">🔐 登录</h1>
      <p class="login-hint">使用账号与密码登录，解密本地金库后使用私钥</p>
      <form @submit.prevent="handleLogin" class="login-form">
        <input
          v-model.trim="inputId"
          type="text"
          class="login-input"
          placeholder="账号 (user_id)"
          maxlength="64"
          :disabled="isLoading"
          autocomplete="username"
        />
        <div class="password-wrap">
          <input
            v-model="inputPassword"
            type="password"
            class="login-input"
            placeholder="密码"
            :disabled="isLoading"
            autocomplete="current-password"
          />
        </div>
        <button type="submit" class="login-btn" :disabled="isLoading">
          {{ isLoading ? '验证中...' : '登录' }}
        </button>
        <button type="button" class="forgot-link" @click="resetModalOpen = true">
          忘记密码？
        </button>
      </form>

      <!-- 新设备：无本机金库时要求邮箱验证码后拉取密码盒恢复 -->
      <div v-if="showNewDeviceStep" class="new-device-panel glass">
        <p class="new-device-hint">检测到新设备登录，验证码已发送到您的绑定邮箱，请输入验证码完成恢复。</p>
        <div class="code-row">
          <input
            v-model.trim="newDeviceCode"
            type="text"
            class="login-input code-input"
            placeholder="6 位验证码"
            maxlength="6"
            :disabled="newDeviceLoading"
          />
          <button
            type="button"
            class="login-btn"
            :disabled="newDeviceLoading || !newDeviceCode || newDeviceCode.length !== 6"
            @click="confirmNewDeviceAndRestore"
          >
            {{ newDeviceLoading ? '恢复中...' : '确认' }}
          </button>
        </div>
        <p v-if="newDeviceError" class="login-error">{{ newDeviceError }}</p>
      </div>
      <p v-if="errorText" class="login-error">{{ errorText }}</p>
      <RouterLink to="/" class="login-back">← 返回首页</RouterLink>
    </div>

    <!-- 忘记密码：仅邮箱验证 + 破产重组（新密钥） -->
    <Teleport to="body">
      <div v-if="resetModalOpen" class="reset-overlay" @click.self="resetModalOpen = false">
        <div class="reset-modal glass">
          <h2 class="reset-title">🔑 忘记密码</h2>
          <p class="reset-hint">验证绑定邮箱后生成全新密钥并覆写账号，请使用新密码登录。</p>
          <form @submit.prevent="doResetPassword" class="reset-form">
            <input
              v-model.trim="resetUserId"
              type="text"
              class="login-input"
              placeholder="账号 (user_id)"
              maxlength="64"
              :disabled="resetLoading"
              autocomplete="username"
            />
            <input
              v-model.trim="resetEmail"
              type="email"
              class="login-input"
              placeholder="绑定邮箱"
              :disabled="resetLoading"
            />
            <div class="code-row">
              <input
                v-model.trim="resetCode"
                type="text"
                class="login-input code-input"
                placeholder="验证码"
                maxlength="6"
                :disabled="resetLoading"
              />
              <button
                type="button"
                class="secondary-btn"
                :disabled="resetCodeCooldown > 0 || resetLoading || !resetEmail"
                @click="sendResetCode"
              >
                {{ resetCodeCooldown > 0 ? `${resetCodeCooldown}s 后重试` : '获取验证码' }}
              </button>
            </div>
            <div class="password-wrap">
              <input
                v-model="resetNewPassword"
                type="password"
                class="login-input"
                placeholder="新密码"
                :disabled="resetLoading"
                autocomplete="new-password"
              />
            </div>
            <p v-if="resetError" class="reset-error">{{ resetError }}</p>
            <p v-if="resetStatus" class="reset-status">{{ resetStatus }}</p>
            <div class="reset-actions">
              <button type="button" class="secondary-btn" @click="resetModalOpen = false">
                取消
              </button>
              <button type="submit" class="login-btn" :disabled="resetLoading">
                {{ resetLoading ? '处理中...' : '确认重置' }}
              </button>
            </div>
          </form>
        </div>
      </div>
    </Teleport>

  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import { useRouter } from 'vue-router';
import {
  getEncryptedPrivateKeys,
  getKeyBackupV2,
  saveKeyBackupV2
} from '../core/secure-sandbox';
import { decryptPrivateKeys } from '../core/cryptoManager';
import {
  generateMK,
  encryptMKWithPassword,
  encryptAsymWithMK,
  buildPasswordBox,
  decryptMKWithPassword,
  decryptAsymWithMK,
  decryptMKFromPasswordBox,
  zeroBuffer
} from '../core/masterKey';
import { KemEngine } from '../core/kem-engine';
import { DsaEngine } from '../core/dsa-engine';
import { bytesToBase64 } from '../core/key-storage';
import { useSessionStore } from '../store/session';
import { API_BASE, ensureOk, apiFetch } from '../api/client';

const router = useRouter();
const session = useSessionStore();

const inputId = ref('');
const inputPassword = ref('');
const isLoading = ref(false);
const errorText = ref('');

const resetModalOpen = ref(false);
const resetUserId = ref('');
const resetEmail = ref('');
const resetCode = ref('');
const resetNewPassword = ref('');
const resetCodeCooldown = ref(0);
const resetLoading = ref(false);
const resetError = ref('');
const resetStatus = ref('');

const showNewDeviceStep = ref(false);
const newDeviceCode = ref('');
const newDeviceLoading = ref(false);
const newDeviceError = ref('');
const loginIdRef = ref('');
const loginPwdRef = ref('');
/** 新设备登录时后端下发的临时 token，仅用于发验证码/校验验证码，校验通过后再换 JWT；不写入 localStorage */
const loginChallengeTokenRef = ref<string | null>(null);

let resetCodeCooldownTimer: ReturnType<typeof setInterval> | null = null;
watch(resetCodeCooldown, (v) => {
  if (v <= 0 && resetCodeCooldownTimer) {
    clearInterval(resetCodeCooldownTimer);
    resetCodeCooldownTimer = null;
  }
});

const LOGIN_TIMEOUT_MS = 10000;

async function handleLogin() {
  const id = inputId.value.trim();
  const pwd = inputPassword.value;
  console.log('[DEBUG] 0. 开始登录流程，校验表单...');
  if (!id) {
    errorText.value = '请输入账号';
    return;
  }
  if (!pwd) {
    errorText.value = '请输入密码';
    return;
  }
  errorText.value = '';
  loginChallengeTokenRef.value = null;
  isLoading.value = true;
  try {
    console.log('[DEBUG] 1. 先检查本地是否有该账号金库（新设备需邮箱验证，老设备直接 JWT）...');
    const vaultV2 = await getKeyBackupV2(id);
    const vaultV1 = vaultV2 ? null : await getEncryptedPrivateKeys(id);
    const hasLocalVault = !!(vaultV2 || vaultV1);
    console.log('[DEBUG] 2. 金库检查完毕，hasLocalVault=', hasLocalVault);

    const res = await apiFetch(
      `${API_BASE}/api/auth/login`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: id, password: pwd, is_new_device: !hasLocalVault })
      },
      LOGIN_TIMEOUT_MS
    );
    const data = await res.json().catch(() => ({})) as {
      token?: string;
      login_challenge_token?: string;
      user_id?: string;
      detail?: string;
    };
    if (!res.ok) {
      const msg = typeof data.detail === 'string' ? data.detail : '登录失败';
      throw new Error(msg);
    }

    if (hasLocalVault) {
      const token = data.token;
      if (!token) throw new Error('服务端未返回 Token');
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('quantum_guard_auth_token', token);
        localStorage.setItem('quantum_guard_my_id', id);
      }
      try {
        if (vaultV2) {
          const mk: Uint8Array | null = await decryptMKWithPassword(vaultV2.mkEncryptedLocal, pwd, id);
          const { kemPrivateKey, dsaPrivateKey } = await decryptAsymWithMK(vaultV2.asymPrivEncrypted, mk);
          zeroBuffer(mk);
          session.setSessionAfterLogin(token, id, kemPrivateKey, dsaPrivateKey);
        } else if (vaultV1) {
          const { kemPrivateKey, dsaPrivateKey } = await decryptPrivateKeys(
            vaultV1.encrypted,
            vaultV1.salt,
            vaultV1.iv,
            pwd
          );
          session.setSessionAfterLogin(token, id, kemPrivateKey, dsaPrivateKey);
        }
        await router.replace('/receiver');
      } catch (e: unknown) {
        session.resetAll();
        if (typeof localStorage !== 'undefined') {
          localStorage.removeItem('quantum_guard_auth_token');
          localStorage.removeItem('quantum_guard_my_id');
        }
        const isCryptoFailure =
          e instanceof Error &&
          (e?.name === 'OperationError' || (e instanceof Error && (e.message?.includes('decrypt') || e.message?.includes('password'))));
        errorText.value = isCryptoFailure ? '本地凭证解密失败，密码错误' : (e instanceof Error ? e.message : '解密失败');
        alert(errorText.value || '网络或系统错误');
      }
      return;
    }

    if (data.token) {
      const token = data.token;
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('quantum_guard_auth_token', token);
        localStorage.setItem('quantum_guard_my_id', id);
      }
      try {
        const keyRes = await apiFetch(`${API_BASE}/api/auth/me/key-backup`, {
          method: 'GET',
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!keyRes.ok) {
          const d = await keyRes.json().catch(() => ({})) as { detail?: string };
          throw new Error(typeof d.detail === 'string' ? d.detail : '拉取密钥备份失败');
        }
        const keyBackup = await keyRes.json() as {
          password_box_salt?: string;
          mk_encrypted_by_password?: string;
          asym_priv_encrypted: string;
        };
        const salt = keyBackup.password_box_salt;
        const mkEnc = keyBackup.mk_encrypted_by_password;
        if (!salt || !mkEnc) throw new Error('该账号无密码盒备份，请使用忘记密码重置');
        const mk = await decryptMKFromPasswordBox(salt, mkEnc, pwd);
        const asymEnc = new Uint8Array(Uint8Array.from(atob(keyBackup.asym_priv_encrypted), c => c.charCodeAt(0)));
        const { kemPrivateKey, dsaPrivateKey } = await decryptAsymWithMK(asymEnc, mk);
        const { blob: mkEncryptedLocal } = await encryptMKWithPassword(mk, pwd, id);
        zeroBuffer(mk);
        await saveKeyBackupV2(id, mkEncryptedLocal, asymEnc);
        session.setSessionAfterLogin(token, id, kemPrivateKey, dsaPrivateKey);
        await router.replace('/receiver');
      } catch (e: unknown) {
        if (typeof localStorage !== 'undefined') {
          localStorage.removeItem('quantum_guard_auth_token');
          localStorage.removeItem('quantum_guard_my_id');
        }
        errorText.value = e instanceof Error ? e.message : '恢复失败';
      }
      return;
    }

    const challengeToken = data.login_challenge_token;
    if (!challengeToken) throw new Error('新设备登录时服务端未返回 login_challenge_token 或 token');
    loginChallengeTokenRef.value = challengeToken;
    try {
      await apiFetch(`${API_BASE}/api/auth/me/send-login-verify-code`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${challengeToken}` }
      });
    } catch (e) {
      loginChallengeTokenRef.value = null;
      errorText.value = e instanceof Error ? e.message : '发送验证码失败，请确认账号已绑定邮箱';
      return;
    }
    loginIdRef.value = id;
    loginPwdRef.value = pwd;
    showNewDeviceStep.value = true;
    newDeviceCode.value = '';
    newDeviceError.value = '';
  } catch (e: unknown) {
    console.error('[DEBUG] 发生致命错误（登录）:', e);
    if (e instanceof Error && e.stack) console.error(e.stack);
    const msg = e instanceof Error ? e.message : '登录失败';
    errorText.value = msg;
    alert(msg || '网络或系统错误');
  } finally {
    isLoading.value = false;
  }
}

async function sendResetCode() {
  const e = resetEmail.value.trim().toLowerCase();
  if (!e || !e.includes('@')) {
    resetError.value = '请填写有效邮箱';
    return;
  }
  if (resetCodeCooldown.value > 0) return;
  resetError.value = '';
  try {
    await ensureOk(
      await apiFetch(`${API_BASE}/api/auth/send-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: e, is_reset: true })
      }),
      '发送验证码'
    );
    resetCodeCooldown.value = 60;
    resetCodeCooldownTimer = setInterval(() => {
      resetCodeCooldown.value--;
      if (resetCodeCooldown.value <= 0 && resetCodeCooldownTimer) {
        clearInterval(resetCodeCooldownTimer);
        resetCodeCooldownTimer = null;
      }
    }, 1000);
    resetStatus.value = '验证码已发送，请查收邮件';
  } catch (err: unknown) {
    resetError.value = err instanceof Error ? err.message : '发送验证码失败';
  }
}

async function doResetPassword() {
  resetError.value = '';
  resetStatus.value = '';
  const userId = resetUserId.value.trim();
  const email = resetEmail.value.trim().toLowerCase();
  const code = resetCode.value.trim();
  const newPwd = resetNewPassword.value;

  if (!userId) {
    resetError.value = '请填写账号 (user_id)';
    return;
  }
  if (!email || !email.includes('@')) {
    resetError.value = '请填写绑定邮箱';
    return;
  }
  if (!code || code.length !== 6) {
    resetError.value = '请填写 6 位验证码';
    return;
  }
  if (!newPwd) {
    resetError.value = '请填写新密码';
    return;
  }

  resetLoading.value = true;
  let mk: Uint8Array | null = null;
  try {
    resetStatus.value = '正在生成全新主密钥与 ML-KEM / ML-DSA 密钥对...';
    mk = generateMK();
    const kemPair = await KemEngine.generateKeyPair();
    const dsaPair = DsaEngine.generateKeyPair();
    resetStatus.value = '正在构建密码盒并加密私钥...';
    const { saltB64, mkEncryptedB64 } = await buildPasswordBox(mk, newPwd);
    const asymPrivEncrypted = await encryptAsymWithMK(kemPair.privateKey, dsaPair.privateKey, mk);
    const { blob: mkEncryptedLocal } = await encryptMKWithPassword(mk, newPwd, userId);
    await saveKeyBackupV2(userId, mkEncryptedLocal, asymPrivEncrypted);
    const asymPrivEncryptedBase64 = btoa(String.fromCharCode(...Array.from(asymPrivEncrypted)));
    zeroBuffer(mk);
    mk = null;

    const payload = {
      user_id: userId,
      email,
      code,
      new_password: newPwd,
      new_kem_public_key: bytesToBase64(kemPair.publicKey),
      new_dsa_public_key: bytesToBase64(dsaPair.publicKey),
      password_box_salt: saltB64,
      mk_encrypted_by_password: mkEncryptedB64,
      asym_priv_encrypted: asymPrivEncryptedBase64
    };
    const res = await apiFetch(`${API_BASE}/api/auth/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json().catch(() => ({})) as { user_id?: string; detail?: string };
    if (!res.ok) {
      const msg = typeof data.detail === 'string' ? data.detail : '重置失败';
      throw new Error(msg);
    }
    resetStatus.value = '重置成功，请使用新密码登录';
    resetError.value = '';
    setTimeout(() => {
      resetModalOpen.value = false;
      resetUserId.value = '';
      resetEmail.value = '';
      resetCode.value = '';
      resetNewPassword.value = '';
      resetStatus.value = '';
    }, 1500);
  } catch (e: unknown) {
    resetError.value = e instanceof Error ? e.message : '重置失败';
    resetStatus.value = '';
  } finally {
    if (mk) zeroBuffer(mk);
    resetLoading.value = false;
  }
}

async function confirmNewDeviceAndRestore() {
  const code = newDeviceCode.value.trim();
  const id = loginIdRef.value;
  const pwd = loginPwdRef.value;
  if (!code || code.length !== 6 || !id || !pwd) {
    newDeviceError.value = '请填写 6 位验证码';
    return;
  }
  const challengeToken = loginChallengeTokenRef.value;
  if (!challengeToken) {
    newDeviceError.value = '登录已失效，请重新登录';
    return;
  }
  newDeviceError.value = '';
  newDeviceLoading.value = true;
  try {
    const verifyRes = await apiFetch(`${API_BASE}/api/auth/me/verify-login-code`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${challengeToken}` },
      body: JSON.stringify({ code })
    });
    const verifyData = await verifyRes.json().catch(() => ({})) as { token?: string; detail?: string };
    if (!verifyRes.ok) {
      throw new Error(typeof verifyData.detail === 'string' ? verifyData.detail : '验证码错误或已过期');
    }
    const token = verifyData.token;
    if (!token) throw new Error('服务端未返回 JWT');
    loginChallengeTokenRef.value = null;
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('quantum_guard_auth_token', token);
      localStorage.setItem('quantum_guard_my_id', id);
    }
    const keyRes = await apiFetch(`${API_BASE}/api/auth/me/key-backup`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!keyRes.ok) {
      const d = await keyRes.json().catch(() => ({})) as { detail?: string };
      throw new Error(typeof d.detail === 'string' ? d.detail : '拉取密钥备份失败');
    }
    const keyBackup = await keyRes.json() as {
      password_box_salt?: string;
      mk_encrypted_by_password?: string;
      asym_priv_encrypted: string;
    };
    const salt = keyBackup.password_box_salt;
    const mkEnc = keyBackup.mk_encrypted_by_password;
    if (!salt || !mkEnc) {
      throw new Error('该账号无密码盒备份，请使用忘记密码重置');
    }
    const mk = await decryptMKFromPasswordBox(salt, mkEnc, pwd);
    const asymEnc = new Uint8Array(Uint8Array.from(atob(keyBackup.asym_priv_encrypted), c => c.charCodeAt(0)));
    const { kemPrivateKey, dsaPrivateKey } = await decryptAsymWithMK(asymEnc, mk);
    const { blob: mkEncryptedLocal } = await encryptMKWithPassword(mk, pwd, id);
    zeroBuffer(mk);
    await saveKeyBackupV2(id, mkEncryptedLocal, asymEnc);
    session.setSessionAfterLogin(token, id, kemPrivateKey, dsaPrivateKey);
    showNewDeviceStep.value = false;
    loginIdRef.value = '';
    loginPwdRef.value = '';
    newDeviceCode.value = '';
    await router.replace('/receiver');
  } catch (e: unknown) {
    newDeviceError.value = e instanceof Error ? e.message : '恢复失败';
  } finally {
    newDeviceLoading.value = false;
  }
}
</script>

<style scoped>
.login-page {
  position: relative;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  overflow: hidden;
}

.login-bg {
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

.login-bg::before {
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

.login-card {
  position: relative;
  z-index: 1;
  width: 100%;
  max-width: 380px;
  padding: 32px;
  border-radius: 16px;
}

.login-title {
  font-size: 1.5rem;
  font-weight: 700;
  color: #f1f5f9;
  margin: 0 0 8px;
}

.login-hint {
  color: rgba(148, 163, 184, 0.9);
  font-size: 0.9rem;
  margin: 0 0 24px;
  line-height: 1.5;
}

.login-form {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.login-input {
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

.login-input::placeholder {
  color: rgba(148, 163, 184, 0.6);
}

.login-input:focus {
  border-color: rgba(34, 211, 238, 0.7);
  box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.15);
}

.password-wrap {
  width: 100%;
}

.login-btn {
  padding: 14px 24px;
  font-size: 1rem;
  font-weight: 700;
  color: #0a0e17;
  background: linear-gradient(135deg, #22d3ee 0%, #06b6d4 100%);
  border: none;
  border-radius: 10px;
  cursor: pointer;
  transition: transform 0.2s, box-shadow 0.2s;
}

.login-btn:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 0 24px rgba(34, 211, 238, 0.4);
}

.login-btn:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.login-error {
  margin: 12px 0 0;
  color: #f87171;
  font-size: 0.9rem;
}

.login-back {
  display: inline-block;
  margin-top: 20px;
  color: rgba(34, 211, 238, 0.9);
  font-size: 0.9rem;
  text-decoration: none;
  transition: color 0.2s;
}

.login-back:hover {
  color: #22d3ee;
}

.forgot-link {
  background: none;
  border: none;
  color: rgba(148, 163, 184, 0.95);
  font-size: 0.9rem;
  cursor: pointer;
  padding: 0;
  margin: -4px 0 0;
  text-align: left;
}
.forgot-link:hover {
  color: #22d3ee;
  text-decoration: underline;
}

.new-device-panel {
  margin-top: 20px;
  padding: 20px;
  border-radius: 12px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.new-device-hint {
  margin: 0;
  color: rgba(226, 232, 240, 0.95);
  font-size: 0.95rem;
}
.new-device-panel .code-row {
  display: flex;
  gap: 12px;
  align-items: center;
}
.new-device-panel .code-input {
  flex: 1;
  min-width: 0;
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
  backdrop-filter: blur(4px);
}
.reset-modal {
  width: 100%;
  max-width: 400px;
  padding: 24px;
  border-radius: 16px;
  border: 1px solid rgba(34, 211, 238, 0.25);
}
.reset-title {
  font-size: 1.25rem;
  font-weight: 700;
  color: #f1f5f9;
  margin: 0 0 8px;
}
.reset-option {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
  color: rgba(148, 163, 184, 0.95);
  font-size: 0.9rem;
  cursor: pointer;
}
.reset-option input { margin: 0; }
.reset-hint {
  color: rgba(148, 163, 184, 0.95);
  font-size: 0.85rem;
  margin: 0 0 20px;
  line-height: 1.5;
}
.reset-form {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.reset-form .code-row {
  display: flex;
  gap: 8px;
}
.reset-form .code-input {
  flex: 1;
}
.recovery-textarea {
  resize: vertical;
  min-height: 64px;
  font-family: ui-monospace, monospace;
}
.reset-form .secondary-btn {
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
.reset-form .secondary-btn:hover:not(:disabled) {
  background: rgba(34, 211, 238, 0.25);
}
.reset-form .secondary-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
.reset-error {
  color: #f87171;
  font-size: 0.9rem;
  margin: 0;
}
.reset-status {
  color: rgba(34, 211, 238, 0.95);
  font-size: 0.9rem;
  margin: 0;
}
.reset-actions {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
  margin-top: 8px;
}
.reset-actions .login-btn {
  flex: 1;
}
</style>
