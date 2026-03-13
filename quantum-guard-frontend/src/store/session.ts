/**
 * 全局安全会话状态（Pinia）。目标方公钥与 TOFU 核验状态不持久化；切换接收方时清空并需重新执行指纹核验。
 * 存入的公钥均经克隆，避免外部持有引用导致的数据污染。
 */
import { defineStore } from 'pinia';
import { computed, ref } from 'vue';

const MLKEM768_PUBLIC_KEY_BYTES = 1184;

function normalizeUserId(id: string): string {
  return (id ?? '').trim();
}

function normalizeFingerprint(fp: string): string {
  return (fp ?? '').trim();
}

function cloneBytes(input: Uint8Array): Uint8Array {
  const out = new Uint8Array(input.byteLength);
  out.set(input);
  return out;
}

function assertValidPublicKey(pubKey: Uint8Array): void {
  if (!(pubKey instanceof Uint8Array)) {
    throw new Error('target publicKey 必须是 Uint8Array');
  }
  if (pubKey.byteLength !== MLKEM768_PUBLIC_KEY_BYTES) {
    throw new Error(
      `target publicKey 长度非法: ${pubKey.byteLength}，期望 ${MLKEM768_PUBLIC_KEY_BYTES}`
    );
  }
}

const AUTH_TOKEN_KEY = 'quantum_guard_auth_token';

export const useSessionStore = defineStore('session', () => {
  const currentUserId = ref<string>('');
  const authToken = ref<string>('');
  const kemPrivateKey = ref<Uint8Array | null>(null);
  const dsaPrivateKey = ref<Uint8Array | null>(null);

  const targetUserId = ref<string>('');
  const targetPublicKey = ref<Uint8Array | null>(null);
  const targetFingerprint = ref<string>('');
  const isTofuVerified = ref<boolean>(false);

  // authToken 会同步写入 localStorage 供后端鉴权；解密后私钥仅存内存；isTofuVerified 表示是否已完成指纹核验
  const hasTarget = computed(() => {
    return (
      targetUserId.value.length > 0 &&
      !!targetPublicKey.value &&
      targetFingerprint.value.length > 0
    );
  });

  const canSendSecureFile = computed(() => {
    return (
      currentUserId.value.length > 0 &&
      hasTarget.value &&
      isTofuVerified.value
    );
  });

  /** 设置当前登录用户标识。 */
  function setCurrentUser(id: string) {
    currentUserId.value = normalizeUserId(id);
  }

  /** 登录成功后写入：token、userId 及解密后的双私钥；token 同时持久化至 localStorage。 */
  function setSessionAfterLogin(
    token: string,
    userId: string,
    kemPriv: Uint8Array,
    dsaPriv: Uint8Array
  ) {
    currentUserId.value = normalizeUserId(userId);
    authToken.value = token;
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(AUTH_TOKEN_KEY, token);
      localStorage.setItem('quantum_guard_my_id', userId);
    }
    kemPrivateKey.value = cloneBytes(kemPriv);
    dsaPrivateKey.value = cloneBytes(dsaPriv);
  }

  /** 当前会话是否已持有解密后的私钥（即金库已成功解密）。 */
  const hasInMemoryPrivateKeys = computed(
    () => !!kemPrivateKey.value && !!dsaPrivateKey.value && currentUserId.value.length > 0
  );

  /** 设置发送目标：写入目标 userId、公钥（克隆）与指纹；切换目标时重置 TOFU 状态，需重新核验。 */
  function setTarget(id: string, pubKey: Uint8Array, fingerprint: string) {
    const cleanId = normalizeUserId(id);
    const cleanFp = normalizeFingerprint(fingerprint);

    if (!cleanId) {
      throw new Error('targetUserId 不能为空');
    }
    if (!cleanFp) {
      throw new Error('targetFingerprint 不能为空');
    }

    assertValidPublicKey(pubKey);

    targetUserId.value = cleanId;
    targetPublicKey.value = cloneBytes(pubKey);
    targetFingerprint.value = cleanFp;
    isTofuVerified.value = false;
  }

  /** 仅更新目标指纹（如公钥刷新后）；指纹变更时 TOFU 状态失效，须重新确认。 */
  function updateTargetFingerprint(fingerprint: string) {
    const cleanFp = normalizeFingerprint(fingerprint);
    if (!cleanFp) {
      throw new Error('targetFingerprint 不能为空');
    }

    if (targetFingerprint.value !== cleanFp) {
      targetFingerprint.value = cleanFp;
      isTofuVerified.value = false;
    }
  }

  /** 用户完成带外指纹核验后调用，将 TOFU 状态置为已通过。 */
  function verifyTofu() {
    if (!hasTarget.value) {
      throw new Error('目标会话信息不完整，无法确认 TOFU');
    }
    isTofuVerified.value = true;
  }

  /** 销毁目标会话：清空目标 userId、公钥与 TOFU 状态；不影响 currentUserId。 */
  function destroySession() {
    targetUserId.value = '';
    targetPublicKey.value = null;
    targetFingerprint.value = '';
    isTofuVerified.value = false;
  }

  /** 登出时调用：清除 token、内存中的私钥及 localStorage 中的认证数据。 */
  function resetAll() {
    currentUserId.value = '';
    authToken.value = '';
    kemPrivateKey.value = null;
    dsaPrivateKey.value = null;
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem(AUTH_TOKEN_KEY);
    }
    destroySession();
  }

  /** 从 localStorage 恢复 token 与 userId 至 Pinia；私钥不恢复，须重新登录解密金库。 */
  function restoreTokenFromStorage() {
    if (typeof localStorage === 'undefined') return;
    const t = localStorage.getItem(AUTH_TOKEN_KEY);
    const id = localStorage.getItem('quantum_guard_my_id');
    if (t) authToken.value = t;
    if (id) currentUserId.value = id.trim();
  }

  return {
    // state
    currentUserId,
    authToken,
    kemPrivateKey,
    dsaPrivateKey,
    targetUserId,
    targetPublicKey,
    targetFingerprint,
    isTofuVerified,

    // getters
    hasTarget,
    canSendSecureFile,
    hasInMemoryPrivateKeys,

    // actions
    setCurrentUser,
    setSessionAfterLogin,
    setTarget,
    updateTargetFingerprint,
    verifyTofu,
    destroySession,
    resetAll,
    restoreTokenFromStorage
  };
});
