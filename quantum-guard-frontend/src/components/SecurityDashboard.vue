<template>
  <section class="security-dashboard" aria-label="安全状态面板">
    <article
      v-for="item in items"
      :key="item.label"
      class="status-item"
    >
      <span class="label">{{ item.label }}</span>
      <span class="value" :class="item.className">{{ item.value }}</span>
    </article>
  </section>
</template>

<script setup lang="ts">
type DashboardItem = {
  label: string;
  value: string;
  className: 'standard' | 'encrypt' | 'secure' | 'blind';
};

const items: DashboardItem[] = [
  {
    label: '抗量子标准',
    value: 'FIPS 203/204 (ML-KEM · ML-DSA)',
    className: 'standard'
  },
  {
    label: '对称加密',
    value: 'AES-256-GCM',
    className: 'encrypt'
  },
  {
    label: '分块 AAD 防篡改',
    value: '🛡️ 已启用',
    className: 'secure'
  },
  {
    label: '服务器零知识',
    value: '密文不可解密',
    className: 'blind'
  }
];
</script>

<style scoped>
.security-dashboard {
  display: grid;
  grid-template-columns: repeat(4, minmax(180px, 1fr));
  gap: 12px;
  background: rgba(15, 23, 42, 0.5);
  backdrop-filter: blur(12px);
  padding: 15px;
  border-radius: 12px;
  margin-bottom: 25px;
  border: 1px solid rgba(34, 211, 238, 0.2);
  box-shadow: 0 0 30px rgba(34, 211, 238, 0.05), inset 0 1px 0 rgba(255, 255, 255, 0.04);
}

.status-item {
  min-height: 82px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  gap: 6px;
  text-align: center;
  border-radius: 8px;
  background: rgba(34, 211, 238, 0.03);
  padding: 8px;
  border: 1px solid rgba(34, 211, 238, 0.08);
}

.label {
  font-size: 0.72rem;
  color: #94a3b8;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  line-height: 1.3;
}

.value {
  font-weight: 700;
  font-family: 'Courier New', ui-monospace, monospace;
  font-size: 0.93rem;
  line-height: 1.35;
  word-break: break-word;
}

.standard {
  color: #22d3ee;
}
.encrypt {
  color: #fbbf24;
}
.secure {
  color: #34d399;
}
.blind {
  color: #a78bfa;
}

/* 平板 */
@media (max-width: 1024px) {
  .security-dashboard {
    grid-template-columns: repeat(2, minmax(160px, 1fr));
  }
}

/* 手机 */
@media (max-width: 640px) {
  .security-dashboard {
    grid-template-columns: 1fr;
    padding: 12px;
  }

  .status-item {
    min-height: 70px;
  }

  .label {
    font-size: 0.68rem;
  }

  .value {
    font-size: 0.88rem;
  }
}
</style>
