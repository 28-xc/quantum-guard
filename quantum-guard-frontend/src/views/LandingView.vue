<template>
  <div class="landing">
    <div class="landing-bg" aria-hidden="true"></div>
    <div class="landing-content">
      <h1 class="landing-title">
        <span class="title-icon">🛡️</span>
        QuantumGuard
      </h1>
      <p class="landing-subtitle">零信任 · 抗量子端到端加密</p>
      <p class="landing-desc">NIST FIPS 203 (ML-KEM) 级安全传输沙盘</p>
      <div class="landing-actions">
        <RouterLink to="/register" class="landing-btn register">
          <span class="btn-icon">✨</span>
          注册
        </RouterLink>
        <RouterLink to="/login" class="landing-btn login">
          <span class="btn-icon">🔐</span>
          登录
        </RouterLink>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue';
import { RouterLink } from 'vue-router';
import { useSessionStore } from '../store/session';

const session = useSessionStore();

onMounted(() => {
  session.resetAll();
});
</script>

<style scoped>
.landing {
  position: relative;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  overflow: hidden;
}

.landing-bg {
  position: absolute;
  inset: 0;
  background: linear-gradient(
    135deg,
    #0a0e17 0%,
    #0d1321 25%,
    #0f1729 50%,
    #0a0e17 75%,
    #0d1321 100%
  );
  background-size: 400% 400%;
  animation: gradient-shift 12s ease infinite;
}

.landing-bg::before {
  content: '';
  position: absolute;
  inset: 0;
  background: radial-gradient(
    ellipse 80% 50% at 50% 0%,
    rgba(34, 211, 238, 0.08) 0%,
    transparent 50%
  );
  pointer-events: none;
}

.landing-bg::after {
  content: '';
  position: absolute;
  inset: 0;
  background: radial-gradient(
    ellipse 60% 40% at 80% 80%,
    rgba(139, 92, 246, 0.06) 0%,
    transparent 50%
  );
  pointer-events: none;
}

@keyframes gradient-shift {
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
}

.landing-content {
  position: relative;
  z-index: 1;
  text-align: center;
  max-width: 420px;
}

.landing-title {
  font-size: clamp(2rem, 6vw, 3rem);
  font-weight: 800;
  color: #fff;
  margin: 0 0 8px;
  letter-spacing: 0.02em;
  text-shadow: 0 0 40px rgba(34, 211, 238, 0.3);
}

.title-icon {
  display: inline-block;
  margin-right: 8px;
}

.landing-subtitle {
  color: rgba(34, 211, 238, 0.95);
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0 0 4px;
  letter-spacing: 0.15em;
}

.landing-desc {
  color: rgba(148, 163, 184, 0.9);
  font-size: 0.9rem;
  margin: 0 0 40px;
}

.landing-actions {
  display: flex;
  gap: 16px;
  justify-content: center;
  flex-wrap: wrap;
}

.landing-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 16px 32px;
  font-size: 1.1rem;
  font-weight: 700;
  border-radius: 12px;
  text-decoration: none;
  transition: transform 0.2s, box-shadow 0.2s;
  min-width: 140px;
  justify-content: center;
}

.landing-btn.register {
  background: linear-gradient(135deg, #22d3ee 0%, #06b6d4 100%);
  color: #0a0e17;
  border: none;
  box-shadow: 0 0 24px rgba(34, 211, 238, 0.4);
}

.landing-btn.register:hover {
  transform: translateY(-2px);
  box-shadow: 0 0 32px rgba(34, 211, 238, 0.5);
}

.landing-btn.login {
  background: rgba(255, 255, 255, 0.06);
  color: #e2e8f0;
  border: 2px solid rgba(34, 211, 238, 0.5);
  box-shadow: 0 0 20px rgba(34, 211, 238, 0.15);
}

.landing-btn.login:hover {
  background: rgba(34, 211, 238, 0.1);
  border-color: rgba(34, 211, 238, 0.8);
  transform: translateY(-2px);
  box-shadow: 0 0 28px rgba(34, 211, 238, 0.25);
}

.btn-icon {
  font-size: 1.2em;
}
</style>
