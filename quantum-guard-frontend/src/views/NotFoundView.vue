<template>
  <main class="not-found">
    <div class="not-found-bg" aria-hidden="true"></div>
    <div class="not-found-content">
      <h1>404</h1>
      <p>页面不存在或已被移动。</p>
      <div class="actions">
        <RouterLink to="/" class="btn">返回首页</RouterLink>
        <RouterLink to="/receiver" class="btn secondary">接收舱</RouterLink>
        <RouterLink to="/sender" class="btn secondary">发送舱</RouterLink>
      </div>
    </div>
  </main>
</template>

<script setup lang="ts">
import { RouterLink } from 'vue-router';
</script>

<style scoped>
.not-found {
  position: relative;
  min-height: 70vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
}

.not-found-bg {
  position: absolute;
  inset: 0;
  background: radial-gradient(
    ellipse 60% 50% at 50% 50%,
    rgba(34, 211, 238, 0.04) 0%,
    transparent 60%
  );
}

.not-found-content {
  position: relative;
  z-index: 1;
  text-align: center;
}

h1 {
  margin: 0;
  font-size: 56px;
  line-height: 1;
  color: #e2e8f0;
  text-shadow: 0 0 30px rgba(34, 211, 238, 0.2);
}

p {
  margin: 0 0 20px;
  color: #94a3b8;
}

.actions {
  display: flex;
  gap: 12px;
  justify-content: center;
  flex-wrap: wrap;
}

.btn {
  padding: 10px 18px;
  border-radius: 10px;
  text-decoration: none;
  font-weight: 600;
  transition: all 0.2s;
  border: 1px solid rgba(34, 211, 238, 0.4);
  background: rgba(34, 211, 238, 0.15);
  color: #22d3ee;
}

.btn:hover {
  background: rgba(34, 211, 238, 0.25);
  box-shadow: 0 0 20px rgba(34, 211, 238, 0.2);
  transform: translateY(-1px);
}

.btn.secondary {
  border-color: rgba(148, 163, 184, 0.4);
  background: rgba(148, 163, 184, 0.1);
  color: #94a3b8;
}

.btn.secondary:hover {
  background: rgba(148, 163, 184, 0.2);
  color: #e2e8f0;
}
</style>
