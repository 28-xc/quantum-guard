import { createApp } from 'vue';
import { createPinia, getActivePinia } from 'pinia';

import App from './App.vue';
import router from './router';
import { setOnUnauthorized } from './api/client';
import { useSessionStore } from './store/session';

async function bootstrap() {
  const app = createApp(App);

  const pinia = createPinia();
  app.use(pinia);
  app.use(router);

  setOnUnauthorized(() => {
    const piniaInstance = getActivePinia();
    if (piniaInstance) useSessionStore(piniaInstance).resetAll();
    router.replace('/login');
  });

  // 等待路由就绪后再挂载，避免首屏闪烁与状态不同步
  await router.isReady();

  app.mount('#app');
}

bootstrap().catch((err) => {
  console.error('🚨 应用启动失败:', err);
});
