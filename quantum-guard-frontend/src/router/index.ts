import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router';
import { getAuthToken } from '../api/client';

// 路由组件懒加载，减小首屏包体积
const LandingView = () => import('../views/LandingView.vue');
const LoginView = () => import('../views/LoginView.vue');
const RegisterView = () => import('../views/RegisterView.vue');
const SenderView = () => import('../views/SenderView.vue');
const ReceiverView = () => import('../views/ReceiverView.vue');
const NotFoundView = () => import('../views/NotFoundView.vue');

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'landing',
    component: LandingView,
    meta: { title: 'QuantumGuard - 零信任加密' }
  },
  {
    path: '/login',
    name: 'login',
    component: LoginView,
    meta: { title: '登录 - QuantumGuard' }
  },
  {
    path: '/register',
    name: 'register',
    component: RegisterView,
    meta: { title: '注册 - QuantumGuard' }
  },
  {
    path: '/receiver',
    name: 'receiver',
    component: ReceiverView,
    meta: { title: '接收方 - QuantumGuard' }
  },
  {
    path: '/sender',
    name: 'sender',
    component: SenderView,
    meta: { title: '发送方 - QuantumGuard' }
  },
  {
    // 未匹配路径统一进入 404，避免白屏
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: NotFoundView,
    meta: { title: '404 - QuantumGuard' }
  }
];

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
  scrollBehavior() {
    return { top: 0 };
  }
});

// 访问 /receiver、/sender 前校验 token，缺失则重定向至登录；使用 return 式守卫避免 next 导致的挂起
router.beforeEach((to, _from) => {
  const needAuth = to.path === '/receiver' || to.path === '/sender';
  if (needAuth) {
    const token = getAuthToken();
    if (!token || !token.trim()) return '/login';
  }
  return true;
});

// 路由切换时根据 meta.title 更新 document.title
router.afterEach((to) => {
  const title = (to.meta.title as string | undefined) ?? 'QuantumGuard';
  document.title = title;
});

export default router;
