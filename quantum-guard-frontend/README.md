# QuantumGuard 前端与 Tauri 桌面端

QuantumGuard 的客户端实现：Web 应用（Vue 3 + TypeScript + Vite）与可选桌面端（Tauri 2 + Rust）。负责端到端加密文件传输中的密钥生成、密码盒与本地金库、KEM/DSA 加解密及大文件流式处理。

项目总览与整体架构见 [PROJECT_OVERVIEW.md](./PROJECT_OVERVIEW.md)。

---

## 1. 快速开始

### 1.1 环境要求

- **Node.js**：`^20.19.0` 或 `>=22.12.0`（见 `package.json` engines）
- **Rust**（仅 Tauri 桌面端）：[rustup](https://rustup.rs/) 安装的稳定版 toolchain

### 1.2 安装与运行

```bash
# 安装依赖
npm install

# Web 开发（默认 http://localhost:5173）
npm run dev

# Tauri 桌面开发（需已安装 Rust）
npm run tauri dev

# 生产构建（含 TypeScript 类型检查）
npm run build
```

### 1.3 配置

| 项 | 说明 |
|----|------|
| **API 基地址** | 环境变量 `VITE_API_BASE_URL`，默认指向线上；代码中会将 `localhost` 替换为 `127.0.0.1` 以避免部分环境下的 IPv6 解析问题 |
| **请求与鉴权** | 所有业务请求经 `src/api/client.ts` 的 `apiFetch` 发起，自动附加 `Authorization: Bearer <token>`，收到 401 时触发全局登出 |

---

## 2. 项目结构

```
├── src/
│   ├── api/           # 请求封装、JWT、401 处理
│   ├── components/    # 通用组件（如 FileDownloader、SecurityDashboard）
│   ├── core/          # 密码学与密钥：KEM、DSA、HKDF、AES-GCM、密码盒、金库
│   ├── services/      # 上传/下载业务：uploadService、downloadService
│   ├── store/         # Pinia 会话与状态
│   ├── utils/         # 工具（Tauri 检测、保存文件等）
│   ├── views/         # 页面：Landing、Register、Login、Sender、Receiver
│   ├── App.vue
│   └── main.ts
├── src-tauri/         # Tauri 2 桌面端（Rust）
│   └── src/
│       └── lib.rs     # PBKDF2、流式写盘、stream_decrypt_batch 等
├── docs/
│   └── LARGE_FILE_CRYPTO_FLOW.md   # 大文件加解密流程说明
├── PROJECT_OVERVIEW.md
└── README.md          # 本文件
```

---

## 3. 核心模块

### 3.1 密码学与密钥（`src/core/`）

| 模块 | 职责 |
|------|------|
| **cryptoEngine.ts** | KEM 封装、HKDF 派生会话密钥、`deriveAesKeyFromSharedSecretAndFileId` |
| **crypto-stream.ts** | 5MB 分块、AES-GCM 加解密、AAD 绑定 fileId+chunkIndex，兼容旧版 AAD |
| **masterKey.ts** | 密码规范化、密码盒构建（PBKDF2 + AES-GCM）、本地金库加解密 |
| **kem-engine.ts** | ML-KEM-768 封装/解封 |
| **dsa-engine.ts** | ML-DSA-65 签名/验签 |
| **secure-sandbox.ts** | IndexedDB 金库（v1/v2）、`saveKeyBackupV2` / `getKeyBackupV2` |
| **key-storage.ts** | 公钥拉取与缓存、私钥引用 |

密码规范化与后端一致：UTF-8 长度 ≤64 字节用原字节，>64 字节用 SHA-256 摘要，避免“登录成功但解不开密码盒”。

### 3.2 业务服务（`src/services/`）

| 服务 | 职责 |
|------|------|
| **uploadService.ts** | 拉取接收方公钥、生成加密套件、5MB 分块、流式 SHA-256、3 路并发上传、DSA 签名、finalize |
| **downloadService.ts** | 元数据拉取、KEM 解封、HKDF 派生 AES、按块拉取与解密；浏览器/Tauri 双路径写盘 |

### 3.3 大文件解密（Tauri、浏览器与 Android）

- **Tauri 桌面**：`FileDownloader.vue` 单次调用 `invoke('stream_decrypt_batch', {...})`；Rust 内 3 路并发拉取、解密并顺序写盘，可选文件预分配；前端监听 `decrypt-progress` 更新进度。详见 `docs/LARGE_FILE_CRYPTO_FLOW.md`。
- **浏览器**：`showSaveFilePicker` 或 StreamSaver 取得 `WritableStream`，3 路并发拉取+解密，单写循环按块号顺序写盘，乱序块暂存于 `pending` Map，避免全量进内存。
- **Android（Content URI）**：当用户选择的保存路径为 `content://` 时，不调用 Rust 写盘；使用 `@tauri-apps/plugin-fs` 的 `writeFile(path, ReadableStream)`，在 JS 侧按块拉取并解密后推入 `ReadableStream`，由插件写入用户所选目录。

---

## 4. Tauri 与 Rust 侧

### 4.1 命令一览

| 命令 | 说明 |
|------|------|
| `derive_key_pbkdf2` | PBKDF2-HMAC-SHA256 派生密钥，用于密码盒与金库，减轻主线程负担 |
| `stream_save_open` / `stream_save_write_chunk` / `stream_save_end` | 流式写盘（明文块） |
| `stream_decrypt_batch` | **推荐**：单次调用，Rust 内 3 路拉取+解密+顺序写盘，emit `decrypt-progress` |
| `stream_decrypt_open` / `stream_decrypt_fetch_and_flush` / `stream_decrypt_end` | 兼容旧版逐块解密落盘 |

### 4.2 依赖（Cargo）

- `aes-gcm`、`sha2`、`pbkdf2`：解密与 KDF
- `reqwest`（rustls）：Rust 侧 HTTP 拉取密文块
- `tokio`（sync, rt-multi-thread）：并发与 channel

---

## 5. 脚本与质量

| 命令 | 说明 |
|------|------|
| `npm run dev` | Vite 开发服务器 |
| `npm run build` | 类型检查 + 生产构建 |
| `npm run tauri dev` | Tauri 桌面开发 |
| `npm run tauri build` | Tauri 桌面生产构建 |
| `npm run type-check` | 仅运行 `vue-tsc --build` |
| `npm run lint` | ESLint + oxlint |
| `npm run format` | Prettier 格式化 `src/` |

---

## 6. 安全注意事项

- 明文密钥（MK、KEM/DSA 私钥）仅存在于前端内存与会话状态，登出或 401 时清空并同步清理 localStorage 中的 JWT。
- IndexedDB 中仅存加密后的金库与指纹，不存明文私钥。
- 大文件上传采用流式哈希与分块加密，不将整文件加载进内存；下载采用流式写盘或 Rust 侧流水线，避免浏览器 OOM。

---

## 7. 相关文档

- [PROJECT_OVERVIEW.md](./PROJECT_OVERVIEW.md) — 项目架构与安全模型
- [docs/LARGE_FILE_CRYPTO_FLOW.md](./docs/LARGE_FILE_CRYPTO_FLOW.md) — 大文件加密与解密流程
- 后端接口与约定 — 见后端仓库 `README.md`
