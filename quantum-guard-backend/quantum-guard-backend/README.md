# QuantumGuard 后端

QuantumGuard 的服务端实现：基于 **FastAPI + SQLite**，提供认证、公钥与密钥备份、以及加密文件分块存储。设计为**零信任存储节点**：不生成、不持有明文密钥，不参与对称密钥派生与文件加解密，不参与 KEM 解封或 DSA 验签。

项目总览与整体架构见前端仓库 [PROJECT_OVERVIEW.md](https://github.com/.../PROJECT_OVERVIEW.md)（或本仓库同级的总体文档）。

---

## 1. 快速开始

### 1.1 环境与依赖

```bash
pip install -r requirements.txt
```

主要依赖：`fastapi`、`uvicorn`、`SQLAlchemy`、`python-multipart`、`bcrypt`、`pyjwt`、`python-dotenv`。

### 1.2 运行

```bash
# 开发
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 生产示例
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

- **健康检查**：`GET /healthz` 返回 `{"status":"ok"}`。
- **环境变量**：启动时从项目根目录加载 `.env`（`load_dotenv()`），可配置 JWT、CORS、SMTP 等。

---

## 2. 数据模型

### 2.1 用户与密钥表 `user_public_keys`

| 字段 | 说明 |
|------|------|
| `user_id` | 主键 |
| `kem_public_key` / `dsa_public_key` | ML-KEM / ML-DSA 公钥（仅用于加密与验签） |
| `hashed_password` | bcrypt 哈希；入库前经密码规范化（见 §4.1） |
| `email` | 可选，唯一；用于新设备风控与忘记密码 |
| `password_box_salt` / `mk_encrypted_by_password` | 密码盒，由客户端计算；服务端视为不透明 |
| `asym_priv_encrypted` | MK 加密的 KEM/DSA 私钥包密文 |
| `recovery_blob` / `mk_encrypted_cloud` | 历史字段，破产重组后清空 |

### 2.2 文件元数据表 `file_metadata`

| 字段 | 说明 |
|------|------|
| `file_id` | 主键；白名单 `[A-Za-z0-9._-]{8,128}` |
| `sender_id` / `receiver_id` | 发送方 / 接收方 user_id |
| `total_chunks` / `storage_path` | 分块数；密文块目录路径 |
| `global_signature` | 兼容字段；优先使用 `kem_ciphertext` |
| `kem_ciphertext` / `sender_signature` | KEM 密文；可选 DSA 签名 |
| `file_name` / `file_size` | 可选 |

密文块存储在 `data/encrypted_files/<file_id>/0`、`1`、…；数据库文件默认 `data/quantum_guard.db`。

---

## 3. 认证与风控

### 3.1 密码规范化

超长密码在 bcrypt 前统一处理，与前端 KDF 一致：

```python
def _normalize_password_bytes(password: str) -> bytes:
    raw = password.encode("utf-8")
    if len(raw) > 64:
        return hashlib.sha256(raw).digest()
    return raw
```

避免截断导致“登录成功但客户端解不开密码盒”。

### 3.2 注册与登录

| 接口 | 说明 |
|------|------|
| `POST /api/auth/send-code` | Body：`email`，可选 `is_reset`。发送 6 位验证码；同一邮箱 60 秒限发一次 |
| `POST /api/auth/register` | Body：`user_id`、`password`、公钥、可选 `email`/`code`；可选密码盒与私钥包密文。提供 email 时须提供 code 并校验 |
| `POST /api/auth/login` | Body：`user_id`、`password`，可选 `is_new_device`。已绑定邮箱且新设备时仅返回 `login_challenge_token`；否则返回 JWT。15 分钟内同一 user_id 失败超 5 次返回 429 |

### 3.3 新设备与 JWT

| 接口 | 鉴权 | 说明 |
|------|------|------|
| `POST /api/auth/me/send-login-verify-code` | JWT 或 `login_challenge_token` | 向当前用户绑定邮箱发验证码 |
| `POST /api/auth/me/verify-login-code` | 同上 | Body：`code`。通过后响应返回 JWT，并消费 challenge token |
| `GET /api/auth/me` | JWT | 返回 `user_id`、`email_masked` |
| `GET /api/auth/me/key-backup` | JWT | 返回密码盒与私钥包密文；无则 404 |
| `POST /api/auth/me/send-bind-email-code` | JWT | Body：`email`。发送绑定/修改邮箱验证码 |
| `POST /api/auth/me/confirm-bind-email` | JWT | Body：`email`、`code`。确认绑定或修改邮箱 |

### 3.4 修改密码与忘记密码

| 接口 | 说明 |
|------|------|
| `POST /api/auth/send-code-change-password` | JWT；向当前用户绑定邮箱发验证码 |
| `POST /api/auth/change-password` | Body：`code`、`new_password`。校验验证码后仅更新 `hashed_password` |
| `POST /api/auth/forgot-password-verify` | Body：`email`、`code`。通过后返回 `recovery_token`、`user_id` |
| `POST /api/auth/reset-password` | Body：`user_id`、`email`、`code`、`new_password`、新公钥、**password_box_salt**、**mk_encrypted_by_password**、**asym_priv_encrypted**。校验后**覆盖**密码盒与私钥包，更新哈希与公钥，清空旧版恢复字段 |

忘记密码时采用**覆盖**而非清空，避免账号在新设备上无法恢复（“绝户”）。

---

## 4. 公钥与文件接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/keys/upload` | Body：`user_id`、`kem_public_key`、`dsa_public_key`。不存在则创建，存在则覆盖 |
| GET | `/keys/{user_id}` | 返回该用户公钥；不存在 404 |
| POST | `/files/upload_chunk` | Form：`file_id`、`chunk_index`、`file`（密文块）。单块上限 20MB 明文 + AEAD 开销 |
| POST | `/files/finalize` | Form：`file_id`、`sender_id`、`receiver_id`、`total_chunks`、`global_signature`，可选 `kem_ciphertext`、`sender_signature`、`file_name`、`file_size` |
| GET | `/files/list/{receiver_id}` | JWT；仅当当前用户为 receiver_id 时可访问；分页 `page`、`size` |
| GET | `/files/sent` | JWT；当前用户为发送方的列表；分页 |
| GET | `/files/download/{file_id}/chunk/{chunk_index}` | JWT；仅接收方可下载对应块 |
| GET | `/api/transfer/download/{file_id}/meta` | JWT；仅接收方；返回元数据，`kem_ciphertext` 优先于 `global_signature` |

---

## 5. 环境变量

| 变量 | 说明 |
|------|------|
| `ENV` / `PRODUCTION` | 设为 production 或 1 时，不向客户端暴露未捕获异常详情，并禁止占位 JWT |
| `JWT_SECRET` | JWT 签名密钥；**生产必须设置** |
| `CORS_ORIGINS` | 允许的源，逗号分隔；未设置时 CORS 为 `*` 且 credentials=False |
| `SMTP_HOST` | 默认 `smtp.qq.com` |
| `SMTP_PORT` | 默认 `465` |
| `SMTP_USER` | 发验证码的邮箱（发件人账号） |
| `SMTP_PASSWORD` | SMTP 授权码（如 QQ 邮箱授权码） |
| `SMTP_FROM` | 发件人地址；未设置时使用 `SMTP_USER` |

---

## 6. 邮件与部署

- 发件人由 `SMTP_FROM` 或 `SMTP_USER` 决定；收件人为各接口传入的 `to_email`（用户安全邮箱）。
- **阿里云 / 服务器**：在项目根目录放置 `.env`，或通过 systemd 的 `EnvironmentFile`、云平台环境变量注入；确保进程工作目录为项目根以便 `load_dotenv()` 生效。
- **清空数据**：`python scripts/clear_all_data.py`（需先停止服务），将清空用户表、文件元数据及 `data/encrypted_files/` 下内容。

---

## 7. 目录结构

```
app/
├── main.py              # FastAPI 应用、CORS、生命周期、路由挂载
├── database.py          # SQLite 引擎与会话
├── models.py            # UserPublicKey、FileMetadata
├── routers/
│   ├── auth.py          # 认证、风控、密钥备份、绑定邮箱
│   ├── key_exchange.py  # 公钥上传与查询
│   ├── file_transfer.py # 分块上传、finalize、下载块、列表
│   └── transfer.py      # 可选 transfer 风格接口
└── utils/
    └── email_sender.py  # SMTP 发信
data/                    # 数据库与密文块目录
scripts/
tests/
```

---

## 8. 与前端约定摘要

- **注册**：提交 password_box_salt、mk_encrypted_by_password、asym_priv_encrypted 及账号、公钥；邮箱与验证码可选（提供则校验后写入）。
- **新设备登录**：前端以 `is_new_device: true` 登录；若返回 `login_challenge_token`，则用该 token 调用 send-login-verify-code 与 verify-login-code，从响应取得 JWT 后再调用 key-backup。
- **忘记密码**：前端提交新公钥及新密码盒三字段；后端在验证邮箱与验证码后**覆盖**上述字段。
- **认证**：除 register、login、send-code、forgot-password-verify、reset-password、key-backup-by-recovery-token、reset-password-by-recovery 外，均需 `Authorization: Bearer <token>`；send-login-verify-code 与 verify-login-code 还接受 `login_challenge_token`。

接口或模型变更时，请同步更新本文档与前端 README。
