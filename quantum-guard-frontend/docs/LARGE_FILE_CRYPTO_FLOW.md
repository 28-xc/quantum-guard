# 大文件加密与解密逻辑（完整版）

本文档描述 QuantumGuard 前端 + 后端在大文件上的**加密上传**与**解密下载**全流程，包括分块大小、密钥派生、AAD、存储格式及两条下载路径（downloadService / FileDownloader）。

---

## 一、约定与常量

| 项目 | 值 | 说明 |
|------|-----|------|
| 分块大小（明文） | 5MB | 前端 `uploadService`、`crypto-stream` 一致；后端上限 20MB，5MB 合规 |
| 单块密文格式 | 12 字节 IV + AES-GCM 密文（含 16 字节 tag） | 上传时拼接为 `IV \|\| ciphertext`，下载时前 12 字节为 IV |
| AAD 格式（标准） | `{fileId}_{chunkIndex}` | 与 upload 的 `UPLOAD_SERVICE_AAD_FORMAT`、解密端 AAD 一致 |
| AAD 格式（旧版兼容） | `{fileId}:chunk:{chunkIndex}` | 解密时若标准 AAD 失败会尝试旧版 |
| 上传并发数 | 3 | `UPLOAD_MAX_CONCURRENCY`，控制同时在飞的分块任务数 |
| Tauri 下载并发数 | 3 | Rust 内 `stream_decrypt_batch` 三路拉取+解密+顺序写盘 |
| 浏览器下载并发数 | 3 | 流式写盘 + 顺序写缓冲，解密一块写一块 |

---

## 二、大文件加密（上传）逻辑

### 2.1 流程概览

1. 拉取接收方 ML-KEM 公钥。
2. 生成加密套件：KEM 封装 → 生成 `fileId` → 用共享秘密 + `fileId` 经 HKDF 派生 AES-256 密钥。
3. 按 5MB 分块：每块「读块 → 流式 SHA-256 更新 → AES-GCM 加密（AAD 绑定 fileId + chunkIndex）→ 上传单块（IV+密文）」。
4. 全部块上传完成后，计算整文件 SHA-256，用发送方 ML-DSA 私钥对 `fileId \|\| kemCiphertext \|\| fileHash` 签名。
5. 调用 finalize 提交元数据（file_id、sender_id、receiver_id、total_chunks、kem_ciphertext、sender_signature、file_name、file_size 等）。

### 2.2 密钥与 fileId（cryptoEngine + uploadService）

- **入口**：`uploadService.runUpload()`。
- **拉公钥**：`GET /keys/{receiverId}` → 取 `kem_public_key`（Base64），解码为 `Uint8Array`。
- **生成套件**：`generateEncryptionSuite(receiverKemPublicKey)`：
  - `KemEngine.encapsulateSecret(receiverKemPublicKey)` → `{ ciphertext: kemCiphertext, sharedSecret }`（sharedSecret 32 字节）。
  - `fileId = crypto.randomUUID()`。
  - HKDF-SHA256：salt 固定 `QuantumGuard-HKDF-Salt-v1`，info = `QuantumGuard-AES-GCM-v1:` + fileId，从 sharedSecret 派生 256 位，导入为 AES-GCM 密钥 `aesKey`。
- **输出**：`{ aesKey, kemCiphertext, fileId }`，供后续分块加密与 finalize 使用。

### 2.3 分块加密与上传（uploadService）

- **分块数**：`totalChunks = Math.ceil(file.size / CHUNK_SIZE)`，`CHUNK_SIZE = 5 * 1024 * 1024`（5MB，单块解密与 IPC 更快）。
- **流式哈希**：使用 `jsSHA('SHA-256', 'ARRAYBUFFER')`，在每块读取后 `hasher.update(chunkData)`，**不在内存中保留整文件**，避免大文件 OOM。
- **单块原子任务** `runAtomicChunkTask(chunkIndex)`：
  1. `file.slice(start, end)` 得到该块 Blob，`arrayBuffer()` 得到 `chunkData`。
  2. `hasher.update(chunkData)`。
  3. `encryptChunkWithAad(chunkData, aesKey, fileId, chunkIndex)`：
     - 随机 12 字节 IV；
     - AAD = `encoder.encode(\`${fileId}_${chunkIndex}\`)`；
     - `crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD, tagLength: 128 }, aesKey, chunkData)`。
  4. 构造上传 payload：`payload = IV \|\| ciphertext`（Uint8Array）。
  5. `uploadChunk(fileId, chunkIndex, payload)`：FormData 含 `file_id`、`chunk_index`、`file`（Blob(payload)），POST `/files/upload_chunk`。
- **并发**：最多 `UPLOAD_MAX_CONCURRENCY = 3` 个 `runAtomicChunkTask` 同时在飞，通过 `inFlight` Set + `Promise.race` 控制。

### 2.4 签名与 finalize（uploadService）

- **签名字段**：`messageToSign = fileId (UTF-8) \|\| kemCiphertext \|\| fileHash`（fileHash 为 hasher 在全部块处理完后的 `getHash('ARRAYBUFFER')`）。
- **签名**：`DsaEngine.sign(messageToSign, myKeys.dsaPrivateKey)`，得到 `signature`（Uint8Array），再 Base64。
- **Finalize**：POST `/files/finalize`，Form 字段：file_id、sender_id、receiver_id、total_chunks、global_signature（即 kem_ciphertext Base64）、kem_ciphertext、sender_signature、file_name、file_size。

### 2.5 后端存储（file_transfer.py）

- **upload_chunk**：
  - 根据 `file_id` 建分块目录（如 `ENCRYPTED_DIR / file_id`），每块存为单独文件，文件名为 `chunk_index`（如 0, 1, 2…）。
  - 单块内容为前端发来的二进制：前 12 字节为 IV，其后为 AES-GCM 密文（含 16 字节 tag）。
  - 单块大小上限：`CHUNK_PHYSICAL_SIZE = CHUNK_PLAINTEXT_SIZE + 12 + 16`（后端允许最大明文 20MB，前端当前 5MB）。
- **finalize**：
  - 校验 sender_id / receiver_id 已注册，且 0 到 total_chunks-1 的块文件均存在。
  - 写入 `FileMetadata`：file_id、sender_id、receiver_id、total_chunks、global_signature、storage_path（分块目录路径）、kem_ciphertext、sender_signature、file_name、file_size。

---

## 三、大文件解密（下载）逻辑

解密侧有两种入口：**downloadService.runDownload()**（通用接收方流程）与 **FileDownloader.vue**（带 UI 的零信任解密，可从列表/transfer meta 拿元数据）。两者在「密钥派生 + 单块解密」上一致，在「写盘方式」和「并发」上略有差异。

### 3.1 元数据与密钥派生（共用）

- **元数据**：
  - downloadService：`GET /api/transfer/download/{fileId}/meta` → FileMeta（file_id、sender_id、receiver_id、kem_ciphertext、sender_signature、total_chunks、file_name、file_size）。
  - FileDownloader：可从列表项或 `GET /api/transfer/download/{fileId}/meta` 取 file_id、kem_ciphertext、total_chunks、file_name、file_size。
- **KEM 解封**：使用接收方 ML-KEM 私钥（从 KeyStorage/IndexedDB 取），`KemEngine.decapsulateSecret(kemCiphertext, privateKey)` → 32 字节 sharedSecret。
- **AES 密钥**：`deriveAesKeyFromSharedSecretAndFileId(sharedSecret, fileId)`（与 cryptoEngine 中 HKDF 参数一致：同一 salt、info = `QuantumGuard-AES-GCM-v1:` + fileId），得到 AES-GCM 的 CryptoKey。

### 3.2 按块拉取与解密（共用）

- **单块请求**：`GET /files/download/{file_id}/chunk/{chunk_index}`，需 JWT（接收方身份），后端校验 `file_record.receiver_id == current_user.user_id` 后返回该块二进制。
- **单块格式**：响应 body = 12 字节 IV + AES-GCM 密文（含 16 字节 tag）。前端取 `iv = body.slice(0,12)`，`ciphertext = body.slice(12)`。
- **解密**：
  - downloadService：内部 `decryptChunk(ciphertext, aesKey, iv, fileId, chunkIndex)`，AAD 为 `UPLOAD_SERVICE_AAD_FORMAT(fileId, chunkIndex)` 即 `fileId_chunkIndex`。
  - FileDownloader：`CryptoStream.decryptChunk(encryptedData, aesKey, iv, fileId, chunkIndex)`，内部先试 AAD `fileId_chunkIndex`，失败则试旧版 `fileId:chunk:chunkIndex`（兼容旧文件）。
- **完整性**：若元数据带 `sender_signature`，接收方在写盘/流的同时用 jsSHA 做增量 SHA-256；全部块写完后得到 fileHash，验签 `DsaEngine.verify(senderSignature, fileId \|\| kemCiphertext \|\| fileHash, senderDsaPk)`。

### 3.3 downloadService 写盘与并发

- **浏览器**：与 FileDownloader 浏览器路径类似，流式写盘或串行写盘视实现而定。
- **Tauri**：可由 downloadService 调用 `stream_decrypt_batch` 或沿用逐块 invoke（若仍存在）。

### 3.4 FileDownloader.vue 写盘与并发（竞赛级优化）

- **Tauri**（并行流水线）：
  - 先选保存路径；前端导出 AES 密钥（raw），**单次**调用 `invoke('stream_decrypt_batch', { path, aesKey, fileId, baseUrl, authHeader, totalChunks, expectedPlainSize })`。
  - Rust 内：3 路并发拉取（`AtomicU32` 分配块号）→ 每路拉取后即解密（`decrypt_block`）→ 通过 channel 送入**单写线程**按块号顺序写盘并更新 SHA-256；可选 `expected_plain_size` 做 `file.set_len` 预分配。
  - 前端监听 `decrypt-progress` 事件更新进度；batch 返回整文件 SHA-256（当前未做 DSA 验签时由前端可选校验）。
  - 解密失败时仍支持「兼容模式」：用 sharedSecret 导入 AES 再调一次 `stream_decrypt_batch`。
- **浏览器**（流式写盘 + 3 并发）：
  - 先通过 `showSaveFilePicker` 或 StreamSaver 取得 `WritableStream`，再启动 3 个拉取+解密任务与 1 个写盘循环。
  - 解密任务从共享 `nextIndexToFetch` 取块号，拉取→解密后向队列 `enqueue({ index, data })`；写盘循环 `dequeue()` 后按块号顺序写入（乱序块暂存 `pending` Map），写满 `total` 后关闭流。
  - 并发数 `MAX_DOWNLOAD_CONCURRENCY = 3`，与上传一致；**不再全量进内存**，避免 1.8GB 级 OOM。
- **Android（Content URI）**：
  - 当保存路径为 `content://`（系统文档选择器返回）时，Rust 无法直接写入；由前端使用 `@tauri-apps/plugin-fs` 的 `writeFile(path, ReadableStream, { create: true })`。
  - 在 JS 侧构造 `ReadableStream`：`pull` 中按序拉取块、解密（`CryptoStream.decryptChunk`）并 `enqueue` 明文；`writeFile` 消费该流并写入 Content URI，由系统 DocumentProvider 落盘到用户所选位置。

### 3.5 后端下发单块（file_transfer.py）

- `GET /files/download/{file_id}/chunk/{chunk_index}`：校验 file 存在、当前用户为 receiver、chunk_index 在 [0, total_chunks)，从 `storage_path` 下读取名为 `str(chunk_index)` 的文件，`Response(content=content, media_type='application/octet-stream')` 返回，不做任何加解密。

---

## 四、密文长度与校验

- **单块密文长度**：明文块 ≤ 20MB（前端当前 5MB），密文 = 明文 + 12(IV) + 16(tag)。若已知明文总长 `file_size` 与块数 `total`，则密文总长 = `file_size + total * 28`（最后一块若非整块仍按实际密文长度）。
- **FileDownloader（Tauri）**：若存在 `file_size`，可做密文总长或明文总长校验，防止缺块或篡改。
- **FileDownloader（浏览器/Android）**：若元数据 `file_size` 与最终写入字节数不一致，仅记录日志提示，不阻断流程，以实际写入为准（兼容元数据为密文长度或跨端差异）。

---

## 五、数据流简图

```
加密上传:
  文件 → 分块(5MB) → [ 读块 → 流式SHA256 → AES-GCM加密(AAD=fileId_chunkIndex) → IV||密文 ] × N
       → 整文件 SHA256 → DSA 签名(fileId||kemCiphertext||fileHash) → finalize 元数据
  后端: 每块存为 file_id 目录下 chunk_index 文件；finalize 写 FileMetadata。

解密下载:
  元数据(kem_ciphertext, total_chunks, …) → KEM Decap(接收方私钥) → sharedSecret
       → HKDF(fileId) → AES Key
  Tauri: 单次 invoke stream_decrypt_batch → Rust 内 3 路拉取 + 解密 + 顺序写盘 + 可选预分配；前端监听 decrypt-progress。
  浏览器: showSaveFilePicker/StreamSaver 得 WritableStream → 3 并发拉取+解密 → 队列 → 单写循环按序写盘（乱序暂存 pending）。
  若有 sender_signature: 可用 Rust 返回的 fileHash 或浏览器端增量 SHA256 验签。
```

---

## 六、涉及文件一览

| 角色 | 文件 | 说明 |
|------|------|------|
| 上传 | `src/services/uploadService.ts` | 分块、流式哈希、加密、并发上传、签名、finalize |
| 上传 | `src/core/cryptoEngine.ts` | generateEncryptionSuite（KEM + HKDF）、deriveAesKeyFromSharedSecretAndFileId |
| 加解密 | `src/core/crypto-stream.ts` | CHUNK_SIZE、deriveAesKey、importAesKey、encryptChunk、decryptChunk（含旧版 AAD） |
| 下载 | `src/services/downloadService.ts` | 元数据、KEM 解封、按块拉取与解密、浏览器/Tauri 流式写盘、验签 |
| 下载 UI | `src/components/FileDownloader.vue` | 从 meta/列表取元数据；Tauri 单次 stream_decrypt_batch；浏览器流式写盘+3 并发；Android 使用 plugin-fs writeFile(ReadableStream) 写 content URI；兼容密钥与 AAD |
| 后端 | `app/routers/file_transfer.py` | upload_chunk、finalize、download chunk、CHUNK_PLAINTEXT_SIZE/CHUNK_PHYSICAL_SIZE |
| Tauri | `src-tauri/src/lib.rs` | stream_decrypt_batch（3 路拉取+解密+顺序写盘+预分配）、decrypt_block、decrypt-progress 事件；保留 stream_decrypt_* 兼容 |

以上即为当前大文件加密与解密的完整逻辑说明。
