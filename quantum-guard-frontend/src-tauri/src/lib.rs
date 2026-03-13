//! QuantumGuard Tauri 2 核心库：桌面与 Android 共用。
//! 流式落盘命令与状态在此定义；KDF 由 Rust 执行以规避前端卡顿；Android 通过 `run()` 入口加载。

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::sync::Mutex;

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm,
};
use base64::Engine;
use pbkdf2::pbkdf2_hmac_array;
use sha2::{Digest, Sha256};
use tauri::Manager;
use tauri::Emitter;
use tokio::sync::mpsc;

/// 流式落盘状态：持有一个 BufWriter，前端通过 write-chunk 逐块写入，避免大文件 IPC 阻塞。
struct StreamWriteState(Mutex<Option<BufWriter<File>>>);

/// 流式解密落盘状态：持有关键材料、写入句柄与 SHA-256 哈希器，Rust 侧解密后写盘并更新哈希。
struct StreamDecryptState(Mutex<Option<StreamDecryptInner>>);

struct StreamDecryptInner {
    writer: BufWriter<File>,
    key: [u8; 32],
    file_id: String,
    hasher: Sha256,
    /// 当前块密文缓冲，避免单次 IPC 传整块导致序列化极慢
    chunk_buf: Vec<u8>,
}

/// 返回可用于解密落盘的可写目录路径（含末尾斜杠）。Android 上 save 返回 content URI 且 current_dir 只读，
/// 故用 Tauri PathResolver 的 app_cache_dir（应用可写）；桌面端用 current_dir/decrypted。
#[tauri::command]
fn get_decrypt_output_dir(app: tauri::AppHandle) -> Result<String, String> {
    let dir = app
        .path()
        .app_cache_dir()
        .map_err(|e| format!("{}", e))?
        .join("decrypted");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut s = dir.to_string_lossy().to_string();
    if !s.ends_with(std::path::MAIN_SEPARATOR) {
        s.push(std::path::MAIN_SEPARATOR);
    }
    Ok(s)
}

/// 在 Rust 侧执行 PBKDF2-HMAC-SHA256，派生 32 字节 AES 密钥，避免前端 10 万次迭代卡顿。
/// 参数：password_base64 为前端规范化后的密码（UTF-8 或超长时 SHA-256 摘要）的 base64，与后端 bcrypt 规范一致；salt_base64、iterations；返回：key_base64（32 字节）。
#[tauri::command]
fn derive_key_pbkdf2(
    password_base64: String,
    salt_base64: String,
    iterations: u32,
) -> Result<String, String> {
    let password_bytes = base64::engine::general_purpose::STANDARD
        .decode(&password_base64)
        .map_err(|e| e.to_string())?;
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&salt_base64)
        .map_err(|e| e.to_string())?;
    let key: [u8; 32] = pbkdf2_hmac_array::<Sha256, 32>(
        &password_bytes,
        &salt,
        iterations.max(1),
    );
    Ok(base64::engine::general_purpose::STANDARD.encode(key))
}

#[tauri::command]
fn stream_save_open(state: tauri::State<StreamWriteState>, path: String) -> Result<(), String> {
    let file = File::create(&path).map_err(|e| e.to_string())?;
    let writer = BufWriter::new(file);
    *state
        .0
        .lock()
        .map_err(|e| e.to_string())? = Some(writer);
    Ok(())
}

#[tauri::command]
fn stream_save_write_chunk(
    state: tauri::State<StreamWriteState>,
    chunk: Vec<u8>,
) -> Result<(), String> {
    let mut guard = state.0.lock().map_err(|e| e.to_string())?;
    if let Some(ref mut w) = *guard {
        w.write_all(&chunk).map_err(|e| e.to_string())?;
        Ok(())
    } else {
        Err("stream not open".to_string())
    }
}

#[tauri::command]
fn stream_save_end(state: tauri::State<StreamWriteState>) -> Result<(), String> {
    let mut guard = state.0.lock().map_err(|e| e.to_string())?;
    let _ = guard.take(); // drop 即 flush + close
    Ok(())
}

const AES_GCM_IV_LEN: usize = 12;
const AES_GCM_TAG_LEN: usize = 16;

/// 内部：对单块密文解密并写入文件、更新哈希。
fn decrypt_and_write_chunk(
    inner: &mut StreamDecryptInner,
    chunk_index: u32,
    iv_and_ciphertext: Vec<u8>,
) -> Result<(), String> {
    if iv_and_ciphertext.len() < AES_GCM_IV_LEN + AES_GCM_TAG_LEN {
        return Err(format!(
            "块 {} 长度异常: {}",
            chunk_index,
            iv_and_ciphertext.len()
        ));
    }
    let (iv, ct_with_tag) = iv_and_ciphertext.split_at(AES_GCM_IV_LEN);
    let (encrypted, tag) = ct_with_tag.split_at(ct_with_tag.len() - AES_GCM_TAG_LEN);

    let cipher = Aes256Gcm::new_from_slice(&inner.key).map_err(|e| e.to_string())?;
    let nonce = aes_gcm::Nonce::from_slice(iv);
    let tag_arr = aes_gcm::Tag::from_slice(tag);

    let aad_standard = format!("{}_{}", inner.file_id, chunk_index);
    let aad_legacy = format!("{}:chunk:{}", inner.file_id, chunk_index);

    let mut buf = encrypted.to_vec();
    let ok = cipher
        .decrypt_in_place_detached(nonce, aad_standard.as_bytes(), &mut buf, tag_arr)
        .or_else(|_| {
            buf = encrypted.to_vec();
            cipher.decrypt_in_place_detached(nonce, aad_legacy.as_bytes(), &mut buf, tag_arr)
        });
    ok.map_err(|e| format!("块 {} 解密失败: {}", chunk_index, e))?;

    inner.writer.write_all(&buf).map_err(|e| e.to_string())?;
    inner.hasher.update(&buf);
    Ok(())
}

/// 仅解密单块，返回明文（不写盘）。供批量流水线使用；AAD 与 decrypt_and_write_chunk 一致。
fn decrypt_block(
    key: &[u8; 32],
    file_id: &str,
    chunk_index: u32,
    iv_and_ciphertext: Vec<u8>,
) -> Result<Vec<u8>, String> {
    if iv_and_ciphertext.len() < AES_GCM_IV_LEN + AES_GCM_TAG_LEN {
        return Err(format!(
            "块 {} 长度异常: {}",
            chunk_index,
            iv_and_ciphertext.len()
        ));
    }
    let (iv, ct_with_tag) = iv_and_ciphertext.split_at(AES_GCM_IV_LEN);
    let (encrypted, tag) = ct_with_tag.split_at(ct_with_tag.len() - AES_GCM_TAG_LEN);

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = aes_gcm::Nonce::from_slice(iv);
    let tag_arr = aes_gcm::Tag::from_slice(tag);

    let aad_standard = format!("{}_{}", file_id, chunk_index);
    let aad_legacy = format!("{}:chunk:{}", file_id, chunk_index);

    let mut buf = encrypted.to_vec();
    let ok = cipher
        .decrypt_in_place_detached(nonce, aad_standard.as_bytes(), &mut buf, tag_arr)
        .or_else(|_| {
            buf = encrypted.to_vec();
            cipher.decrypt_in_place_detached(nonce, aad_legacy.as_bytes(), &mut buf, tag_arr)
        });
    ok.map_err(|e| format!("块 {} 解密失败: {}", chunk_index, e))?;
    Ok(buf)
}

/// 打开流式解密：创建文件、保存 AES 密钥与 file_id，用于后续按块解密并写盘。
#[tauri::command]
fn stream_decrypt_open(
    state: tauri::State<StreamDecryptState>,
    path: String,
    aes_key: Vec<u8>,
    file_id: String,
) -> Result<(), String> {
    if aes_key.len() != 32 {
        return Err("aes_key 须为 32 字节".to_string());
    }
    let file = File::create(&path).map_err(|e| e.to_string())?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&aes_key);
    let inner = StreamDecryptInner {
        writer: BufWriter::new(file),
        key,
        file_id,
        hasher: Sha256::new(),
        chunk_buf: Vec::new(),
    };
    *state.0.lock().map_err(|e| e.to_string())? = Some(inner);
    Ok(())
}

/// 追加当前块的密文片段（前端按 64KB 分片发送，避免单次传整块导致 IPC 序列化极慢）。
#[tauri::command]
fn stream_decrypt_append_ciphertext(
    state: tauri::State<StreamDecryptState>,
    data: Vec<u8>,
) -> Result<(), String> {
    let mut guard = state.0.lock().map_err(|e| e.to_string())?;
    let inner = guard.as_mut().ok_or("stream_decrypt 未 open")?;
    inner.chunk_buf.extend(data);
    Ok(())
}

/// 将当前缓冲的密文按一块解密并写盘，然后清空缓冲。缓冲须为 12 字节 IV + 密文（含 16 字节 tag）。
#[tauri::command]
fn stream_decrypt_flush_chunk(
    state: tauri::State<StreamDecryptState>,
    chunk_index: u32,
) -> Result<(), String> {
    let mut guard = state.0.lock().map_err(|e| e.to_string())?;
    let inner = guard.as_mut().ok_or("stream_decrypt 未 open")?;
    let iv_and_ciphertext = std::mem::take(&mut inner.chunk_buf);
    decrypt_and_write_chunk(inner, chunk_index, iv_and_ciphertext)
}

/// Rust 侧直接拉取密文并解密写盘，避免大块数据经 IPC。前端只传 URL 与 Authorization。
#[tauri::command]
async fn stream_decrypt_fetch_and_flush(
    state: tauri::State<'_, StreamDecryptState>,
    chunk_index: u32,
    url: String,
    auth_header: String,
) -> Result<(), String> {
    let client = reqwest::Client::new();
    let mut req = client.get(&url);
    if !auth_header.trim().is_empty() {
        req = req.header("Authorization", auth_header.trim());
    }
    let res = req
        .send()
        .await
        .map_err(|e| format!("块 {} 拉取失败: {}", chunk_index, e))?;
    if !res.status().is_success() {
        return Err(format!(
            "块 {} 拉取 HTTP {}",
            chunk_index,
            res.status().as_u16()
        ));
    }
    let bytes = res
        .bytes()
        .await
        .map_err(|e| format!("块 {} 读取 body 失败: {}", chunk_index, e))?;
    let iv_and_ciphertext = bytes.to_vec();

    let mut guard = state.0.lock().map_err(|e| e.to_string())?;
    let inner = guard.as_mut().ok_or("stream_decrypt 未 open")?;
    decrypt_and_write_chunk(inner, chunk_index, iv_and_ciphertext)
}

/// 结束流式解密：关闭文件并返回整文件 SHA-256（32 字节），供前端验签。
#[tauri::command]
fn stream_decrypt_end(state: tauri::State<StreamDecryptState>) -> Result<Vec<u8>, String> {
    let mut guard = state.0.lock().map_err(|e| e.to_string())?;
    let inner = guard.take().ok_or("stream_decrypt 未 open")?;
    drop(inner.writer); // flush + close
    let hash = inner.hasher.finalize();
    Ok(hash.to_vec())
}

/// 并行流水线解密：Rust 内 3 路并发拉取 + 解密 + 顺序写盘，前端只调一次。
/// 参数：path、aes_key(32)、file_id、base_url(如 https://api.example.com)、auth_header、total_chunks、expected_plain_size(可选，用于预分配文件)。
/// 通过 app 发送 "decrypt-progress" 事件，payload 为 [current, total]。
#[tauri::command]
async fn stream_decrypt_batch(
    app: tauri::AppHandle,
    path: String,
    aes_key: Vec<u8>,
    file_id: String,
    base_url: String,
    auth_header: String,
    total_chunks: u32,
    expected_plain_size: Option<u64>,
) -> Result<Vec<u8>, String> {
    use std::io::{Seek, SeekFrom};
    use std::sync::atomic::{AtomicU32, Ordering};

    if aes_key.len() != 32 {
        return Err("aes_key 须为 32 字节".to_string());
    }
    let key: [u8; 32] = aes_key.as_slice().try_into().map_err(|_| "aes_key 长度非法")?;

    let mut file = File::create(&path).map_err(|e| e.to_string())?;
    if let Some(s) = expected_plain_size {
        file.set_len(s).map_err(|e| e.to_string())?;
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    }
    let mut writer = BufWriter::new(file);
    let mut hasher = Sha256::new();
    let mut pending: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut next_index: u32 = 0;

    let (write_tx, mut write_rx) = mpsc::channel::<Result<(u32, Vec<u8>), String>>(32);
    let base_url = base_url.trim_end_matches('/').to_string();

    let next_to_fetch = std::sync::Arc::new(AtomicU32::new(0));
    let client = reqwest::Client::new();

    for _ in 0..3 {
        let next_to_fetch = next_to_fetch.clone();
        let client = client.clone();
        let key = key;
        let file_id = file_id.clone();
        let auth = auth_header.clone();
        let tx = write_tx.clone();
        let base = base_url.clone();
        tauri::async_runtime::spawn(async move {
            loop {
                let i = next_to_fetch.fetch_add(1, Ordering::Relaxed);
                if i >= total_chunks {
                    break;
                }
                let url = format!("{}/files/download/{}/chunk/{}", base, file_id, i);
                let mut req = client.get(&url);
                if !auth.trim().is_empty() {
                    req = req.header("Authorization", auth.trim());
                }
                let res = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx.send(Err(format!("块 {} 拉取失败: {}", i, e))).await;
                        break;
                    }
                };
                if !res.status().is_success() {
                    let _ = tx
                        .send(Err(format!("块 {} HTTP {}", i, res.status().as_u16())))
                        .await;
                    break;
                }
                let body = match res.bytes().await {
                    Ok(b) => b.to_vec(),
                    Err(e) => {
                        let _ = tx.send(Err(format!("块 {} 读取失败: {}", i, e))).await;
                        break;
                    }
                };
                match decrypt_block(&key, &file_id, i, body) {
                    Ok(plain) => {
                        if tx.send(Ok((i, plain))).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        });
    }
    drop(write_tx);

    while next_index < total_chunks {
        match write_rx.recv().await {
            Some(Ok((i, data))) => {
                pending.insert(i, data);
                while let Some(data) = pending.remove(&next_index) {
                    writer.write_all(&data).map_err(|e| e.to_string())?;
                    hasher.update(&data);
                    let _ = app.emit("decrypt-progress", (next_index + 1, total_chunks));
                    next_index += 1;
                    if next_index >= total_chunks {
                        break;
                    }
                }
            }
            Some(Err(e)) => return Err(e),
            None => return Err("下载或解密未完成即结束".to_string()),
        }
    }

    writer.flush().map_err(|e| e.to_string())?;
    drop(writer);
    Ok(hasher.finalize().to_vec())
}

/// 应用构建与运行：桌面由 main 调用，Android 由 mobile_entry_point 调用。
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .manage(StreamWriteState(Mutex::new(None)))
        .manage(StreamDecryptState(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            stream_save_open,
            stream_save_write_chunk,
            stream_save_end,
            stream_decrypt_open,
            stream_decrypt_append_ciphertext,
            stream_decrypt_flush_chunk,
            stream_decrypt_fetch_and_flush,
            stream_decrypt_end,
            stream_decrypt_batch,
            get_decrypt_output_dir,
            derive_key_pbkdf2
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
