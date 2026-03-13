/**
 * 解密后文件保存：Tauri 桌面端使用系统“另存为”对话框 + 原生写入；
 * 浏览器端回退为 createObjectURL + <a> 下载。
 */

import { isTauri } from './tauri';

/**
 * 将解密后的二进制数据保存到本地。
 * - Tauri：弹出系统“另存为”对话框，用户选择路径后通过 @tauri-apps/plugin-fs 写入。
 * - 浏览器：使用 createObjectURL + <a> 触发下载。
 * @param data 解密后的文件内容（Uint8Array 或 Blob）
 * @param suggestedFileName 建议的文件名（用于对话框默认名或下载属性）
 * @returns 是否已保存；Tauri 下用户取消对话框时为 false
 */
export async function saveDecryptedFile(
  data: Uint8Array | Blob,
  suggestedFileName: string
): Promise<boolean> {
  try {
    // 1. 数据格式转换：确保底层拿到的是纯净的二进制流
    const bytes = data instanceof Blob ? new Uint8Array(await data.arrayBuffer()) : data;
    const name = suggestedFileName?.trim() || 'decrypted.bin';

    if (isTauri()) {
      const { save } = await import('@tauri-apps/plugin-dialog');
      const { writeFile } = await import('@tauri-apps/plugin-fs');

      console.log("[系统日志] 正在唤起 Windows 原生另存为窗口...");

      // 2. 唤起系统弹窗
      const path = await save({
        defaultPath: name,
        filters: [{ name: 'All Files', extensions: ['*'] }]
      });

      // 3. 判断用户是否点了取消
      if (path == null || path === '') {
        console.warn("[系统日志] 用户点击了取消保存");
        return false;
      }

      console.log(`[系统日志] 准备将 ${bytes.length} 字节的数据写入路径:`, path);

      // 4. 核心写入操作（带致命错误捕捉）
      try {
        await writeFile(path, bytes);
        console.log("[系统日志] 🎉 文件写入硬盘成功！完美落盘！");
        return true;
      } catch (writeError) {
        console.error("🚨 致命错误：Tauri 写入硬盘失败！详细原因:", writeError);
        // 把真实的报错原因抛出去，打破“未知错误”的黑盒
        throw new Error(`写入被拦截或失败，原因: ${writeError}`);
      }

    } else {
      // ==== 浏览器回退逻辑保持不变 ====
      console.log("[系统日志] 当前为浏览器环境，触发传统 Web 下载...");
      const blob = new Blob([new Uint8Array(bytes)], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      console.log("[系统日志] Web 下载触发完毕。");
      return true;
    }
  } catch (globalError) {
    console.error("🚨 saveDecryptedFile 发生外层异常:", globalError);
    throw globalError;
  }
}
