#!/usr/bin/env python3
"""
发布前清空所有数据：删除所有账号、文件元数据及磁盘上的加密分块。
使用前请先停止后端服务，避免连接占用数据库。
"""
import sys
from pathlib import Path

# 保证能导入 app
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import text
from app.database import engine, DB_PATH, ENCRYPTED_DIR


def main():
    print("数据库路径:", DB_PATH)
    print("加密文件目录:", ENCRYPTED_DIR)
    confirm = input("确认清空所有账号与文件数据？输入 yes 继续: ").strip().lower()
    if confirm != "yes":
        print("已取消")
        return

    with engine.connect() as conn:
        conn.execute(text("DELETE FROM file_metadata"))
        conn.execute(text("DELETE FROM user_public_keys"))
        conn.commit()
        print("已清空表: file_metadata, user_public_keys")

    # 删除加密分块目录下所有内容（保留目录本身）
    if ENCRYPTED_DIR.exists():
        for p in ENCRYPTED_DIR.iterdir():
            if p.is_dir():
                for f in p.iterdir():
                    f.unlink()
                p.rmdir()
            else:
                p.unlink()
        print("已清空加密文件目录:", ENCRYPTED_DIR)
    else:
        print("加密文件目录不存在，跳过")

    print("完成。可重新启动后端，数据库与磁盘已干净。")


if __name__ == "__main__":
    main()
