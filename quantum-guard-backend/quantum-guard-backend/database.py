from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# 以模块所在位置解析项目根目录，避免工作目录变更导致路径不一致
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
ENCRYPTED_DIR = DATA_DIR / "encrypted_files"
DB_PATH = DATA_DIR / "quantum_guard.db"

# 启动时把目录建好
DATA_DIR.mkdir(parents=True, exist_ok=True)
ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)

# 使用绝对路径连接 SQLite，保证稳定性
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH.as_posix()}"

# FastAPI + SQLite 标准引擎配置
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    future=True,
    expire_on_commit=False,
)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI 依赖注入用：每请求一个会话，请求结束时自动关闭。"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()