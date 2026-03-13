import os

from dotenv import load_dotenv
load_dotenv()  # 加载项目根目录 .env，使 SMTP、JWT 等环境变量生效

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.database import engine
from app import models
from app.routers import key_exchange, file_transfer, transfer, auth


def _column_exists(conn, table: str, column: str) -> bool:
    """判断指定表是否包含指定列，基于 SQLite PRAGMA table_info。"""
    r = conn.execute(text(f"PRAGMA table_info({table})"))
    return any(row[1] == column for row in r.fetchall())


def _migrate_e2e_schema():
    """
    E2E 零信任架构的数据库迁移：为 user_public_keys 补充 kem_public_key、dsa_public_key（若存在 public_key_b64 则回填）；
    为 file_metadata 补充 kem_ciphertext、sender_signature；为 user_public_keys 补充 hashed_password、email 及 email 唯一约束。
    """
    with engine.connect() as conn:
        try:
            # user_public_keys：添加 KEM/DSA 公钥列
            if not _column_exists(conn, "user_public_keys", "kem_public_key"):
                conn.execute(text("ALTER TABLE user_public_keys ADD COLUMN kem_public_key TEXT"))
            if not _column_exists(conn, "user_public_keys", "dsa_public_key"):
                conn.execute(text("ALTER TABLE user_public_keys ADD COLUMN dsa_public_key TEXT"))
            # 若存在旧列 public_key_b64，则回填 kem_public_key
            if _column_exists(conn, "user_public_keys", "public_key_b64"):
                conn.execute(text(
                    "UPDATE user_public_keys SET kem_public_key = public_key_b64 "
                    "WHERE kem_public_key IS NULL OR kem_public_key = ''"
                ))
            conn.execute(text(
                "UPDATE user_public_keys SET dsa_public_key = '' "
                "WHERE dsa_public_key IS NULL OR dsa_public_key = ''"
            ))
            conn.commit()
        except Exception as e:
            if "no such table" in str(e).lower():
                pass  # 表尚未创建，由 create_all 处理
            else:
                raise
        try:
            if not _column_exists(conn, "file_metadata", "kem_ciphertext"):
                conn.execute(text("ALTER TABLE file_metadata ADD COLUMN kem_ciphertext TEXT"))
            if not _column_exists(conn, "file_metadata", "sender_signature"):
                conn.execute(text("ALTER TABLE file_metadata ADD COLUMN sender_signature TEXT"))
            conn.commit()
        except Exception as e:
            if "no such table" in str(e).lower():
                pass
            else:
                raise
        try:
            if not _column_exists(conn, "user_public_keys", "hashed_password"):
                conn.execute(text("ALTER TABLE user_public_keys ADD COLUMN hashed_password VARCHAR(255)"))
            if not _column_exists(conn, "user_public_keys", "email"):
                conn.execute(text("ALTER TABLE user_public_keys ADD COLUMN email VARCHAR(255)"))
            # 仅对 email 非空值施加唯一约束
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_user_public_keys_email_not_null "
                "ON user_public_keys(email) WHERE email IS NOT NULL AND email != ''"
            ))
            conn.commit()
        except Exception as e:
            if "no such table" in str(e).lower():
                pass
            else:
                raise
        try:
            if not _column_exists(conn, "user_public_keys", "recovery_blob"):
                conn.execute(text("ALTER TABLE user_public_keys ADD COLUMN recovery_blob TEXT"))
            conn.commit()
        except Exception as e:
            if "no such table" in str(e).lower():
                pass
            else:
                raise
        try:
            if not _column_exists(conn, "user_public_keys", "mk_encrypted_cloud"):
                conn.execute(text("ALTER TABLE user_public_keys ADD COLUMN mk_encrypted_cloud TEXT"))
            if not _column_exists(conn, "user_public_keys", "asym_priv_encrypted"):
                conn.execute(text("ALTER TABLE user_public_keys ADD COLUMN asym_priv_encrypted TEXT"))
            if not _column_exists(conn, "user_public_keys", "keys_updated_at"):
                conn.execute(text("ALTER TABLE user_public_keys ADD COLUMN keys_updated_at DATETIME"))
            if not _column_exists(conn, "user_public_keys", "password_box_salt"):
                conn.execute(text("ALTER TABLE user_public_keys ADD COLUMN password_box_salt TEXT"))
            if not _column_exists(conn, "user_public_keys", "mk_encrypted_by_password"):
                conn.execute(text("ALTER TABLE user_public_keys ADD COLUMN mk_encrypted_by_password TEXT"))
            conn.commit()
        except Exception as e:
            if "no such table" in str(e).lower():
                pass
            else:
                raise


@asynccontextmanager
async def lifespan(_: FastAPI):
    models.Base.metadata.create_all(bind=engine)
    try:
        _migrate_e2e_schema()
    except Exception:
        pass  # 表没建好或迁移报错就跳过，不拦启动
    yield


app = FastAPI(
    title="QuantumGuard Backend",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS：生产/答辩建议设置 CORS_ORIGINS（逗号分隔），如 https://your-front.com；未设置时开发用 *，credentials 与 * 同源不兼容故设为 False
_cors_origins_raw = (os.environ.get("CORS_ORIGINS") or "").strip()
if _cors_origins_raw:
    _cors_origins = [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]
    _cors_credentials = True
else:
    _cors_origins = ["*"]
    _cors_credentials = False
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Content-Length"],
)

_IS_PRODUCTION = os.environ.get("ENV") == "production" or os.environ.get("PRODUCTION") == "1"


@app.exception_handler(Exception)
async def global_exception_handler(_, exc: Exception):
    """未捕获异常返回 500；生产环境不向客户端暴露异常详情，仅写通用文案。"""
    detail = "服务器内部错误" if _IS_PRODUCTION else (str(exc) or "服务器内部错误")
    return JSONResponse(
        status_code=500,
        content={"detail": detail},
        headers={"Access-Control-Allow-Origin": "*"},
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok"}

app.include_router(key_exchange.router)
app.include_router(file_transfer.router)
app.include_router(transfer.router)
app.include_router(auth.router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)