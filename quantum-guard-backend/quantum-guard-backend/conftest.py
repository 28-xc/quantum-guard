"""pytest 配置：使用内存 SQLite 覆盖 get_db，避免污染正式库。"""
import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# 测试前确保不触发生产 JWT 校验
os.environ.setdefault("ENV", "test")
os.environ.setdefault("JWT_SECRET", "test_jwt_secret_for_pytest_only_32bytes_long!!")

from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app import models  # noqa: F401 — 确保 Base 已注册所有表
from app.main import app

# 使用 StaticPool 保证内存库仅一个连接，create_all 与请求内 session 共用同一 DB
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="function")
def client():
    Base.metadata.create_all(bind=engine)
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
