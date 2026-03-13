"""认证与收件箱鉴权的基础测试：无 token 不可访问 list；登录成功返回 token；错误密码 401。"""
import pytest
from fastapi.testclient import TestClient


def test_list_without_auth_returns_401(client: TestClient):
    """未带 Authorization 时，GET /files/list/{receiver_id} 应返回 401。"""
    r = client.get("/files/list/Alice")
    assert r.status_code == 401


def test_list_with_invalid_token_returns_401(client: TestClient):
    """无效或过期的 Bearer token 应返回 401。"""
    r = client.get("/files/list/Alice", headers={"Authorization": "Bearer invalid"})
    assert r.status_code == 401


def test_login_nonexistent_user_returns_401(client: TestClient):
    """不存在的用户登录应返回 401。"""
    r = client.post(
        "/api/auth/login",
        json={"user_id": "NoSuchUser", "password": "any"},
    )
    assert r.status_code == 401


def test_register_and_login_success_returns_token(client: TestClient):
    """注册后使用正确密码登录应返回 200 与 token。"""
    reg = client.post(
        "/api/auth/register",
        json={
            "user_id": "TestUser",
            "password": "testpass123",
            "kem_public_key": "e" * 200,
            "dsa_public_key": "d" * 200,
        },
    )
    assert reg.status_code == 200
    login = client.post(
        "/api/auth/login",
        json={"user_id": "TestUser", "password": "testpass123"},
    )
    assert login.status_code == 200
    data = login.json()
    assert "token" in data
    assert data.get("user_id") == "TestUser"


def test_login_wrong_password_returns_401(client: TestClient):
    """正确用户、错误密码应返回 401。"""
    client.post(
        "/api/auth/register",
        json={
            "user_id": "Alice",
            "password": "right",
            "kem_public_key": "k" * 200,
            "dsa_public_key": "d" * 200,
        },
    )
    r = client.post(
        "/api/auth/login",
        json={"user_id": "Alice", "password": "wrong"},
    )
    assert r.status_code == 401


def test_list_with_valid_token_but_other_user_returns_403(client: TestClient):
    """已登录用户 A 请求 B 的收件箱应返回 403。"""
    client.post(
        "/api/auth/register",
        json={
            "user_id": "Alice",
            "password": "pass",
            "kem_public_key": "k" * 200,
            "dsa_public_key": "d" * 200,
        },
    )
    login = client.post("/api/auth/login", json={"user_id": "Alice", "password": "pass"})
    token = login.json()["token"]
    # 请求 Bob 的收件箱（当前用户是 Alice）
    r = client.get(
        "/files/list/Bob",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 403
