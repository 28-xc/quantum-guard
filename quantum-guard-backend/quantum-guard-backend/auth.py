"""
认证模块：邮箱验证码发送、用户注册、登录（返回 JWT 或新设备用 login_challenge_token）。注册时可选绑定邮箱，绑定邮箱时须先通过验证码校验。
"""
import hashlib
import os
import re
import time
import random
from typing import Optional

import secrets as _secrets
from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import UserPublicKey, utcnow
from app.utils.email_sender import send_email

import bcrypt

try:
    import jwt
except ImportError:
    jwt = None

router = APIRouter(prefix="/api/auth", tags=["Auth"])

# 验证码内存存储：key 为邮箱，值 (code, expiry_timestamp)，有效期 5 分钟
_EMAIL_CODES: dict[str, tuple[str, float]] = {}
_CODE_TTL_SECONDS = 300

# 验证码发送限流：同一邮箱 60 秒内仅允许请求一次
_EMAIL_SEND_LAST: dict[str, float] = {}
_SEND_CODE_COOLDOWN_SECONDS = 60

# 登录失败限流：同一 user_id 15 分钟内最多允许 5 次失败，超过返回 429
_LOGIN_FAIL: dict[str, tuple[int, float]] = {}  # user_id -> (count, window_start)
_LOGIN_FAIL_MAX = 5
_LOGIN_FAIL_WINDOW_SECONDS = 900

# 忘记密码恢复用短期 token：token -> (user_id, expiry_timestamp)，5 分钟有效
_RECOVERY_TOKENS: dict[str, tuple[str, float]] = {}
_RECOVERY_TOKEN_TTL = 300

# 新设备登录用短期 challenge token：仅用于发验证码、校验验证码，校验通过后下发 JWT
_LOGIN_CHALLENGE_TOKENS: dict[str, tuple[str, float]] = {}
_LOGIN_CHALLENGE_TTL = 300

USER_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

_JWT_PLACEHOLDER = "your_jwt_secret_placeholder_change_in_production"


def _get_jwt_secret() -> str:
    """返回 JWT 密钥。生产环境（ENV=production 或 PRODUCTION=1）下禁止使用占位符，未配置则抛 500。"""
    secret = (os.environ.get("JWT_SECRET") or "").strip() or _JWT_PLACEHOLDER
    is_production = os.environ.get("ENV") == "production" or os.environ.get("PRODUCTION") == "1"
    if is_production and (not secret or secret == _JWT_PLACEHOLDER):
        raise HTTPException(
            status_code=500,
            detail="生产环境未配置 JWT_SECRET，请在环境变量中设置强随机密钥"
        )
    return secret


def _normalize_password_bytes(password: str) -> bytes:
    """与前端一致：UTF-8 编码后若超过 64 字节则用 SHA-256 摘要（32 字节）作为有效密码，避免 bcrypt 截断导致前后端不一致。"""
    raw = password.encode("utf-8")
    if len(raw) > 64:
        return hashlib.sha256(raw).digest()
    return raw


def _hash_password(password: str) -> str:
    raw = _normalize_password_bytes(password)
    salt = bcrypt.gensalt()
    hashed_bytes = bcrypt.hashpw(raw, salt)
    return hashed_bytes.decode("utf-8")


def _verify_password(plain: str, hashed: str) -> bool:
    raw = _normalize_password_bytes(plain)
    return bcrypt.checkpw(raw, hashed.encode("utf-8"))


def _encode_jwt(user_id: str) -> str:
    if jwt is None:
        raise RuntimeError("PyJWT 未安装，请执行: pip install pyjwt")
    secret = _get_jwt_secret()
    payload = {"sub": user_id, "exp": time.time() + 86400}
    return jwt.encode(payload, secret, algorithm="HS256")


def _decode_jwt(token: str) -> str:
    """解码 JWT 并返回 sub 作为 user_id；无效或过期则抛出 HTTP 401。"""
    if jwt is None:
        raise HTTPException(status_code=501, detail="JWT 未配置")
    secret = _get_jwt_secret()
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        user_id = payload.get("sub")
        if not user_id or not isinstance(user_id, str):
            raise HTTPException(status_code=401, detail="Token 无效")
        return user_id.strip()
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token 已过期")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token 无效")


_http_bearer = HTTPBearer(auto_error=True)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_http_bearer),
    db: Session = Depends(get_db),
) -> UserPublicKey:
    """从 Authorization 头解析 JWT 得到当前用户；仅信任 token，不采信前端传入的身份字段。"""
    user_id = _decode_jwt(credentials.credentials)
    user = db.query(UserPublicKey).filter(UserPublicKey.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="用户不存在")
    return user


def get_current_user_or_challenge(
    credentials: HTTPAuthorizationCredentials = Depends(_http_bearer),
    db: Session = Depends(get_db),
) -> UserPublicKey:
    """新设备登录用：接受 JWT 或 login_challenge_token。先尝试按 challenge 解析，否则按 JWT 解析。用于 send-login-verify-code、verify-login-code。"""
    token = (credentials.credentials or "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="缺少认证信息")
    user = _get_user_by_login_challenge(token, db)
    if user is not None:
        return user
    try:
        user_id = _decode_jwt(token)
        user = db.query(UserPublicKey).filter(UserPublicKey.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="用户不存在")
        return user
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Token 无效或已过期")


# --------------- 请求/响应模型 ---------------


class SendCodeBody(BaseModel):
    email: str = Field(..., min_length=1, max_length=255)
    is_reset: Optional[bool] = Field(False, description="为 true 时表示忘记密码流程用码，仅当该邮箱已绑定某账号时才发送")

    @field_validator("email")
    @classmethod
    def _email_format(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or not v:
            raise ValueError("邮箱格式无效")
        return v


class RegisterBody(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1)
    kem_public_key: str = Field(..., min_length=1)
    dsa_public_key: str = Field(..., min_length=1)
    email: Optional[str] = Field(None, max_length=255)
    code: Optional[str] = Field(None, min_length=6, max_length=6)
    recovery_blob: Optional[str] = Field(None, description="旧版恢复包，可选")
    mk_encrypted_cloud: Optional[str] = Field(None, description="新版：恢复公钥加密的 MK，v1|<base64>")
    asym_priv_encrypted: Optional[str] = Field(None, description="新版：MK 加密的私钥包 base64")
    password_box_salt: Optional[str] = Field(None, description="密码盒 KDF 盐 base64")
    mk_encrypted_by_password: Optional[str] = Field(None, description="密码盒：密码加密的 MK base64")

    @field_validator("user_id")
    @classmethod
    def _user_id(cls, v: str) -> str:
        v = v.strip()
        if not USER_ID_RE.match(v):
            raise ValueError("user_id 非法，仅允许字母/数字/._-，长度 1~64")
        return v

    @field_validator("email")
    @classmethod
    def _email(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v.strip():
            return None
        v = v.strip().lower()
        if "@" not in v:
            raise ValueError("邮箱格式无效")
        return v

    @field_validator("code")
    @classmethod
    def _code_digits(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v.strip():
            return None
        v = v.strip()
        if not v.isdigit() or len(v) != 6:
            raise ValueError("验证码须为 6 位数字")
        return v


class LoginBody(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1)
    is_new_device: bool = Field(default=False, description="True 时仅返回 login_challenge_token，不返回 JWT，用于新设备邮箱验证流程")

    @field_validator("user_id")
    @classmethod
    def _user_id(cls, v: str) -> str:
        v = v.strip()
        if not USER_ID_RE.match(v):
            raise ValueError("user_id 非法")
        return v


class ResetPasswordBody(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    email: str = Field(..., min_length=1, max_length=255)
    code: str = Field(..., min_length=6, max_length=6)
    new_password: str = Field(..., min_length=1)
    new_kem_public_key: str = Field(..., min_length=1)
    new_dsa_public_key: str = Field(..., min_length=1)
    password_box_salt: str = Field(..., min_length=1, description="新密码盒 salt base64，与注册逻辑一致")
    mk_encrypted_by_password: str = Field(..., min_length=1, description="新密码加密的 MK 密文 base64")
    asym_priv_encrypted: str = Field(..., min_length=1, description="MK 加密的私钥包 base64")

    @field_validator("user_id")
    @classmethod
    def _user_id(cls, v: str) -> str:
        v = v.strip()
        if not USER_ID_RE.match(v):
            raise ValueError("user_id 非法")
        return v

    @field_validator("email")
    @classmethod
    def _email_format(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or not v:
            raise ValueError("邮箱格式无效")
        return v

    @field_validator("code")
    @classmethod
    def _code_digits(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or len(v) != 6:
            raise ValueError("验证码须为 6 位数字")
        return v


class ChangePasswordBody(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)
    new_password: str = Field(..., min_length=1)

    @field_validator("code")
    @classmethod
    def _code_digits(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or len(v) != 6:
            raise ValueError("验证码须为 6 位数字")
        return v


class RecoveryBlobBody(BaseModel):
    """登录后上传恢复包，供新设备「用恢复码恢复」使用。"""
    recovery_blob: str = Field(..., min_length=1)


class ForgotPasswordVerifyBody(BaseModel):
    """忘记密码：邮箱+验证码校验，通过后下发短期 recovery_token。"""
    email: str = Field(..., min_length=1, max_length=255)
    code: str = Field(..., min_length=6, max_length=6)

    @field_validator("email")
    @classmethod
    def _email_fmt(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or not v:
            raise ValueError("邮箱格式无效")
        return v

    @field_validator("code")
    @classmethod
    def _code_digits(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or len(v) != 6:
            raise ValueError("验证码须为 6 位数字")
        return v


class ResetPasswordByRecoveryBody(BaseModel):
    """凭 recovery_token 重设密码（助记词恢复后仅更新 bcrypt）。"""
    recovery_token: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=1)


class BindEmailSendBody(BaseModel):
    """登录后绑定/更换邮箱：发送验证码请求体。"""
    email: str = Field(..., min_length=1, max_length=255)

    @field_validator("email")
    @classmethod
    def _bind_email_format(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or not v:
            raise ValueError("邮箱格式无效")
        return v


class BindEmailConfirmBody(BaseModel):
    """登录后绑定/更换邮箱：确认绑定请求体。"""
    email: str = Field(..., min_length=1, max_length=255)
    code: str = Field(..., min_length=6, max_length=6)

    @field_validator("email")
    @classmethod
    def _confirm_email_format(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or not v:
            raise ValueError("邮箱格式无效")
        return v

    @field_validator("code")
    @classmethod
    def _confirm_code_digits(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or len(v) != 6:
            raise ValueError("验证码须为 6 位数字")
        return v


# --------------- 验证码内存操作 ---------------


def _set_code(email: str, code: str) -> None:
    _EMAIL_CODES[email] = (code, time.time() + _CODE_TTL_SECONDS)


def _verify_and_consume_code(email: str, user_code: str) -> bool:
    """
    校验验证码：仅当完全匹配或已过期时删除记录；错误时不删除，保留重试机会。
    返回 True 表示验证通过并已消费该码，False 表示验证失败。
    """
    entry = _EMAIL_CODES.get(email)
    if not entry:
        return False
    code, expiry = entry
    if time.time() > expiry:
        del _EMAIL_CODES[email]
        return False
    if user_code != code:
        return False
    del _EMAIL_CODES[email]
    return True


# --------------- 接口 ---------------


@router.post("/send-code")
def send_code(
    body: SendCodeBody,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """发送 6 位验证码到邮箱，5 分钟有效；同一邮箱 60 秒内仅可请求一次。"""
    now = time.time()
    if body.email in _EMAIL_SEND_LAST and (now - _EMAIL_SEND_LAST[body.email]) < _SEND_CODE_COOLDOWN_SECONDS:
        raise HTTPException(
            status_code=429,
            detail=f"请 {_SEND_CODE_COOLDOWN_SECONDS} 秒后再请求验证码"
        )
    if body.is_reset:
        exists = db.query(UserPublicKey).filter(UserPublicKey.email == body.email).first()
        if not exists:
            raise HTTPException(
                status_code=400,
                detail="该邮箱未绑定任何账号，无法用于重置密码"
            )
    code = str(random.randint(100000, 999999))
    _set_code(body.email, code)
    _EMAIL_SEND_LAST[body.email] = now
    background_tasks.add_task(
        send_email,
        body.email,
        "QuantumGuard 验证码",
        f"您的验证码为：{code}，5 分钟内有效。如非本人操作请忽略。"
    )
    return {"status": "success", "message": "验证码已发送"}


@router.post("/me/send-bind-email-code")
def send_bind_email_code(
    body: BindEmailSendBody,
    background_tasks: BackgroundTasks,
    current_user: UserPublicKey = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    登录后绑定/更换邮箱：向指定邮箱发送 6 位验证码。
    - 若当前账号已绑定邮箱，则视为“更换邮箱”，需确保新邮箱未被其他账号占用。
    - 同一邮箱 60 秒内仅可请求一次验证码。
    """
    email = body.email

    # 禁止将邮箱绑定到多个账号
    other = (
        db.query(UserPublicKey)
        .filter(UserPublicKey.email == email, UserPublicKey.user_id != current_user.user_id)
        .first()
    )
    if other:
        raise HTTPException(status_code=400, detail="该邮箱已被其他账号绑定")

    now = time.time()
    if email in _EMAIL_SEND_LAST and (now - _EMAIL_SEND_LAST[email]) < _SEND_CODE_COOLDOWN_SECONDS:
        raise HTTPException(
            status_code=429,
            detail=f"请 {_SEND_CODE_COOLDOWN_SECONDS} 秒后再请求验证码",
        )

    code = str(random.randint(100000, 999999))
    _set_code(email, code)
    _EMAIL_SEND_LAST[email] = now
    background_tasks.add_task(
        send_email,
        email,
        "QuantumGuard 绑定邮箱验证码",
        f"您正在为账号 {current_user.user_id} 绑定或更换安全邮箱，验证码为：{code}，5 分钟内有效。如非本人操作请忽略。",
    )
    return {"status": "success", "message": "验证码已发送"}


@router.post("/me/confirm-bind-email")
def confirm_bind_email(
    body: BindEmailConfirmBody,
    current_user: UserPublicKey = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    登录后绑定/更换邮箱：校验邮箱+验证码，通过后将该邮箱绑定到当前账号。
    若原先已绑定邮箱，将直接覆盖为新邮箱。
    """
    email = body.email

    # 校验验证码
    if not _verify_and_consume_code(email, body.code):
        raise HTTPException(status_code=400, detail="验证码错误或已过期")

    # 确保该邮箱未被其他账号占用
    other = (
        db.query(UserPublicKey)
        .filter(UserPublicKey.email == email, UserPublicKey.user_id != current_user.user_id)
        .first()
    )
    if other:
        raise HTTPException(status_code=400, detail="该邮箱已被其他账号绑定")

    current_user.email = email
    db.add(current_user)
    db.commit()
    return {"status": "success", "email": email}

@router.post("/register")
def register(body: RegisterBody, db: Session = Depends(get_db)):
    """
    注册：写入 user_id、密码哈希、KEM/DSA 公钥；若提供 email 则校验 code 后写入 email。
    """
    if body.email and (not body.code or not body.code.strip()):
        raise HTTPException(status_code=400, detail="提供 email 时必须提供验证码 code")

    if body.email:
        if not _verify_and_consume_code(body.email, body.code or ""):
            raise HTTPException(status_code=400, detail="验证码错误或已过期")

    hashed = _hash_password(body.password)

    existing = db.query(UserPublicKey).filter(UserPublicKey.user_id == body.user_id).first()
    if existing:
        # 禁止通过“再次注册”覆盖已有账号，防止攻击者用已知用户名抢注并查看原用户的收件箱/发件箱元数据
        raise HTTPException(
            status_code=400,
            detail="该账号已存在，请直接登录；若忘记密码请使用忘记密码（需绑定邮箱）"
        )

    if body.email:
        other = db.query(UserPublicKey).filter(UserPublicKey.email == body.email).first()
        if other:
            raise HTTPException(status_code=400, detail="该邮箱已被其他账号绑定")

    mk_cloud = (body.mk_encrypted_cloud or "").strip() or None
    asym_priv = (body.asym_priv_encrypted or "").strip() or None
    recovery_blob_val = (body.recovery_blob or "").strip() or None
    pw_salt = (body.password_box_salt or "").strip() or None
    mk_by_pw = (body.mk_encrypted_by_password or "").strip() or None
    if mk_cloud and asym_priv:
        recovery_blob_val = None  # 新版优先，不存旧 recovery_blob
    new_user = UserPublicKey(
        user_id=body.user_id,
        kem_public_key=body.kem_public_key,
        dsa_public_key=body.dsa_public_key,
        hashed_password=hashed,
        email=body.email,
        recovery_blob=recovery_blob_val,
        mk_encrypted_cloud=mk_cloud,
        asym_priv_encrypted=asym_priv,
        password_box_salt=pw_salt,
        mk_encrypted_by_password=mk_by_pw,
        keys_updated_at=utcnow() if (mk_cloud and asym_priv) or (pw_salt and mk_by_pw) else None,
    )
    db.add(new_user)
    db.commit()
    return {"status": "success", "message": "注册成功", "user_id": body.user_id}


def _check_login_rate_limit(user_id: str) -> None:
    """登录失败限流：同一 user_id 15 分钟内失败超过 5 次则 429。"""
    now = time.time()
    if user_id in _LOGIN_FAIL:
        count, start = _LOGIN_FAIL[user_id]
        if now - start > _LOGIN_FAIL_WINDOW_SECONDS:
            _LOGIN_FAIL[user_id] = (0, now)
        else:
            if count >= _LOGIN_FAIL_MAX:
                raise HTTPException(
                    status_code=429,
                    detail=f"登录尝试过于频繁，请 {_LOGIN_FAIL_WINDOW_SECONDS // 60} 分钟后再试"
                )


def _record_login_failure(user_id: str) -> None:
    now = time.time()
    if user_id not in _LOGIN_FAIL:
        _LOGIN_FAIL[user_id] = (1, now)
    else:
        count, start = _LOGIN_FAIL[user_id]
        if now - start > _LOGIN_FAIL_WINDOW_SECONDS:
            _LOGIN_FAIL[user_id] = (1, now)
        else:
            _LOGIN_FAIL[user_id] = (count + 1, start)


def _clear_login_failure(user_id: str) -> None:
    _LOGIN_FAIL.pop(user_id, None)


def _create_login_challenge(user_id: str) -> str:
    """新设备登录：生成短期 login_challenge_token，仅用于发验证码、校验验证码，校验通过后再下发 JWT。"""
    token = _secrets.token_urlsafe(32)
    _LOGIN_CHALLENGE_TOKENS[token] = (user_id.strip(), time.time() + _LOGIN_CHALLENGE_TTL)
    return token


def _get_user_by_login_challenge(token: str, db: Session) -> Optional[UserPublicKey]:
    """校验 login_challenge_token 并返回对应用户；不消费 token；无效或过期返回 None。"""
    t = (token or "").strip()
    if not t or t not in _LOGIN_CHALLENGE_TOKENS:
        return None
    user_id, expiry = _LOGIN_CHALLENGE_TOKENS[t]
    if time.time() > expiry:
        del _LOGIN_CHALLENGE_TOKENS[t]
        return None
    return db.query(UserPublicKey).filter(UserPublicKey.user_id == user_id).first()


def _consume_login_challenge(token: str) -> Optional[str]:
    """校验并消费 login_challenge_token，返回 user_id；无效或过期返回 None。"""
    t = (token or "").strip()
    if not t or t not in _LOGIN_CHALLENGE_TOKENS:
        return None
    user_id, expiry = _LOGIN_CHALLENGE_TOKENS.pop(t)
    if time.time() > expiry:
        return None
    return user_id


@router.post("/login")
def login(body: LoginBody, db: Session = Depends(get_db)):
    """登录：校验 user_id 与 password。is_new_device=True 时仅返回 login_challenge_token（不发 JWT）；否则返回 JWT。同一账号 15 分钟内失败超过 5 次将限流。"""
    _check_login_rate_limit(body.user_id)
    row = db.query(UserPublicKey).filter(UserPublicKey.user_id == body.user_id).first()
    if not row:
        _record_login_failure(body.user_id)
        raise HTTPException(status_code=401, detail="用户不存在")
    if not row.hashed_password:
        _record_login_failure(body.user_id)
        raise HTTPException(status_code=401, detail="该账号未设置密码，请先完成带密码的注册")
    if not _verify_password(body.password, row.hashed_password):
        _record_login_failure(body.user_id)
        raise HTTPException(status_code=401, detail="密码错误")
    _clear_login_failure(body.user_id)
    if body.is_new_device:
        # 已绑定邮箱时走双因子：仅返 challenge_token，验证码通过后再发 JWT；未绑定邮箱则无法发验证码，直接下发 JWT 以便拉取 key-backup
        if row.email and (row.email or "").strip():
            challenge_token = _create_login_challenge(body.user_id)
            return {"status": "success", "login_challenge_token": challenge_token, "user_id": body.user_id}
    token = _encode_jwt(body.user_id)
    return {"status": "success", "token": token, "user_id": body.user_id}


@router.get("/recovery-blob")
def get_recovery_blob(
    user_id: str = Query(..., min_length=1, max_length=64),
    db: Session = Depends(get_db),
):
    """获取指定用户的恢复包（恢复码加密的私钥密文）。仅用于新设备「用恢复码恢复」；密文无恢复码无法解密。"""
    uid = user_id.strip()
    if not USER_ID_RE.match(uid):
        raise HTTPException(status_code=400, detail="user_id 非法")
    row = db.query(UserPublicKey).filter(UserPublicKey.user_id == uid).first()
    if not row or not getattr(row, "recovery_blob", None) or not (row.recovery_blob or "").strip():
        raise HTTPException(status_code=404, detail="该账号无恢复数据")
    return {"recovery_blob": row.recovery_blob}


def _create_recovery_token(user_id: str) -> str:
    """生成短期 recovery_token 并存入内存。"""
    token = _secrets.token_urlsafe(32)
    _RECOVERY_TOKENS[token] = (user_id.strip(), time.time() + _RECOVERY_TOKEN_TTL)
    return token


def _get_recovery_token_user_id(token: str) -> Optional[str]:
    """校验 recovery_token 并返回 user_id，不消费；无效或过期返回 None。"""
    t = (token or "").strip()
    if not t or t not in _RECOVERY_TOKENS:
        return None
    user_id, expiry = _RECOVERY_TOKENS[t]
    if time.time() > expiry:
        del _RECOVERY_TOKENS[t]
        return None
    return user_id


def _consume_recovery_token(token: str) -> Optional[str]:
    """校验并消费 recovery_token，返回 user_id；无效或过期返回 None。"""
    t = (token or "").strip()
    if not t or t not in _RECOVERY_TOKENS:
        return None
    user_id, expiry = _RECOVERY_TOKENS.pop(t)
    if time.time() > expiry:
        return None
    return user_id


@router.post("/forgot-password-verify")
def forgot_password_verify(body: ForgotPasswordVerifyBody, db: Session = Depends(get_db)):
    """忘记密码：校验邮箱+验证码，通过后返回短期 recovery_token 与 user_id，用于拉取密钥备份并重设密码。"""
    if not _verify_and_consume_code(body.email, body.code):
        raise HTTPException(status_code=400, detail="验证码错误或已过期")
    user = db.query(UserPublicKey).filter(UserPublicKey.email == body.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="该邮箱未绑定任何账号")
    mk_cloud = (user.mk_encrypted_cloud or "").strip() if getattr(user, "mk_encrypted_cloud", None) else ""
    asym_priv = (user.asym_priv_encrypted or "").strip() if getattr(user, "asym_priv_encrypted", None) else ""
    if not mk_cloud or not asym_priv:
        raise HTTPException(status_code=404, detail="该账号无新版密钥备份，无法通过助记词恢复密码")
    token = _create_recovery_token(user.user_id)
    return {"recovery_token": token, "user_id": user.user_id}


@router.get("/key-backup-by-recovery-token")
def get_key_backup_by_recovery_token(
    recovery_token: Optional[str] = Header(None, alias="Recovery-Token"),
    db: Session = Depends(get_db),
):
    """凭忘记密码流程下发的 Recovery-Token 拉取 mk_encrypted_cloud、asym_priv_encrypted（不消费 token）。"""
    if not recovery_token or not recovery_token.strip():
        raise HTTPException(status_code=401, detail="缺少 Recovery-Token")
    user_id = _get_recovery_token_user_id(recovery_token)
    if not user_id:
        raise HTTPException(status_code=401, detail="恢复凭证无效或已过期，请重新验证邮箱")
    user = db.query(UserPublicKey).filter(UserPublicKey.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    mk_cloud = (user.mk_encrypted_cloud or "").strip() or None
    asym_priv = (user.asym_priv_encrypted or "").strip() or None
    if not mk_cloud or not asym_priv:
        raise HTTPException(status_code=404, detail="该账号无密钥备份")
    return {"mk_encrypted_cloud": mk_cloud, "asym_priv_encrypted": asym_priv}


@router.post("/reset-password-by-recovery")
def reset_password_by_recovery(body: ResetPasswordByRecoveryBody, db: Session = Depends(get_db)):
    """凭 recovery_token 重设密码（助记词恢复后仅更新 bcrypt，不换密钥）。"""
    user_id = _consume_recovery_token(body.recovery_token)
    if not user_id:
        raise HTTPException(status_code=401, detail="恢复凭证无效或已过期，请重新验证邮箱并完成恢复")
    user = db.query(UserPublicKey).filter(UserPublicKey.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    user.hashed_password = _hash_password(body.new_password)
    db.commit()
    return {"status": "success", "message": "密码已重设", "user_id": user.user_id}


@router.post("/reset-password")
def reset_password(body: ResetPasswordBody, db: Session = Depends(get_db)):
    """
    忘记密码（破产重组）：校验账号与绑定邮箱一致后，验证验证码，用新密码与新公钥覆写该用户记录。
    """
    user = db.query(UserPublicKey).filter(UserPublicKey.user_id == body.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    if user.email is None or (user.email or "").strip() == "":
        raise HTTPException(
            status_code=403,
            detail="验证邮箱与该账号绑定的邮箱不匹配，或该账号未绑定邮箱！"
        )
    if (user.email or "").strip().lower() != body.email:
        raise HTTPException(
            status_code=403,
            detail="验证邮箱与该账号绑定的邮箱不匹配，或该账号未绑定邮箱！"
        )

    if not _verify_and_consume_code(body.email, body.code):
        raise HTTPException(status_code=400, detail="验证码错误或已过期")

    hashed = _hash_password(body.new_password)
    pw_salt = (body.password_box_salt or "").strip() or None
    mk_by_pw = (body.mk_encrypted_by_password or "").strip() or None
    asym_priv = (body.asym_priv_encrypted or "").strip() or None
    if not pw_salt or not mk_by_pw or not asym_priv:
        raise HTTPException(
            status_code=400,
            detail="忘记密码（破产重组）必须上传新密码盒与私钥密文，以便在新设备登录"
        )

    user.hashed_password = hashed
    user.kem_public_key = body.new_kem_public_key
    user.dsa_public_key = body.new_dsa_public_key
    user.recovery_blob = None
    user.mk_encrypted_cloud = None
    user.password_box_salt = pw_salt
    user.mk_encrypted_by_password = mk_by_pw
    user.asym_priv_encrypted = asym_priv
    user.keys_updated_at = utcnow()
    db.commit()
    return {"status": "success", "message": "密码与密钥已重置", "user_id": user.user_id}


# --------------- 登录态鉴权：修改密码（仅信任 JWT + 库内邮箱） ---------------


def _mask_email(email: str) -> str:
    """脱敏显示邮箱，如 a***@qq.com"""
    if not email or "@" not in email:
        return "***"
    parts = email.strip().split("@", 1)
    local, domain = parts[0], parts[1]
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"


@router.get("/me", response_model=dict)
def get_me(current_user: UserPublicKey = Depends(get_current_user)):
    """获取当前登录用户信息（含脱敏邮箱），用于修改密码等场景。"""
    email_masked = _mask_email(current_user.email or "") if current_user.email else None
    return {"user_id": current_user.user_id, "email_masked": email_masked}


@router.get("/me/key-backup")
def get_my_key_backup(current_user: UserPublicKey = Depends(get_current_user)):
    """已登录状态下拉取密钥备份。优先返回密码盒字段，兼容 mk_encrypted_cloud / asym_priv_encrypted。"""
    asym_priv = (current_user.asym_priv_encrypted or "").strip() or None
    pw_salt = (current_user.password_box_salt or "").strip() or None
    mk_by_pw = (current_user.mk_encrypted_by_password or "").strip() or None
    mk_cloud = (current_user.mk_encrypted_cloud or "").strip() or None
    if not asym_priv:
        raise HTTPException(status_code=404, detail="该账号无密钥备份")
    out = {"asym_priv_encrypted": asym_priv}
    if pw_salt and mk_by_pw:
        out["password_box_salt"] = pw_salt
        out["mk_encrypted_by_password"] = mk_by_pw
    if mk_cloud:
        out["mk_encrypted_cloud"] = mk_cloud
    return out


@router.post("/me/recovery-blob")
def upload_my_recovery_blob(
    body: RecoveryBlobBody,
    current_user: UserPublicKey = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """已登录状态下上传恢复包（恢复码加密的私钥备份）。用于补传或更新恢复数据，之后可在新设备「用恢复码恢复」。"""
    blob = (body.recovery_blob or "").strip()
    if not blob:
        raise HTTPException(status_code=400, detail="recovery_blob 不能为空")
    current_user.recovery_blob = blob
    db.commit()
    return {"status": "success", "message": "恢复包已保存"}


@router.post("/send-code-change-password")
def send_code_change_password(
    background_tasks: BackgroundTasks,
    current_user: UserPublicKey = Depends(get_current_user),
):
    """修改密码前向当前用户绑定邮箱发送验证码，不信任前端传入的邮箱。"""
    email = (current_user.email or "").strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="该账号未绑定邮箱，无法修改密码")
    code = str(random.randint(100000, 999999))
    _set_code(email, code)
    background_tasks.add_task(
        send_email,
        email,
        "QuantumGuard 修改密码验证码",
        f"您的验证码为：{code}，5 分钟内有效。如非本人操作请忽略。"
    )
    return {"status": "success", "message": "验证码已发送"}


class VerifyLoginCodeBody(BaseModel):
    """新设备登录：验证绑定邮箱验证码后允许拉取密码盒。"""
    code: str = Field(..., min_length=6, max_length=6)

    @field_validator("code")
    @classmethod
    def _code_digits(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or len(v) != 6:
            raise ValueError("验证码须为 6 位数字")
        return v


@router.post("/me/send-login-verify-code")
def send_login_verify_code(
    background_tasks: BackgroundTasks,
    current_user: UserPublicKey = Depends(get_current_user_or_challenge),
):
    """新设备登录：接受 JWT 或 login_challenge_token。向当前用户绑定邮箱发送验证码，验证通过后可拉取密码盒恢复密钥。"""
    email = (current_user.email or "").strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="该账号未绑定邮箱，无法在新设备恢复，请使用忘记密码重置")
    code = str(random.randint(100000, 999999))
    _set_code(email, code)
    background_tasks.add_task(
        send_email,
        email,
        "QuantumGuard 新设备登录验证码",
        f"您的验证码为：{code}，5 分钟内有效。如非本人操作请忽略。"
    )
    return {"status": "success", "message": "验证码已发送"}


@router.post("/me/verify-login-code")
def verify_login_code(
    body: VerifyLoginCodeBody,
    credentials: HTTPAuthorizationCredentials = Depends(_http_bearer),
    current_user: UserPublicKey = Depends(get_current_user_or_challenge),
):
    """新设备登录：校验当前用户绑定邮箱的验证码，通过后下发 JWT（若本次用的是 login_challenge_token 则消费该 token）。"""
    email = (current_user.email or "").strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="该账号未绑定邮箱")
    if not _verify_and_consume_code(email, body.code):
        raise HTTPException(status_code=400, detail="验证码错误或已过期")
    _consume_login_challenge((credentials.credentials or "").strip())
    token = _encode_jwt(current_user.user_id)
    return {"ok": True, "token": token}


@router.post("/change-password")
def change_password(
    body: ChangePasswordBody,
    current_user: UserPublicKey = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """修改密码：仅信任 JWT 当前用户 + 其绑定邮箱的验证码，绝不信任前端身份字段。"""
    email = (current_user.email or "").strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="该账号未绑定邮箱，无法修改密码")
    if not _verify_and_consume_code(email, body.code):
        raise HTTPException(status_code=400, detail="验证码错误或已过期")
    hashed = _hash_password(body.new_password)
    current_user.hashed_password = hashed
    db.commit()
    return {"status": "success", "message": "密码修改成功，请重新登录"}
