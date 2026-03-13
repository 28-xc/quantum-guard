import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import UserPublicKey

router = APIRouter(prefix="/keys", tags=["Key Exchange"])

USER_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class PublicKeyUpload(BaseModel):
    """E2E 公钥登记：上传用户的 ML-KEM 公钥（密钥封装）与 ML-DSA 公钥（签名验证）；后端仅持久化，不参与加解密。"""
    user_id: str = Field(..., min_length=1, max_length=64)
    kem_public_key: str = Field(..., min_length=1)
    dsa_public_key: str = Field(..., min_length=1)

    @field_validator("user_id")
    @classmethod
    def _validate_user_id(cls, v: str) -> str:
        v = v.strip()
        if not USER_ID_RE.match(v):
            raise ValueError("user_id 非法，仅允许字母/数字/._-，长度 1~64")
        return v

    @field_validator("kem_public_key", "dsa_public_key")
    @classmethod
    def _validate_non_empty(cls, v: str) -> str:
        if not (v and v.strip()):
            raise ValueError("公钥不能为空")
        return v.strip()


@router.post("/upload")
def upload_public_key(data: PublicKeyUpload, db: Session = Depends(get_db)):
    """接收并持久化用户双公钥；不存在则新建，已存在则覆盖；返回是否发生变更。"""
    existing_key: Optional[UserPublicKey] = (
        db.query(UserPublicKey)
        .filter(UserPublicKey.user_id == data.user_id)
        .first()
    )

    changed = False
    if existing_key:
        changed = (
            existing_key.kem_public_key != data.kem_public_key
            or existing_key.dsa_public_key != data.dsa_public_key
        )
        existing_key.kem_public_key = data.kem_public_key
        existing_key.dsa_public_key = data.dsa_public_key
    else:
        new_key = UserPublicKey(
            user_id=data.user_id,
            kem_public_key=data.kem_public_key,
            dsa_public_key=data.dsa_public_key
        )
        db.add(new_key)
        changed = True

    db.commit()

    return {
        "status": "success",
        "message": "Public keys registered (KEM + DSA)",
        "user_id": data.user_id,
        "changed": changed
    }


@router.get("/{user_id}")
def get_public_key(user_id: str, db: Session = Depends(get_db)):
    """
    发送文件前根据接收方 user_id 查询并返回其公钥（KEM + DSA）。
    """
    uid = user_id.strip()
    if not USER_ID_RE.match(uid):
        raise HTTPException(status_code=400, detail="非法 user_id")

    key_record: Optional[UserPublicKey] = (
        db.query(UserPublicKey)
        .filter(UserPublicKey.user_id == uid)
        .first()
    )

    if not key_record:
        raise HTTPException(status_code=404, detail="User public key not found")

    return {
        "user_id": key_record.user_id,
        "kem_public_key": key_record.kem_public_key,
        "dsa_public_key": key_record.dsa_public_key
    }