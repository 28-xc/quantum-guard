"""
E2E 零信任传输接口：接收分块及元数据，落盘与落库；后端不解密、不验签，仅负责存储与投递。
"""
import base64
import re
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.database import ENCRYPTED_DIR, get_db
from app.models import FileMetadata, UserPublicKey
from app.routers.auth import get_current_user

router = APIRouter(prefix="/api/transfer", tags=["Transfer (E2E)"])

STORAGE_DIR = ENCRYPTED_DIR

# 单块最大：5MB 明文 + 12 字节 IV + 16 字节 GCM tag
CHUNK_PLAINTEXT_SIZE = 5 * 1024 * 1024
CHUNK_OVERHEAD = 12 + 16
CHUNK_PHYSICAL_SIZE = CHUNK_PLAINTEXT_SIZE + CHUNK_OVERHEAD

# file_id 格式校验，支持 UUID 那种
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")


def _safe_file_id(file_id: str) -> str:
    fid = (file_id or "").strip()
    if not SAFE_ID_RE.match(fid):
        raise HTTPException(status_code=400, detail="非法 file_id")
    return fid


def _chunk_dir(file_id: str) -> Path:
    fid = _safe_file_id(file_id)
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    return STORAGE_DIR / fid


@router.get("/download/{file_id}/meta")
def get_download_meta(
    file_id: str,
    db: Session = Depends(get_db),
    current_user: UserPublicKey = Depends(get_current_user),
):
    """返回指定文件的元数据；仅该文件的接收方可拉取。"""
    fid = _safe_file_id(file_id)
    row = db.query(FileMetadata).filter(FileMetadata.file_id == fid).first()
    if not row:
        raise HTTPException(status_code=404, detail="文件不存在")
    if (row.receiver_id or "").strip() != (current_user.user_id or "").strip():
        raise HTTPException(status_code=403, detail="仅接收方可获取该文件元数据")
    return {
        "file_id": row.file_id,
        "sender_id": row.sender_id,
        "receiver_id": row.receiver_id,
        "kem_ciphertext": getattr(row, "kem_ciphertext", None) or row.global_signature,
        "sender_signature": getattr(row, "sender_signature", None),
        "total_chunks": row.total_chunks,
        "file_name": row.file_name,
        "file_size": row.file_size,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.post("/chunk")
async def receive_chunk(
    file_id: str = Form(...),
    chunk_index: int = Form(...),
    iv: str = Form(...),
    chunk_data: UploadFile = File(..., alias="chunk_data"),
):
    """
    接收前端上传的一个分块：file_id, chunk_index, iv（Base64）, 加密后的 chunk_data。
    以独立文件形式落盘，内容为 iv(12 字节) + chunk_data，便于下载时按序拼接。
    """
    if chunk_index < 0:
        raise HTTPException(status_code=400, detail="chunk_index 必须 >= 0")

    try:
        iv_bytes = base64.standard_b64decode(iv)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"iv 非合法 Base64: {e}") from e

    if len(iv_bytes) != 12:
        raise HTTPException(status_code=400, detail="iv 必须为 12 字节")

    raw = await chunk_data.read()
    if not raw:
        raise HTTPException(status_code=400, detail="chunk_data 不能为空")

    if len(iv_bytes) + len(raw) > CHUNK_PHYSICAL_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"单块总大小不得超过 {CHUNK_PHYSICAL_SIZE} 字节",
        )

    chunk_dir = _chunk_dir(file_id)
    chunk_dir.mkdir(parents=True, exist_ok=True)
    chunk_path = chunk_dir / str(chunk_index)
    chunk_path.write_bytes(iv_bytes + raw)

    return {"status": "success", "chunk_index": chunk_index, "written": len(iv_bytes) + len(raw)}


@router.post("/finalize")
def finalize_transfer(
    file_id: str = Form(...),
    sender_id: str = Form(...),
    receiver_id: str = Form(...),
    kem_ciphertext: str = Form(...),
    sender_signature: str = Form(...),
    total_chunks: int = Form(...),
    file_name: Optional[str] = Form(None),
    file_size: Optional[int] = Form(None),
    db: Session = Depends(get_db),
):
    """
    完成传输：核对分块数量，将元数据写入 file_metadata 表。
    后端不解密、不验签，kem_ciphertext 与 sender_signature 原文存入。
    """
    fid = _safe_file_id(file_id)
    sid = (sender_id or "").strip()
    rid = (receiver_id or "").strip()

    if not sid or not rid:
        raise HTTPException(status_code=400, detail="sender_id / receiver_id 不能为空")
    if total_chunks <= 0:
        raise HTTPException(status_code=400, detail="total_chunks 必须 > 0")
    if not (kem_ciphertext or kem_ciphertext.strip()):
        raise HTTPException(status_code=400, detail="kem_ciphertext 不能为空")
    if not (sender_signature or sender_signature.strip()):
        raise HTTPException(status_code=400, detail="sender_signature 不能为空")

    # 发送方、接收方必须已注册
    if not db.query(UserPublicKey).filter(UserPublicKey.user_id == sid).first():
        raise HTTPException(status_code=400, detail="发送方 ID 未注册，请先完成注册后再发送")
    if not db.query(UserPublicKey).filter(UserPublicKey.user_id == rid).first():
        raise HTTPException(status_code=400, detail="接收方 ID 未注册，无法向其发送文件")

    chunk_dir = _chunk_dir(fid)
    if not chunk_dir.exists() or not chunk_dir.is_dir():
        raise HTTPException(status_code=404, detail="密文分块目录不存在，请先上传全部分块")

    for i in range(total_chunks):
        if not (chunk_dir / str(i)).is_file():
            raise HTTPException(
                status_code=400,
                detail=f"缺少分块 {i}/{total_chunks}，请确保所有分块上传完成后再 finalize",
            )

    if db.query(FileMetadata).filter(FileMetadata.file_id == fid).first():
        raise HTTPException(status_code=409, detail="该 file_id 已存在，禁止重复 finalize")

    kem_clean = kem_ciphertext.strip()
    sig_clean = sender_signature.strip()

    record = FileMetadata(
        file_id=fid,
        sender_id=sid,
        receiver_id=rid,
        total_chunks=total_chunks,
        global_signature=kem_clean,
        storage_path=str(chunk_dir.resolve()),
        kem_ciphertext=kem_clean,
        sender_signature=sig_clean,
        file_name=(file_name or "").strip() or None,
        file_size=file_size if (file_size is not None and file_size >= 0) else None,
    )
    db.add(record)
    db.commit()

    return {"status": "success", "file_id": fid}
