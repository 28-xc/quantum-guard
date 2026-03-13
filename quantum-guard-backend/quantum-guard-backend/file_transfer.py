import os
import re
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from app.database import get_db, ENCRYPTED_DIR
from app.models import FileMetadata, UserPublicKey
from app.routers.auth import get_current_user

router = APIRouter(prefix="/files", tags=["File Transfer"])

# 与 database 中 ENCRYPTED_DIR 一致，保证路径统一
STORAGE_DIR = ENCRYPTED_DIR

# 🌟 核心修改点：将后端允许的最大物理分块大小放宽到 20MB，给并发大分块留足绝对的余量！
CHUNK_PLAINTEXT_SIZE = 20 * 1024 * 1024
CHUNK_OVERHEAD = 12 + 16
CHUNK_PHYSICAL_SIZE = CHUNK_PLAINTEXT_SIZE + CHUNK_OVERHEAD

# file_id 白名单：仅允许字母、数字及 ._-，长度 8~128，防止路径注入
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")


def _safe_file_id(file_id: str) -> str:
    fid = (file_id or "").strip()
    if not SAFE_ID_RE.match(fid):
        raise HTTPException(status_code=400, detail="非法 file_id")
    return fid


def _safe_storage_path(file_id: str) -> Path:
    """返回单文件 .enc 路径，用于兼容旧版单文件存储；当前主流程使用分块目录。"""
    fid = _safe_file_id(file_id)
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    return STORAGE_DIR / f"{fid}.enc"


def _chunk_dir(file_id: str) -> Path:
    """返回该 file_id 对应的分块存储目录；每块独立文件，顺序错乱或缺失将导致解密失败。"""
    fid = _safe_file_id(file_id)
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    return STORAGE_DIR / fid


@router.post("/upload_chunk")
async def upload_chunk(
    file_id: str = Form(...),
    chunk_index: int = Form(...),
    file: UploadFile = File(...)
):
    if chunk_index < 0:
        raise HTTPException(status_code=400, detail="chunk_index 必须 >= 0")

    chunk_dir = _chunk_dir(file_id)
    chunk_dir.mkdir(parents=True, exist_ok=True)
    chunk_path = chunk_dir / str(chunk_index)

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="上传分块为空")
    if len(content) > CHUNK_PHYSICAL_SIZE:
        raise HTTPException(status_code=400, detail="分块大小异常，超过最大物理块大小")

    chunk_path.write_bytes(content)
    return {"status": "success", "chunk_index": chunk_index, "written": len(content)}


@router.post("/finalize")
def finalize_upload(
    file_id: str = Form(...),
    sender_id: str = Form(...),
    receiver_id: str = Form(...),
    total_chunks: int = Form(...),
    global_signature: str = Form(...),
    kem_ciphertext: Optional[str] = Form(None),
    sender_signature: Optional[str] = Form(None),
    file_name: Optional[str] = Form(None),
    file_size: Optional[int] = Form(None),
    db: Session = Depends(get_db)
):
    fid = _safe_file_id(file_id)

    if not sender_id.strip() or not receiver_id.strip():
        raise HTTPException(status_code=400, detail="sender_id / receiver_id 不能为空")
    if total_chunks <= 0:
        raise HTTPException(status_code=400, detail="total_chunks 必须 > 0")
    if not global_signature.strip():
        raise HTTPException(status_code=400, detail="global_signature 不能为空")

    # 发送方、接收方均须已注册，禁止冒用未注册 user_id
    sender_exists = db.query(UserPublicKey).filter(UserPublicKey.user_id == sender_id.strip()).first()
    if not sender_exists:
        raise HTTPException(
            status_code=400,
            detail="发送方 ID 未注册，请先完成注册后再发送"
        )
    # 接收方也必须已注册（公钥存在）
    receiver_exists = db.query(UserPublicKey).filter(UserPublicKey.user_id == receiver_id.strip()).first()
    if not receiver_exists:
        raise HTTPException(
            status_code=400,
            detail="接收方 ID 未注册，无法向其发送文件"
        )

    chunk_dir = _chunk_dir(fid)
    if not chunk_dir.exists() or not chunk_dir.is_dir():
        raise HTTPException(status_code=404, detail="密文分块目录未能在磁盘生成")
    for i in range(total_chunks):
        if not (chunk_dir / str(i)).exists():
            raise HTTPException(
                status_code=400,
                detail=f"缺少分块 {i}/{total_chunks}，请确保所有分块上传完成后再 finalize"
            )

    exists = db.query(FileMetadata).filter(FileMetadata.file_id == fid).first()
    if exists:
        raise HTTPException(status_code=409, detail="该 file_id 已存在，禁止重复 finalize")

    new_metadata = FileMetadata(
        file_id=fid,
        sender_id=sender_id.strip(),
        receiver_id=receiver_id.strip(),
        total_chunks=total_chunks,
        global_signature=global_signature.strip(),
        storage_path=str(chunk_dir.resolve()),
        kem_ciphertext=(kem_ciphertext or "").strip() or None,
        sender_signature=(sender_signature or "").strip() or None,
        file_name=(file_name or "").strip() or None,
        file_size=file_size if (file_size is not None and file_size >= 0) else None,
    )

    db.add(new_metadata)
    db.commit()

    return {"status": "success", "file_id": fid}


@router.get("/list/{receiver_id}")
def list_receiver_files(
    receiver_id: str,
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: UserPublicKey = Depends(get_current_user),
):
    """收件箱：仅允许查看本人作为接收方的文件列表，须携带有效 JWT 且 receiver_id 与当前用户一致。"""
    rid = receiver_id.strip()
    if not rid:
        raise HTTPException(status_code=400, detail="receiver_id 不能为空")
    if (current_user.user_id or "").strip() != rid:
        raise HTTPException(status_code=403, detail="仅能查看本人的收件箱")

    base = db.query(FileMetadata).filter(FileMetadata.receiver_id == rid)
    total = base.count()
    files = (
        base.order_by(FileMetadata.created_at.desc())
        .offset((page - 1) * size)
        .limit(size)
        .all()
    )

    # 转为可序列化结构，避免 ORM 与 datetime 无法直接 JSON 序列化
    items = [
        {
            "file_id": f.file_id,
            "sender_id": f.sender_id,
            "receiver_id": f.receiver_id,
            "total_chunks": f.total_chunks,
            "global_signature": f.global_signature,
            "kem_ciphertext": getattr(f, "kem_ciphertext", None),
            "sender_signature": getattr(f, "sender_signature", None),
            "file_name": f.file_name,
            "file_size": f.file_size,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in files
    ]
    return {"total": total, "items": items, "page": page, "size": size}


@router.get("/sent")
def list_sent_files(
    current_user: UserPublicKey = Depends(get_current_user),
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """发件箱：当前登录用户作为 sender_id 的已发送列表，倒序分页。"""
    sid = (current_user.user_id or "").strip()
    if not sid:
        raise HTTPException(status_code=400, detail="用户身份无效")

    base = db.query(FileMetadata).filter(FileMetadata.sender_id == sid)
    total = base.count()
    files = (
        base.order_by(FileMetadata.created_at.desc())
        .offset((page - 1) * size)
        .limit(size)
        .all()
    )
    items = [
        {
            "file_id": f.file_id,
            "sender_id": f.sender_id,
            "receiver_id": f.receiver_id,
            "total_chunks": f.total_chunks,
            "global_signature": f.global_signature,
            "kem_ciphertext": getattr(f, "kem_ciphertext", None),
            "sender_signature": getattr(f, "sender_signature", None),
            "file_name": f.file_name,
            "file_size": f.file_size,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in files
    ]
    return {"total": total, "items": items, "page": page, "size": size}


def _read_chunks_in_order(chunk_dir: Path, total_chunks: int) -> bytes:
    """按 chunk_index 0,1,2,... 顺序读取并拼接为完整密文，保证与加密端一致"""
    parts = []
    for i in range(total_chunks):
        chunk_path = chunk_dir / str(i)
        if not chunk_path.is_file():
            raise FileNotFoundError(f"分块 {i} 缺失")
        parts.append(chunk_path.read_bytes())
    return b"".join(parts)


@router.get("/download/{file_id}/chunk/{chunk_index}")
def download_encrypted_chunk(
    file_id: str,
    chunk_index: int,
    db: Session = Depends(get_db),
    current_user: UserPublicKey = Depends(get_current_user),
):
    """按 chunk_index 返回单块密文；仅该文件的接收方（receiver_id 与当前用户一致）可下载。"""
    if chunk_index < 0:
        raise HTTPException(status_code=400, detail="chunk_index 必须 >= 0")
    fid = _safe_file_id(file_id)
    file_record = db.query(FileMetadata).filter(FileMetadata.file_id == fid).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="文件不存在")
    if (file_record.receiver_id or "").strip() != (current_user.user_id or "").strip():
        raise HTTPException(status_code=403, detail="仅接收方可下载该文件")
    total = file_record.total_chunks or 0
    if chunk_index >= total:
        raise HTTPException(status_code=400, detail="chunk_index 超出范围")
    path = Path(file_record.storage_path).resolve()
    if not path.exists() or not path.is_dir():
        raise HTTPException(status_code=404, detail="文件不存在或存储路径无效")
    try:
        path.relative_to(STORAGE_DIR)
    except ValueError:
        raise HTTPException(status_code=400, detail="非法存储路径")
    chunk_path = path / str(chunk_index)
    if not chunk_path.is_file():
        raise HTTPException(status_code=404, detail="分块不存在")
    content = chunk_path.read_bytes()
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{fid}.chunk.{chunk_index}"'},
    )


@router.get("/download/{file_id}")
def download_encrypted_file(file_id: str, db: Session = Depends(get_db)):
    fid = _safe_file_id(file_id)

    file_record = db.query(FileMetadata).filter(FileMetadata.file_id == fid).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="文件不存在")

    path = Path(file_record.storage_path).resolve()
    if not path.exists():
        raise HTTPException(status_code=404, detail="文件不存在或存储路径无效")

    try:
        path.relative_to(STORAGE_DIR)
    except ValueError:
        raise HTTPException(status_code=400, detail="非法存储路径")

    # 新格式：storage_path 为分块目录，按顺序读入并一次性返回（避免流式导致客户端收不全）
    if path.is_dir():
        total = file_record.total_chunks
        if not total or total <= 0:
            raise HTTPException(status_code=500, detail="total_chunks 无效")
        content = _read_chunks_in_order(path, total)
        return Response(
            content=content,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{fid}.enc"'},
        )

    # 兼容旧格式：单文件 .enc
    if not path.is_file():
        raise HTTPException(status_code=404, detail="文件不存在或存储路径无效")
    return FileResponse(
        path=str(path),
        media_type="application/octet-stream",
        filename=f"{fid}.enc",
    )