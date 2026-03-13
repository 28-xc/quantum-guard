from datetime import datetime, timezone

from sqlalchemy import Column, String, Integer, DateTime, BigInteger, Text, CheckConstraint, Index
from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)  # 使用 timezone-aware UTC，避免存储与读取的时区歧义


class UserPublicKey(Base):
    """
    用户公钥与账号表。主键 user_id。存储 ML-KEM 公钥（密钥封装）与 ML-DSA 公钥（签名验证）；
    hashed_password 为 bcrypt 哈希，新注册必填；email 可选，非空时具唯一约束。
    """
    __tablename__ = "user_public_keys"

    user_id = Column(String(64), primary_key=True, index=True)
    kem_public_key = Column(Text, nullable=False)
    dsa_public_key = Column(Text, nullable=False)
    hashed_password = Column(String(255), nullable=True)
    email = Column(String(255), nullable=True, unique=True)
    recovery_blob = Column(Text, nullable=True)  # 旧版：恢复码加密的私钥备份；新版由 mk_encrypted_cloud + asym_priv_encrypted 替代
    mk_encrypted_cloud = Column(Text, nullable=True)  # 新版：恢复公钥加密的 MK，格式 v1|<base64>
    asym_priv_encrypted = Column(Text, nullable=True)  # 新版：MK 加密的 KEM/DSA 私钥包
    password_box_salt = Column(Text, nullable=True)  # 密码盒 KDF 盐（base64）
    mk_encrypted_by_password = Column(Text, nullable=True)  # 密码盒：密码加密的 MK（base64，IV12+密文）
    keys_updated_at = Column(DateTime(timezone=True), nullable=True)  # 密钥备份更新时间，便于排查
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False
    )


class FileMetadata(Base):
    """
    文件元数据表。存储索引与存储路径，密文实体存于磁盘。kem_ciphertext、sender_signature 为 E2E 所需，
    后端仅持久化不参与解密与验签。
    """
    __tablename__ = "file_metadata"

    file_id = Column(String(128), primary_key=True, index=True)
    sender_id = Column(String(64), nullable=False, index=True)
    receiver_id = Column(String(64), nullable=False, index=True)

    total_chunks = Column(Integer, nullable=False)
    global_signature = Column(String(1024), nullable=False)
    storage_path = Column(String(1024), nullable=False)

    kem_ciphertext = Column(Text, nullable=True)
    sender_signature = Column(Text, nullable=True)

    file_name = Column(String(512), nullable=True)
    file_size = Column(BigInteger, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint("total_chunks > 0", name="ck_file_metadata_total_chunks_positive"),
        CheckConstraint("file_size IS NULL OR file_size >= 0", name="ck_file_metadata_file_size_non_negative"),
        Index("ix_file_metadata_receiver_created_at", "receiver_id", "created_at"),
        Index("ix_file_metadata_sender_created_at", "sender_id", "created_at"),
    )