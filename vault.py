"""Fernet 加解密工具与凭据保险库。

- vault.key（默认 vault/vault.key，支持外置路径，600）
- vault_entries 存密文；key=uuid 作为凭据唯一标识
- 指纹：由私钥派生公钥计算 SHA256（列表页仅展示指纹，不显示私钥）
"""
from __future__ import annotations

import base64
import hashlib
import os
import uuid
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec, dsa

import models
from config import get_config

_fernet: Optional[Fernet] = None
_fernet_path: Optional[str] = None


def key_path() -> str:
    return get_config().vault_key_path


def ensure_key(path: str | None = None) -> str:
    """确保 vault.key 存在（不存在则生成），返回路径。"""
    path = path or key_path()
    if not os.path.isfile(path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        key = Fernet.generate_key()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
    else:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return path


def _load_fernet() -> Fernet:
    global _fernet, _fernet_path
    path = key_path()
    if _fernet is not None and _fernet_path == path:
        return _fernet
    ensure_key(path)
    with open(path, "rb") as fh:
        key = fh.read().strip()
    _fernet = Fernet(key)
    _fernet_path = path
    return _fernet


def encrypt(plaintext: bytes) -> bytes:
    return _load_fernet().encrypt(plaintext)


def decrypt(blob: bytes) -> bytes:
    try:
        return _load_fernet().decrypt(blob)
    except InvalidToken as exc:  # pragma: no cover - 依赖具体密钥
        raise ValueError("凭据解密失败：vault.key 不匹配或密文损坏") from exc


def store_secret(conn, plaintext: bytes, name: str = "", note: str = "") -> str:
    """加密并写入 vault_entries，返回凭据 key（uuid）。"""
    key = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO vault_entries (key, enc_blob, name, note, created_at) VALUES (?, ?, ?, ?, ?)",
        (key, encrypt(plaintext), name or "", note or "", models.utcnow()),
    )
    return key


def list_entries(conn=None) -> list[dict]:
    """列出凭据元信息（不含密文）。"""
    own = conn is None
    conn = conn or models.connect()
    try:
        rows = conn.execute(
            "SELECT key, name, note, created_at FROM vault_entries ORDER BY created_at DESC, name ASC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        if own:
            conn.close()


def get_entry(conn, key: str) -> dict | None:
    row = conn.execute("SELECT key, name, note, created_at FROM vault_entries WHERE key=?", (key,)).fetchone()
    return dict(row) if row is not None else None


def update_secret(conn, key: str, plaintext: bytes) -> None:
    """更换同一凭据的私钥密文（uuid 不变，服务器绑定不受影响）。"""
    conn.execute("UPDATE vault_entries SET enc_blob=? WHERE key=?", (encrypt(plaintext), key))


def update_entry(conn, key: str, name: str | None = None, note: str | None = None) -> None:
    sets, params = [], []
    if name is not None:
        sets.append("name=?")
        params.append(name)
    if note is not None:
        sets.append("note=?")
        params.append(note)
    if not sets:
        return
    params.append(key)
    conn.execute(f"UPDATE vault_entries SET {','.join(sets)} WHERE key=?", params)


def get_secret(conn, key: str) -> bytes:
    row = conn.execute("SELECT enc_blob FROM vault_entries WHERE key=?", (key,)).fetchone()
    if row is None:
        raise KeyError(f"凭据不存在: {key}")
    return decrypt(row["enc_blob"])


def delete_secret(conn, key: str) -> None:
    conn.execute("DELETE FROM vault_entries WHERE key=?", (key,))


def fingerprint(private_key_pem: bytes) -> str:
    """由私钥派生公钥，计算 SHA256 指纹（十六进制，冒号分隔）。"""
    last_err: Exception | None = None
    loaders = (
        serialization.load_ssh_private_key,
        serialization.load_pem_private_key,
    )
    key = None
    for loader in loaders:
        try:
            if loader is serialization.load_pem_private_key:
                key = loader(private_key_pem, password=None)
            else:
                key = loader(private_key_pem, password=None)
            break
        except Exception as exc:  # noqa: BLE001
            last_err = exc
    if key is None:
        raise ValueError(f"无法解析私钥：{last_err}")

    if isinstance(key, (ed25519.Ed25519PrivateKey,)):
        pub = key.public_key()
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    elif isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, dsa.DSAPrivateKey)):
        pub = key.public_key()
        raw = pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        pub = key.public_key()
        raw = pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    digest = hashlib.sha256(raw).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def normalize_pem(secret: bytes) -> bytes:
    """补全末尾换行，兼容粘贴时丢失换行。"""
    if not secret.endswith(b"\n"):
        secret += b"\n"
    return secret


__all__ = [
    "key_path",
    "ensure_key",
    "encrypt",
    "decrypt",
    "store_secret",
    "get_secret",
    "delete_secret",
    "fingerprint",
    "normalize_pem",
]
