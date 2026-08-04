from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
from ctypes import wintypes
from pathlib import Path
from typing import Any

from app.config import SECRET_DIR


class CredentialStoreError(RuntimeError):
    pass


def _secret_path(reference: str) -> Path:
    digest = hashlib.sha256(reference.encode("utf-8")).hexdigest()
    return SECRET_DIR / f"{digest}.secret"


if os.name == "nt":
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    def _blob(data: bytes) -> tuple[DATA_BLOB, Any]:
        buffer = ctypes.create_string_buffer(data)
        return DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer

    def _protect(data: bytes) -> bytes:
        in_blob, keepalive = _blob(data)
        out_blob = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptProtectData(  # type: ignore[attr-defined]
            ctypes.byref(in_blob), "YashSec Autopilot", None, None, None, 0, ctypes.byref(out_blob)
        ):
            raise CredentialStoreError("Windows DPAPI failed to protect the credential.")
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)  # type: ignore[attr-defined]

    def _unprotect(data: bytes) -> bytes:
        in_blob, keepalive = _blob(data)
        out_blob = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptUnprotectData(  # type: ignore[attr-defined]
            ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)
        ):
            raise CredentialStoreError("Windows DPAPI could not decrypt the credential for this user.")
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)  # type: ignore[attr-defined]
else:
    def _fernet():
        try:
            from cryptography.fernet import Fernet
        except ImportError as exc:
            raise CredentialStoreError("Install the cryptography package for non-Windows development.") from exc
        key_path = SECRET_DIR / ".development-key"
        if not key_path.exists():
            key_path.write_bytes(Fernet.generate_key())
            try:
                key_path.chmod(0o600)
            except OSError:
                pass
        return Fernet(key_path.read_bytes())

    def _protect(data: bytes) -> bytes:
        return _fernet().encrypt(data)

    def _unprotect(data: bytes) -> bytes:
        return _fernet().decrypt(data)


def save_secret(reference: str, value: str | dict[str, Any]) -> None:
    payload = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    protected = _protect(payload.encode("utf-8"))
    path = _secret_path(reference)
    temporary = path.with_suffix(".tmp")
    temporary.write_bytes(base64.b64encode(protected))
    temporary.replace(path)


def load_secret(reference: str) -> str | None:
    path = _secret_path(reference)
    if not path.exists():
        return None
    try:
        return _unprotect(base64.b64decode(path.read_bytes())).decode("utf-8")
    except Exception as exc:
        raise CredentialStoreError(f"Credential '{reference}' could not be read: {exc}") from exc


def load_secret_json(reference: str) -> dict[str, Any]:
    value = load_secret(reference)
    if not value:
        return {}
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise CredentialStoreError("Stored credential has an invalid format.") from exc
    return payload if isinstance(payload, dict) else {}


def delete_secret(reference: str) -> None:
    path = _secret_path(reference)
    if path.exists():
        path.unlink()
