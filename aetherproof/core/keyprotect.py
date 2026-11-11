"""Signing-key passphrase sealed to the OS user (Windows DPAPI).

Without AETHERPROOF_KEY_PASSPHRASE the private key used to sit on disk unencrypted:
anyone who could read the file could sign payout instructions. On Windows a random
passphrase is now generated, sealed with CryptProtectData (decryptable only by the same
Windows user on the same machine), and the key is encrypted with it. Elsewhere the env
var remains the way to encrypt; status() reports which protection is in force.
"""

import ctypes
import os
import secrets
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Optional

SEALED_NAME = "key_passphrase.dpapi"


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> _Blob:
    buf = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def available() -> bool:
    return sys.platform == "win32"


def _call(fn_name: str, data: bytes) -> bytes:
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    src, out = _blob(data), _Blob()
    fn = getattr(crypt32, fn_name)
    # flags 0x1 = CRYPTPROTECT_UI_FORBIDDEN: never pop a dialog from a server process
    if not fn(ctypes.byref(src), None, None, None, None, 0x1, ctypes.byref(out)):
        raise OSError(f"{fn_name} failed (error {ctypes.GetLastError()})")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def seal(data: bytes) -> bytes:
    return _call("CryptProtectData", data)


def unseal(data: bytes) -> bytes:
    return _call("CryptUnprotectData", data)


def sealed_passphrase(key_dir: Path, create: bool) -> Optional[bytes]:
    """The DPAPI-sealed passphrase for this key dir; created on demand when `create`."""
    if not available():
        return None
    path = Path(key_dir) / SEALED_NAME
    if path.exists():
        return unseal(path.read_bytes())
    if not create:
        return None
    pw = secrets.token_urlsafe(32).encode()
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:  # another process created it first; theirs wins
        return unseal(path.read_bytes())
    with os.fdopen(fd, "wb") as f:
        f.write(seal(pw))
    return pw
