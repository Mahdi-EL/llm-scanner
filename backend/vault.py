"""Encryption at rest for secrets we must store, such as a scan target's API key.

The key comes from ENCRYPTION_KEY (a Fernet key) if set, otherwise it is
derived from SECRET_KEY. Changing SECRET_KEY without setting ENCRYPTION_KEY
makes previously stored secrets unreadable (decrypt() then raises).
"""
import base64
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import config


def _fernet() -> Fernet:
    raw = os.getenv("ENCRYPTION_KEY")
    if raw:
        return Fernet(raw.encode())
    derived = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b"llmscanner-v1", info=b"stored-secrets",
    ).derive(config.SECRET_KEY.encode())
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return _fernet().encrypt(value.encode()).decode()


def decrypt(token: Optional[str]) -> Optional[str]:
    """Returns the plaintext, or raises ValueError when the key no longer matches."""
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as e:
        raise ValueError("Stored secret can't be decrypted (was SECRET_KEY changed?)") from e
