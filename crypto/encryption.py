"""AES-256-GCM authenticated encryption for local artifacts at rest.

Scope (see THREAT_MODEL.md §7): this protects confidentiality and integrity of files on local disk
against an attacker who does not hold the key. It is NOT privacy from the control plane, NOT
protection of data in use, and NOT a differential-privacy mechanism. No such claims are made.

Key handling: the key comes from the environment (`TPC_ARTIFACT_KEY`, 64 hex chars) or an explicit
argument. Keys are never hardcoded and never written into the repository.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .hashing import canonical_bytes

__all__ = [
    "ArtifactCipher",
    "generate_key",
    "key_from_env",
    "derive_key_from_password",
    "DecryptionError",
]

KEY_BYTES = 32  # AES-256
NONCE_BYTES = 12  # GCM standard
ENV_VAR = "TPC_ARTIFACT_KEY"


class DecryptionError(Exception):
    """Raised when authentication fails: wrong key, wrong AAD, or tampered ciphertext."""


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def key_from_env(var: str = ENV_VAR) -> bytes:
    raw = os.environ.get(var)
    if not raw:
        raise RuntimeError(
            f"{var} is not set. Generate one with: python -c "
            f"\"import os;print(os.urandom(32).hex())\" and export it. Never commit it."
        )
    key = bytes.fromhex(raw)
    if len(key) != KEY_BYTES:
        raise ValueError(f"{var} must be {KEY_BYTES * 2} hex characters (AES-256)")
    return key


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """scrypt KDF. Parameters follow the `cryptography` docs' interactive-use recommendation."""
    if len(salt) < 16:
        raise ValueError("salt must be at least 16 bytes")
    kdf = Scrypt(salt=salt, length=KEY_BYTES, n=2**14, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


@dataclass
class ArtifactCipher:
    """Encrypt/decrypt bytes, JSON objects, and files with AES-256-GCM.

    Wire format: `nonce (12 B) || ciphertext || tag (16 B)`. Associated data (AAD) binds the
    ciphertext to a context string (e.g. the task id) so a blob cannot be silently moved between
    contexts.
    """

    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) != KEY_BYTES:
            raise ValueError(f"key must be {KEY_BYTES} bytes")
        self._aead = AESGCM(self.key)

    def __repr__(self) -> str:
        return "ArtifactCipher(key=<redacted>)"

    @classmethod
    def from_env(cls, var: str = ENV_VAR) -> ArtifactCipher:
        return cls(key_from_env(var))

    def encrypt(self, plaintext: bytes, aad: bytes | None = None) -> bytes:
        nonce = os.urandom(NONCE_BYTES)  # random 96-bit nonce; safe for < 2^32 messages per key
        return nonce + self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, blob: bytes, aad: bytes | None = None) -> bytes:
        if len(blob) < NONCE_BYTES + 16:
            raise DecryptionError("ciphertext too short to be valid")
        nonce, ct = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
        try:
            return self._aead.decrypt(nonce, ct, aad)
        except InvalidTag as exc:
            raise DecryptionError("authentication failed: wrong key, wrong AAD, or tampering") from exc

    def encrypt_object(self, obj: Any, aad: str | None = None) -> bytes:
        return self.encrypt(canonical_bytes(obj), aad.encode() if aad else None)

    def decrypt_object(self, blob: bytes, aad: str | None = None) -> Any:
        import json

        return json.loads(self.decrypt(blob, aad.encode() if aad else None).decode("utf-8"))

    def encrypt_file(self, src: str | Path, dst: str | Path, aad: str | None = None) -> Path:
        dst = Path(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(self.encrypt(Path(src).read_bytes(), aad.encode() if aad else None))
        return dst

    def decrypt_file(self, src: str | Path, dst: str | Path, aad: str | None = None) -> Path:
        dst = Path(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(self.decrypt(Path(src).read_bytes(), aad.encode() if aad else None))
        return dst
