"""Ed25519 key management for workers.

Private keys are generated on the worker and never travel over the wire, never get logged, and
never reach the API/dashboard layer. `KeyStore` is a local-filesystem adapter used by the
simulation; a production system would use a KMS/HSM, which is out of scope (see THREAT_MODEL.md).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = ["KeyPair", "generate_keypair", "load_public_key", "public_key_hex", "KeyStore"]


@dataclass(frozen=True)
class KeyPair:
    """An Ed25519 keypair plus rotation metadata (key rotation is simulated in M5)."""

    private_key: Ed25519PrivateKey = field(repr=False)
    public_key: Ed25519PublicKey
    key_id: str
    created_at: datetime

    @property
    def public_hex(self) -> str:
        return public_key_hex(self.public_key)

    def private_bytes_pem(self, password: bytes | None = None) -> bytes:
        enc = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )

    def __repr__(self) -> str:  # never leak private material through logs/tracebacks
        return f"KeyPair(key_id={self.key_id!r}, public_hex={self.public_hex[:16]}..., private=<redacted>)"


def public_key_hex(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return raw.hex()


def load_public_key(hex_str: str) -> Ed25519PublicKey:
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError as exc:
        raise ValueError("public key must be hex-encoded") from exc
    if len(raw) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def generate_keypair(key_id: str | None = None) -> KeyPair:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    kid = key_id or f"key-{public_key_hex(pub)[:12]}"
    return KeyPair(
        private_key=priv, public_key=pub, key_id=kid, created_at=datetime.now(UTC)
    )


class KeyStore:
    """Local, on-disk keystore. Directory is created with 0700; files with 0600."""

    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.directory, 0o700)
        except OSError:  # pragma: no cover - platform dependent (e.g. Windows)
            pass

    def _path(self, owner: str) -> Path:
        safe = "".join(c for c in owner if c.isalnum() or c in "-_")
        if not safe:
            raise ValueError("invalid key owner identifier")
        return self.directory / f"{safe}.pem"

    def create(self, owner: str, password: bytes | None = None) -> KeyPair:
        kp = generate_keypair(key_id=owner)
        path = self._path(owner)
        path.write_bytes(kp.private_bytes_pem(password))
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover
            pass
        return kp

    def load(self, owner: str, password: bytes | None = None) -> KeyPair:
        path = self._path(owner)
        if not path.exists():
            raise FileNotFoundError(f"no key for {owner!r} in {self.directory}")
        priv = serialization.load_pem_private_key(path.read_bytes(), password=password)
        if not isinstance(priv, Ed25519PrivateKey):
            raise TypeError("stored key is not Ed25519")
        return KeyPair(
            private_key=priv,
            public_key=priv.public_key(),
            key_id=owner,
            created_at=datetime.fromtimestamp(path.stat().st_mtime, tz=UTC),
        )

    def load_or_create(self, owner: str, password: bytes | None = None) -> KeyPair:
        try:
            return self.load(owner, password)
        except FileNotFoundError:
            return self.create(owner, password)
