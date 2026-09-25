"""Canonical serialisation and hashing primitives.

Design note: every hash in this system is taken over a *canonical* byte encoding so that two
parties independently serialising the same logical object always agree. We use RFC-8785-style
JSON canonicalisation (sorted keys, no insignificant whitespace, UTF-8, no NaN/Inf) rather than
Python's `repr`, which is not stable across versions or types.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

__all__ = [
    "canonical_json",
    "canonical_bytes",
    "sha256_hex",
    "blake2b_hex",
    "hash_object",
    "input_commitment",
    "hmac_hex",
    "constant_time_equals",
]

_DIGESTS = {"sha256": hashlib.sha256, "blake2b": lambda b: hashlib.blake2b(b, digest_size=32)}


def _normalise(obj: Any) -> Any:
    """Reject non-canonicalisable values early instead of hashing something ambiguous."""
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise ValueError("NaN/Infinity cannot be canonically serialised")
        return obj
    if isinstance(obj, (str, int, bool)) or obj is None:
        return obj
    if isinstance(obj, bytes):
        return {"__b64__": obj.hex()}
    if isinstance(obj, dict):
        if not all(isinstance(k, str) for k in obj):
            raise TypeError("canonical JSON requires string keys")
        return {k: _normalise(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_normalise(v) for v in obj]
    # numpy scalars / arrays and similar: go through .tolist() if available
    tolist = getattr(obj, "tolist", None)
    if callable(tolist):
        return _normalise(tolist())
    raise TypeError(f"unsupported type for canonical serialisation: {type(obj)!r}")


def canonical_json(obj: Any) -> str:
    """Deterministic JSON text: sorted keys, compact separators, UTF-8 safe."""
    return json.dumps(
        _normalise(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def canonical_bytes(obj: Any) -> bytes:
    return canonical_json(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blake2b_hex(data: bytes, digest_size: int = 32) -> str:
    return hashlib.blake2b(data, digest_size=digest_size).hexdigest()


def hash_object(obj: Any, algorithm: str = "sha256") -> str:
    """Hash any canonicalisable object. Used for result hashes."""
    if algorithm not in _DIGESTS:
        raise ValueError(f"unsupported algorithm {algorithm!r}; use one of {sorted(_DIGESTS)}")
    return _DIGESTS[algorithm](canonical_bytes(obj)).hexdigest()


def input_commitment(payload: Any) -> str:
    """Commitment to task input. BLAKE2b-256 (fast on CPU, different domain from result hash)."""
    return blake2b_hex(canonical_bytes(payload))


def hmac_hex(key: bytes, data: bytes, algorithm: str = "sha256") -> str:
    import hmac as _hmac

    if not key:
        raise ValueError("HMAC key must not be empty")
    return _hmac.new(key, data, algorithm).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    import hmac as _hmac

    return _hmac.compare_digest(a, b)
