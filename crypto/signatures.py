"""The signed result envelope: construction, signing, and verification.

Protocol (see docs/cryptographic-protocol.md for the full rationale):

    envelope = {task_id, worker_id, model_version, input_commitment,
                result_hash, timestamp, nonce}
    sigma    = Ed25519_Sign(sk_worker, canonical_bytes(envelope))

Verification is a *conjunction* of independent checks and returns a structured result rather than
a bare bool, so that the verifier can record exactly which check failed for the audit trail and
for the experiment metrics.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .hashing import canonical_bytes, constant_time_equals, hash_object
from .keys import KeyPair, load_public_key

__all__ = [
    "ResultEnvelope",
    "SignedResult",
    "VerificationResult",
    "FailureReason",
    "build_envelope",
    "sign_envelope",
    "verify_signed_result",
]

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")


class FailureReason:
    NONE = "none"
    MALFORMED = "malformed_envelope"
    UNKNOWN_WORKER = "unknown_worker_key"
    BAD_SIGNATURE = "invalid_signature"
    HASH_MISMATCH = "result_hash_mismatch"
    INPUT_MISMATCH = "input_commitment_mismatch"
    TASK_MISMATCH = "task_id_mismatch"
    STALE = "stale_timestamp"
    REPLAY = "nonce_replay"
    MODEL_NOT_ALLOWED = "model_version_not_allowed"


@dataclass(frozen=True)
class ResultEnvelope:
    """Exactly the fields that are covered by the signature. Order is irrelevant (canonical JSON)."""

    task_id: str
    worker_id: str
    model_version: str
    input_commitment: str
    result_hash: str
    timestamp: str  # RFC3339 UTC
    nonce: str  # 128-bit hex

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    def signing_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())

    def validate_shape(self) -> str | None:
        """Structural validation before any crypto work. Returns a FailureReason or None."""
        if not self.task_id or not self.worker_id or not self.model_version:
            return FailureReason.MALFORMED
        if not _HEX64.match(self.result_hash or ""):
            return FailureReason.MALFORMED
        if not self.input_commitment or len(self.input_commitment) < 32:
            return FailureReason.MALFORMED
        if not _NONCE_RE.match(self.nonce or ""):
            return FailureReason.MALFORMED
        try:
            parse_timestamp(self.timestamp)
        except Exception:
            return FailureReason.MALFORMED
        return None


@dataclass(frozen=True)
class SignedResult:
    """What a worker returns: the envelope, the signature, and the (unhashed) payload."""

    envelope: ResultEnvelope
    signature_hex: str
    payload: Any

    def to_wire(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "signature": self.signature_hex,
            "payload": self.payload,
        }

    @staticmethod
    def from_wire(data: dict[str, Any]) -> SignedResult:
        return SignedResult(
            envelope=ResultEnvelope(**data["envelope"]),
            signature_hex=data["signature"],
            payload=data.get("payload"),
        )


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    reason: str = FailureReason.NONE
    checks: dict[str, bool] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.checks is None:
            object.__setattr__(self, "checks", {})


def parse_timestamp(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return dt.astimezone(UTC)


def now_rfc3339() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def new_nonce() -> str:
    """128 bits from the OS CSPRNG. Collision probability is negligible for our task volumes."""
    return secrets.token_hex(16)


def build_envelope(
    *,
    task_id: str,
    worker_id: str,
    model_version: str,
    input_commitment: str,
    payload: Any,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> ResultEnvelope:
    return ResultEnvelope(
        task_id=task_id,
        worker_id=worker_id,
        model_version=model_version,
        input_commitment=input_commitment,
        result_hash=hash_object(payload, "sha256"),
        timestamp=timestamp or now_rfc3339(),
        nonce=nonce or new_nonce(),
    )


def sign_envelope(keypair: KeyPair, envelope: ResultEnvelope, payload: Any) -> SignedResult:
    sig = keypair.private_key.sign(envelope.signing_bytes())
    return SignedResult(envelope=envelope, signature_hex=sig.hex(), payload=payload)


def verify_signed_result(
    signed: SignedResult,
    *,
    public_key_hex: str | None,
    expected_task_id: str | None = None,
    expected_input_commitment: str | None = None,
    allowed_model_versions: set[str] | None = None,
    max_age_seconds: float | None = 300.0,
    skew_tolerance_seconds: float = 30.0,
    nonce_seen: Any = None,  # callable(worker_id, nonce) -> bool, or None to skip
    now: datetime | None = None,
) -> VerificationResult:
    """Full envelope verification. Each check is independent and recorded.

    Ordering is cheapest-and-most-decisive first: shape, then identity, then signature (the only
    expensive step, ~50 us), then the semantic bindings. We do not short-circuit the semantic
    checks after signature success because we want the full check vector for the audit log.
    """
    checks: dict[str, bool] = {}
    env = signed.envelope

    shape_failure = env.validate_shape()
    checks["shape"] = shape_failure is None
    if shape_failure is not None:
        return VerificationResult(False, shape_failure, checks)

    if not public_key_hex:
        checks["known_worker"] = False
        return VerificationResult(False, FailureReason.UNKNOWN_WORKER, checks)
    try:
        pub: Ed25519PublicKey = load_public_key(public_key_hex)
    except ValueError:
        checks["known_worker"] = False
        return VerificationResult(False, FailureReason.UNKNOWN_WORKER, checks)
    checks["known_worker"] = True

    try:
        pub.verify(bytes.fromhex(signed.signature_hex), env.signing_bytes())
        checks["signature"] = True
    except (InvalidSignature, ValueError):
        checks["signature"] = False
        return VerificationResult(False, FailureReason.BAD_SIGNATURE, checks)

    # Signature is valid => the envelope content is authentic. Now check that the *payload*
    # actually matches the committed hash (a worker could sign envelope A and ship payload B).
    recomputed = hash_object(signed.payload, "sha256")
    checks["result_hash"] = constant_time_equals(recomputed, env.result_hash)
    if not checks["result_hash"]:
        return VerificationResult(False, FailureReason.HASH_MISMATCH, checks)

    if expected_task_id is not None:
        checks["task_binding"] = constant_time_equals(env.task_id, expected_task_id)
        if not checks["task_binding"]:
            return VerificationResult(False, FailureReason.TASK_MISMATCH, checks)

    if expected_input_commitment is not None:
        checks["input_binding"] = constant_time_equals(
            env.input_commitment, expected_input_commitment
        )
        if not checks["input_binding"]:
            return VerificationResult(False, FailureReason.INPUT_MISMATCH, checks)

    if allowed_model_versions is not None:
        checks["model_version"] = env.model_version in allowed_model_versions
        if not checks["model_version"]:
            return VerificationResult(False, FailureReason.MODEL_NOT_ALLOWED, checks)

    if max_age_seconds is not None:
        current = now or datetime.now(UTC)
        age = (current - parse_timestamp(env.timestamp)).total_seconds()
        checks["freshness"] = -skew_tolerance_seconds <= age <= max_age_seconds
        if not checks["freshness"]:
            return VerificationResult(False, FailureReason.STALE, checks)

    if nonce_seen is not None:
        replayed = bool(nonce_seen(env.worker_id, env.nonce))
        checks["nonce_fresh"] = not replayed
        if replayed:
            return VerificationResult(False, FailureReason.REPLAY, checks)

    return VerificationResult(True, FailureReason.NONE, checks)
