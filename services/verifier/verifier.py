"""Cryptographic Verification Service.

Separates two *different* notions of "verification", which the literature often conflates:

  1. **Integrity verification** (cheap, deterministic, cryptographic): is this envelope authentic,
     bound to this task/input/model, fresh, and consistent with the payload? Cost ~50 us.
  2. **Correctness corroboration** (expensive, probabilistic, replicative): did the worker actually
     compute the right answer? Requires re-execution on other workers. Cost ~= one inference each.

Crypto can only ever answer (1). The adaptive policy exists precisely to ration (2).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from crypto.hashing import canonical_bytes, sha256_hex
from crypto.merkle_tree import MerkleTree
from crypto.replay_protection import ReplayGuard
from crypto.signatures import (
    FailureReason,
    SignedResult,
    VerificationResult,
    parse_timestamp,
    verify_signed_result,
)


@dataclass
class IntegrityOutcome:
    ok: bool
    reason: str
    checks: dict
    latency_ms: float
    envelope_hash: str


@dataclass
class AgreementOutcome:
    agreed: bool
    majority_hash: str | None
    votes: dict[str, int]
    disagreeing_workers: list[str]
    unresolved: bool = False


@dataclass
class VerificationService:
    """Stateless with respect to tasks; holds only the replay guard and the batch accumulator."""

    public_key_lookup: Callable[[str], str | None]
    allowed_model_versions: set[str] | None = None
    max_age_seconds: float = 300.0
    skew_tolerance_seconds: float = 30.0
    replay_guard: ReplayGuard = field(default=None)  # type: ignore[assignment]
    _batch: list[str] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if self.replay_guard is None:
            self.replay_guard = ReplayGuard(
                max_age_seconds=self.max_age_seconds,
                skew_tolerance_seconds=self.skew_tolerance_seconds,
            )

    # -- (1) integrity ------------------------------------------------------
    def check_integrity(
        self,
        signed: SignedResult,
        *,
        expected_task_id: str,
        expected_input_commitment: str,
        register_nonce: bool = True,
    ) -> IntegrityOutcome:
        t0 = time.perf_counter()
        env_hash = sha256_hex(canonical_bytes(signed.envelope.to_dict()))
        pub = self.public_key_lookup(signed.envelope.worker_id)

        res: VerificationResult = verify_signed_result(
            signed,
            public_key_hex=pub,
            expected_task_id=expected_task_id,
            expected_input_commitment=expected_input_commitment,
            allowed_model_versions=self.allowed_model_versions,
            max_age_seconds=self.max_age_seconds,
            skew_tolerance_seconds=self.skew_tolerance_seconds,
        )

        # Replay is checked last and only if everything else passed: we must not burn a nonce on an
        # envelope we are going to reject anyway, otherwise an attacker could grief a worker by
        # pre-registering its nonces.
        if res.ok and register_nonce:
            decision = self.replay_guard.check_and_register(
                signed.envelope.worker_id,
                signed.envelope.nonce,
                parse_timestamp(signed.envelope.timestamp),
            )
            checks = dict(res.checks)
            checks["nonce_fresh"] = decision.accepted
            if not decision.accepted:
                reason = (
                    FailureReason.REPLAY
                    if decision.reason == "replayed_nonce"
                    else FailureReason.STALE
                )
                res = VerificationResult(False, reason, checks)
            else:
                res = VerificationResult(True, FailureReason.NONE, checks)

        if res.ok:
            self._batch.append(env_hash)

        return IntegrityOutcome(
            ok=res.ok,
            reason=res.reason,
            checks=res.checks,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            envelope_hash=env_hash,
        )

    # -- (2) correctness corroboration -------------------------------------
    @staticmethod
    def check_agreement(
        results: Sequence[SignedResult], weights: dict[str, float] | None = None
    ) -> AgreementOutcome:
        """Trust-weighted plurality over result hashes.

        Weighting by trust (rather than one-worker-one-vote) means a cluster of freshly-registered,
        low-trust workers cannot outvote an established one. With uniform weights this reduces to
        plain majority. A tie is reported as `unresolved`, which the scheduler escalates rather
        than guessing.
        """
        if not results:
            return AgreementOutcome(False, None, {}, [], unresolved=True)

        votes: dict[str, float] = {}
        counts: dict[str, int] = {}
        for r in results:
            h = r.envelope.result_hash
            w = (weights or {}).get(r.envelope.worker_id, 1.0)
            votes[h] = votes.get(h, 0.0) + max(w, 1e-6)
            counts[h] = counts.get(h, 0) + 1

        best = max(votes.items(), key=lambda kv: kv[1])
        tied = [h for h, v in votes.items() if abs(v - best[1]) < 1e-9]
        if len(tied) > 1:
            return AgreementOutcome(False, None, counts, [r.envelope.worker_id for r in results], True)

        majority_hash = best[0]
        dissent = [r.envelope.worker_id for r in results if r.envelope.result_hash != majority_hash]
        return AgreementOutcome(
            agreed=len(dissent) == 0, majority_hash=majority_hash, votes=counts,
            disagreeing_workers=dissent,
        )

    # -- batch auditing -----------------------------------------------------
    def batch_size(self) -> int:
        return len(self._batch)

    def seal_batch(self) -> tuple[str, int, MerkleTree]:
        """Close the current batch into a Merkle tree and return (root, size, tree)."""
        tree = MerkleTree.from_hex_digests(self._batch)
        root, size = tree.root, tree.size
        self._batch = []
        return root, size, tree

    def reset(self) -> None:
        self._batch = []
        self.replay_guard.reset()
