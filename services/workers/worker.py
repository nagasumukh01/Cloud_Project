"""Worker execution service.

In M2 a worker is an in-process object behind the `ExecutesTasks` protocol. In M3 the same class
is wrapped in a FastAPI app and a container; the scheduler talks to it through an adapter, so no
domain code changes. The important property for the research is that a worker is the *only* holder
of its private key and the *only* party that signs.

`FaultyWorker` is the simulator-controlled subclass. It lives here so the honest path and the
adversarial path share exactly one execution implementation — a faulty worker differs only in what
it does after computing the honest result.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from crypto.keys import KeyPair, generate_keypair
from crypto.signatures import SignedResult, build_envelope, sign_envelope
from ml.inference_model import InferenceModel


class WorkerError(Exception):
    """Raised when a worker fails to produce a result (crash, timeout, refusal)."""


class ExecutesTasks(Protocol):
    worker_id: str
    public_key_hex: str

    def execute(self, task_id: str, features: list[float], input_commitment: str) -> SignedResult: ...


@dataclass
class Worker:
    """An honest worker. Deterministic given the same model and input."""

    worker_id: str
    model: InferenceModel
    keypair: KeyPair = field(default=None, repr=False)  # type: ignore[assignment]
    capabilities: list[str] = field(default_factory=lambda: ["digits_classification"])
    base_latency_ms: float = 8.0
    latency_jitter_ms: float = 4.0
    rng: random.Random = field(default_factory=lambda: random.Random(0), repr=False)

    def __post_init__(self) -> None:
        if self.keypair is None:
            self.keypair = generate_keypair(self.worker_id)
        self.executions = 0

    @property
    def public_key_hex(self) -> str:
        return self.keypair.public_hex

    @property
    def model_version(self) -> str:
        return self.model.version

    # -- execution ---------------------------------------------------------
    def _simulate_latency(self) -> None:
        """Synthetic service time. Real network/compute variance is not reproducible across
        machines, so we model it explicitly and seed it — see docs/limitations.md."""
        delay = max(0.0, self.rng.gauss(self.base_latency_ms, self.latency_jitter_ms)) / 1000.0
        if delay > 0:
            time.sleep(min(delay, 0.05))  # hard cap keeps the test suite fast

    def _compute(self, features: list[float]) -> dict[str, Any]:
        return self.model.predict_with_uncertainty(features).as_payload()

    def execute(self, task_id: str, features: list[float], input_commitment: str) -> SignedResult:
        self._simulate_latency()
        payload = self._compute(features)
        self.executions += 1
        return self._seal(task_id, payload, input_commitment)

    def _seal(
        self,
        task_id: str,
        payload: Any,
        input_commitment: str,
        *,
        model_version: str | None = None,
        timestamp: str | None = None,
        nonce: str | None = None,
    ) -> SignedResult:
        env = build_envelope(
            task_id=task_id,
            worker_id=self.worker_id,
            model_version=model_version or self.model_version,
            input_commitment=input_commitment,
            payload=payload,
            timestamp=timestamp,
            nonce=nonce,
        )
        return sign_envelope(self.keypair, env, payload)


@dataclass
class FaultyWorker(Worker):
    """Simulator-controlled worker. Only ever used against simulated tasks (brief §9).

    Behaviours are mutually exclusive per execution and drawn with probability `fault_rate`:
      * tamper_payload   - return a wrong label but sign it correctly  (T2: crypto cannot catch this)
      * tamper_transit   - keep the signed envelope, mutate the payload (T1: hash mismatch)
      * forge_signature  - flip bytes in the signature                 (T5)
      * replay           - re-send a previously issued signed result   (T3)
      * stale            - sign with a timestamp far in the past       (T3)
      * wrong_model      - claim a different model_version             (T6)
      * crash            - raise WorkerError                           (crash scenario)
      * slow             - sleep past the scheduler deadline           (slow-worker scenario)
    """

    fault_rate: float = 0.0
    behaviours: tuple[str, ...] = ("tamper_payload",)
    slow_factor: float = 30.0
    _last_signed: SignedResult | None = field(default=None, repr=False)

    def execute(self, task_id: str, features: list[float], input_commitment: str) -> SignedResult:
        behaviour = "honest"
        if self.behaviours and self.rng.random() < self.fault_rate:
            behaviour = self.rng.choice(list(self.behaviours))
        self.last_behaviour = behaviour

        if behaviour == "crash":
            raise WorkerError(f"{self.worker_id}: simulated crash")
        if behaviour == "slow":
            time.sleep(min(self.base_latency_ms * self.slow_factor / 1000.0, 0.4))

        self._simulate_latency()
        honest_payload = self._compute(features)
        self.executions += 1

        if behaviour == "tamper_payload":
            bad = dict(honest_payload)
            bad["label"] = (int(bad["label"]) + 1 + self.rng.randrange(9)) % 10
            signed = self._seal(task_id, bad, input_commitment)
        elif behaviour == "tamper_transit":
            signed = self._seal(task_id, honest_payload, input_commitment)
            mutated = dict(honest_payload)
            mutated["label"] = (int(mutated["label"]) + 1) % 10
            signed = SignedResult(signed.envelope, signed.signature_hex, mutated)
        elif behaviour == "forge_signature":
            signed = self._seal(task_id, honest_payload, input_commitment)
            raw = bytearray(bytes.fromhex(signed.signature_hex))
            raw[0] ^= 0xFF
            signed = SignedResult(signed.envelope, raw.hex(), signed.payload)
        elif behaviour == "replay":
            if self._last_signed is not None:
                # Re-send a previously issued, genuinely signed envelope (T3). Its task_id/nonce
                # belong to the earlier task, so the verifier must reject it.
                return self._last_signed
            # No prior envelope to replay yet: behave honestly this round and cache the result so
            # the next replay attempt has something to re-send.
            signed = self._seal(task_id, honest_payload, input_commitment)
            self._last_signed = signed
            self.last_behaviour = "honest"
            return signed
        elif behaviour == "stale":
            signed = self._seal(
                task_id, honest_payload, input_commitment, timestamp="2020-01-01T00:00:00Z"
            )
        elif behaviour == "wrong_model":
            signed = self._seal(
                task_id, honest_payload, input_commitment, model_version="digits-logreg@0.0.1"
            )
        else:
            signed = self._seal(task_id, honest_payload, input_commitment)

        if behaviour in ("honest", "tamper_payload"):
            self._last_signed = signed
        return signed

    def is_tampering_behaviour(self) -> bool:
        """Ground-truth label for the evaluation harness (never exposed to policy code)."""
        return getattr(self, "last_behaviour", "honest") not in ("honest", "slow")


def build_worker_pool(
    n: int,
    model: InferenceModel,
    *,
    n_faulty: int = 0,
    fault_rate: float = 0.3,
    behaviours: tuple[str, ...] = ("tamper_payload",),
    seed: int = 42,
) -> list[Worker]:
    """Deterministic worker pool. Faulty workers occupy the last `n_faulty` slots."""
    if n_faulty > n:
        raise ValueError("n_faulty cannot exceed n")
    rng = random.Random(seed)
    pool: list[Worker] = []
    for i in range(n):
        wid = f"w-{i:02d}"
        wrng = random.Random(rng.randrange(2**31))
        common = dict(
            worker_id=wid,
            model=model,
            base_latency_ms=6.0 + 4.0 * wrng.random(),
            latency_jitter_ms=2.0,
            rng=wrng,
        )
        if i >= n - n_faulty:
            pool.append(FaultyWorker(fault_rate=fault_rate, behaviours=behaviours, **common))
        else:
            pool.append(Worker(**common))
    return pool
