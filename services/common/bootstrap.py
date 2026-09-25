"""Composition root: wires the services together for a given configuration.

Having one place that constructs the object graph is what lets the API, the CLI demo, the tests
and the experiment runner all exercise *the same* system rather than three divergent copies.
"""

from __future__ import annotations

from dataclasses import dataclass

from ml.inference_model import MODEL_VERSION, InferenceModel, get_model
from services.common.config import Settings, get_settings
from services.common.models import init_db
from services.risk_model.risk import get_policy
from services.scheduler.queue import InMemoryQueue
from services.scheduler.registry import WorkerRegistry
from services.scheduler.scheduler import Scheduler
from services.trust_engine.trust import TrustEngine
from services.verifier.verifier import VerificationService
from services.workers.worker import Worker, build_worker_pool


@dataclass
class System:
    settings: Settings
    model: InferenceModel
    registry: WorkerRegistry
    trust: TrustEngine
    verifier: VerificationService
    scheduler: Scheduler
    queue: InMemoryQueue
    workers: list[Worker]
    session_factory: object | None = None

    def reset(self) -> None:
        """Full reset between experiments (brief §9 requires a reset function)."""
        self.verifier.reset()
        self.trust.reset()
        self.queue.reset()
        self.scheduler.reset_stats()
        for w in self.workers:
            self.trust.register(w.worker_id)
            self.registry.release(w.worker_id)


def build_system(
    *,
    n_workers: int = 4,
    n_faulty: int = 0,
    fault_rate: float = 0.3,
    behaviours: tuple[str, ...] = ("tamper_payload",),
    policy: str = "risk_adaptive",
    selection: str = "trust_weighted",
    persist: bool = False,
    record_ground_truth: bool = False,
    settings: Settings | None = None,
    seed: int | None = None,
) -> System:
    st = settings or get_settings()
    seed = st.seed if seed is None else seed

    model = get_model(cache_dir=st.data_dir / "models", seed=seed)
    workers = build_worker_pool(
        n_workers, model, n_faulty=n_faulty, fault_rate=fault_rate,
        behaviours=behaviours, seed=seed,
    )

    registry = WorkerRegistry()
    trust = TrustEngine(
        alpha=st.trust_ewma_alpha, prior=st.trust_prior, quarantine_floor=st.quarantine_trust_floor
    )
    for w in workers:
        registry.register(w, w.capabilities)
        trust.register(w.worker_id)

    verifier = VerificationService(
        public_key_lookup=registry.public_key_of,
        allowed_model_versions={MODEL_VERSION},
        max_age_seconds=st.max_age_seconds,
        skew_tolerance_seconds=st.skew_tolerance_seconds,
    )

    policy_obj = (
        get_policy(policy, tau_low=st.risk_threshold_low, tau_high=st.risk_threshold_high,
                   epsilon=st.exploration_rate, max_replicas=st.max_replicas,
                   quarantine_floor=st.quarantine_trust_floor)
        if policy == "risk_adaptive"
        else get_policy(policy)
    )

    session_factory = init_db(st.database_url) if persist else None

    scheduler = Scheduler(
        registry=registry, verifier=verifier, trust=trust, policy=policy_obj,
        session_factory=session_factory, max_retries=st.max_retries, seed=seed,
        selection=selection, record_ground_truth=record_ground_truth,
    )

    return System(
        settings=st, model=model, registry=registry, trust=trust, verifier=verifier,
        scheduler=scheduler, queue=InMemoryQueue(), workers=workers,
        session_factory=session_factory,
    )
