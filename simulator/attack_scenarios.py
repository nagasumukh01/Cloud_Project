"""Catalogue of the ten controlled fault/attack scenarios required by the project brief (§9).

Each scenario is a *declarative description*: which worker behaviours to inject, at what rate, and
what the system is expected to do about it. The simulator turns these into a configured worker
pool; the experiment runner turns them into labelled runs.

SAFETY (brief §9): every scenario is confined to simulated, in-process worker objects created by
this repository. Nothing here touches a real host, a real network, or any third-party service.
There is no code path in this module that can affect anything outside the local process.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class DetectableBy(str, Enum):
    """Which layer is *expected* to catch the scenario. Stating this up front is what lets an
    experiment distinguish 'the mechanism worked' from 'we got lucky'."""

    CRYPTO = "cryptographic_verification"      # signature / hash / freshness / allow-list
    REPLICATION = "replicated_execution"       # only detectable by re-running elsewhere
    AVAILABILITY = "availability_monitoring"   # timeouts, circuit breaker, health checks
    NONE = "not_expected_to_be_detected"       # documented blind spot


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    description: str
    behaviours: tuple[str, ...]
    default_fault_rate: float
    detectable_by: DetectableBy
    expected_signal: str
    threat_ids: tuple[str, ...] = ()
    implemented: bool = True
    notes: str = ""


SCENARIOS: dict[str, Scenario] = {
    "worker_crash": Scenario(
        id="worker_crash",
        name="Worker crash",
        description="Worker raises instead of returning a result, simulating a process death.",
        behaviours=("crash",),
        default_fault_rate=1.0,
        detectable_by=DetectableBy.AVAILABILITY,
        expected_signal="retry on a different worker; circuit breaker opens after N failures",
        threat_ids=(),
    ),
    "slow_worker": Scenario(
        id="slow_worker",
        name="Slow worker",
        description="Worker responds far past its usual service time, simulating a stall or a "
                    "noisy neighbour.",
        behaviours=("slow",),
        default_fault_rate=0.5,
        detectable_by=DetectableBy.AVAILABILITY,
        expected_signal="deadline exceeded -> timeout event, trust penalty, retry elsewhere",
    ),
    "modified_result": Scenario(
        id="modified_result",
        name="Modified inference result (in transit)",
        description="Worker signs the honest envelope, then swaps the payload before sending.",
        behaviours=("tamper_transit",),
        default_fault_rate=0.4,
        detectable_by=DetectableBy.CRYPTO,
        expected_signal="result_hash_mismatch",
        threat_ids=("T1",),
    ),
    "silent_wrong_result": Scenario(
        id="silent_wrong_result",
        name="Silently incorrect result (correctly signed)",
        description="Worker computes a wrong answer and signs it properly. This is the scenario "
                    "cryptography fundamentally cannot catch, and the reason the adaptive "
                    "replication policy exists.",
        behaviours=("tamper_payload",),
        default_fault_rate=0.4,
        detectable_by=DetectableBy.REPLICATION,
        expected_signal="replica disagreement; trust decay on the dissenting worker",
        threat_ids=("T2",),
    ),
    "stale_replay": Scenario(
        id="stale_replay",
        name="Stale result replay",
        description="Worker re-sends a previously valid signed envelope from an earlier task.",
        behaviours=("replay",),
        default_fault_rate=0.5,
        detectable_by=DetectableBy.CRYPTO,
        expected_signal="task_id_mismatch or nonce_replay",
        threat_ids=("T3", "T4"),
    ),
    "backdated_result": Scenario(
        id="backdated_result",
        name="Backdated (stale timestamp) result",
        description="Worker signs a fresh result with a timestamp far outside the freshness window.",
        behaviours=("stale",),
        default_fault_rate=0.5,
        detectable_by=DetectableBy.CRYPTO,
        expected_signal="stale_timestamp",
        threat_ids=("T3",),
    ),
    "inconsistent_metadata": Scenario(
        id="inconsistent_metadata",
        name="Inconsistent metadata / invalid signature",
        description="Signature bytes are corrupted, or envelope metadata is altered after signing.",
        behaviours=("forge_signature",),
        default_fault_rate=0.5,
        detectable_by=DetectableBy.CRYPTO,
        expected_signal="invalid_signature",
        threat_ids=("T5", "T7"),
    ),
    "model_version_mismatch": Scenario(
        id="model_version_mismatch",
        name="Model version mismatch",
        description="Worker claims a model version outside the allow-list (downgrade attempt).",
        behaviours=("wrong_model",),
        default_fault_rate=0.5,
        detectable_by=DetectableBy.CRYPTO,
        expected_signal="model_version_not_allowed",
        threat_ids=("T6",),
    ),
    "high_failure_rate": Scenario(
        id="high_failure_rate",
        name="High worker failure rate",
        description="A large fraction of the pool crashes or stalls simultaneously, testing "
                    "whether the scheduler can still complete the workload (H3).",
        behaviours=("crash", "slow"),
        default_fault_rate=0.8,
        detectable_by=DetectableBy.AVAILABILITY,
        expected_signal="completion rate maintained via retries; circuit breakers open",
    ),
    "mixed_adversary": Scenario(
        id="mixed_adversary",
        name="Mixed adversary",
        description="Faulty workers draw from the full behaviour set, mixing crypto-detectable and "
                    "replication-only attacks. The realistic default for end-to-end evaluation.",
        behaviours=("tamper_payload", "tamper_transit", "forge_signature", "replay",
                    "stale", "wrong_model", "crash"),
        default_fault_rate=0.4,
        detectable_by=DetectableBy.CRYPTO,
        expected_signal="mixture; per-reason breakdown recorded in the audit trail",
        threat_ids=("T1", "T2", "T3", "T5", "T6"),
    ),
    # ---- declared but NOT yet implementable: they need the M3 queue/network layer ----
    "queue_backlog": Scenario(
        id="queue_backlog",
        name="Queue backlog",
        description="Submission rate exceeds service rate, so queue depth grows and the "
                    "queue_load risk feature should respond.",
        behaviours=(),
        default_fault_rate=0.0,
        detectable_by=DetectableBy.AVAILABILITY,
        expected_signal="rising queue depth; policy shifts under load",
        implemented=False,
        notes="Requires the M3 asynchronous queue. The in-process scheduler is synchronous, so "
              "there is no backlog to build. Declared here so the gap is visible, not hidden.",
    ),
    "network_delay": Scenario(
        id="network_delay",
        name="Network delay / partition",
        description="Latency injected on the transport between scheduler and worker.",
        behaviours=(),
        default_fault_rate=0.0,
        detectable_by=DetectableBy.AVAILABILITY,
        expected_signal="timeouts, deadline propagation, circuit breaker",
        implemented=False,
        notes="In M2 workers are in-process, so there is no transport to delay. The `slow` "
              "behaviour approximates the symptom but not the cause. Real injection needs the "
              "M3 containerised workers.",
    ),
}


def get_scenario(scenario_id: str) -> Scenario:
    if scenario_id not in SCENARIOS:
        raise KeyError(f"unknown scenario {scenario_id!r}; available: {sorted(SCENARIOS)}")
    return SCENARIOS[scenario_id]


def implemented_scenarios() -> list[Scenario]:
    return [s for s in SCENARIOS.values() if s.implemented]


def declared_but_unimplemented() -> list[Scenario]:
    return [s for s in SCENARIOS.values() if not s.implemented]


@dataclass
class ScenarioExpectation:
    """What a run of this scenario should show. Used to sanity-check experiment output: if a
    crypto-detectable scenario reports zero integrity detections, the harness is broken."""

    scenario: Scenario
    min_integrity_detections: int = 0
    min_disagreements: int = 0
    max_wrong_results_served: int | None = None
    reasons_expected: tuple[str, ...] = field(default_factory=tuple)


EXPECTATIONS = {
    "modified_result": ScenarioExpectation(
        SCENARIOS["modified_result"], min_integrity_detections=1,
        reasons_expected=("result_hash_mismatch",)),
    "inconsistent_metadata": ScenarioExpectation(
        SCENARIOS["inconsistent_metadata"], min_integrity_detections=1,
        reasons_expected=("invalid_signature",)),
    "backdated_result": ScenarioExpectation(
        SCENARIOS["backdated_result"], min_integrity_detections=1,
        reasons_expected=("stale_timestamp",)),
    "model_version_mismatch": ScenarioExpectation(
        SCENARIOS["model_version_mismatch"], min_integrity_detections=1,
        reasons_expected=("model_version_not_allowed",)),
    "stale_replay": ScenarioExpectation(
        SCENARIOS["stale_replay"], min_integrity_detections=1,
        reasons_expected=("task_id_mismatch", "nonce_replay")),
}
