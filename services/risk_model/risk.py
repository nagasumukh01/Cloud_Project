"""Risk estimation and the adaptive verification policy.

M2 ships the **formal specification plus the rule/heuristic baseline**. The learned estimator
(cost-sensitive classifier / contextual bandit) arrives at M4-M6 behind the same `RiskEstimator`
interface, so the policy and the experiment harness do not change when it is swapped in. That
ordering is intentional: the brief requires that any ML policy be compared against a simple
baseline, which means the baseline must exist and be measured first.

--------------------------------------------------------------------------------------------
ALGORITHM: RiskAdaptiveVerification
--------------------------------------------------------------------------------------------
INPUT
    f = (trust, anomaly, uncertainty, sensitivity, latency_dev, hist_fail_rate, queue_load)
        all normalised to [0,1]; sensitivity in {low:0.0, medium:0.5, high:1.0}
    theta = (w, tau_low, tau_high, epsilon, R_max)   -- configuration
OUTPUT
    d in {ACCEPT, VERIFY_1, VERIFY_N, RE_EXECUTE, QUARANTINE}, and r in [0,1]

PSEUDOCODE
    r  <- clip( sum_i w_i * f_i , 0, 1)                      # risk score
    r' <- r * (0.5 + 0.5 * sensitivity)                       # sensitivity modulation
    if Bernoulli(epsilon):        return VERIFY_1, r'         # forced exploration (anti-gaming)
    if r' < tau_low:              return ACCEPT, r'
    if r' < tau_high:             return VERIFY_1, r'
    if trust < quarantine_floor:  return QUARANTINE, r'
    n <- min(R_max, 1 + ceil((r' - tau_high)/(1 - tau_high) * (R_max - 1)))
    return VERIFY_N(n), r'

COMPLEXITY
    Time  O(|f|) = O(1) per task (7 multiply-adds + O(1) comparisons).
    Space O(1) per decision; O(W) for worker state, W = number of workers.
    Selecting k disjoint replicas from W workers costs O(W log W) (sort by score); with W <= 64 in
    our experiments this is negligible relative to inference time.

WHY EXPLORATION (epsilon): without it, a strategic worker could behave honestly until its trust is
high and then defect on exactly the tasks the policy would accept unverified (T11). A floor
exploration rate bounds long-run undetected defection at the cost of epsilon * N extra executions.
epsilon is an ablation parameter.

PARAMETER SELECTION: tau_low/tau_high/w defaults below are *initial* values derived from the
cost model in docs/research-methodology.md. They are swept in the M6 ablation study; no threshold
in this file is to be reported as tuned until that sweep has actually been run.
--------------------------------------------------------------------------------------------
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

SENSITIVITY_VALUE = {"low": 0.0, "medium": 0.5, "high": 1.0}


class Decision(str, Enum):
    ACCEPT = "accept"
    VERIFY_1 = "verify_1"
    VERIFY_N = "verify_n"
    RE_EXECUTE = "re_execute"
    QUARANTINE = "quarantine"


@dataclass(frozen=True)
class RiskFeatures:
    """All features are normalised to [0,1]; higher always means *riskier*."""

    trust: float = 0.7           # worker trust (inverted inside the scorer)
    anomaly: float = 0.0         # anomaly-detector score for the worker
    uncertainty: float = 0.0     # normalised predictive entropy of the result
    sensitivity: str = "medium"  # task sensitivity label
    latency_dev: float = 0.0     # |observed - predicted| latency, normalised
    hist_fail_rate: float = 0.0  # worker's historical verification-failure rate
    queue_load: float = 0.0      # queue pressure; raises the cost of verification

    def as_vector(self) -> dict[str, float]:
        return {
            "distrust": 1.0 - _clip01(self.trust),
            "anomaly": _clip01(self.anomaly),
            "uncertainty": _clip01(self.uncertainty),
            "latency_dev": _clip01(self.latency_dev),
            "hist_fail_rate": _clip01(self.hist_fail_rate),
            "queue_load": _clip01(self.queue_load),
        }


def _clip01(x: float) -> float:
    if math.isnan(x):
        return 0.0
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else float(x)


class RiskEstimator(Protocol):
    name: str

    def estimate(self, features: RiskFeatures) -> float: ...


@dataclass
class HeuristicRiskEstimator:
    """Linear, interpretable baseline. Weights sum to 1 so the output is already in [0,1].

    Weight rationale (documented, not arbitrary):
      distrust 0.35      - strongest single predictor in the fault model: defection is persistent
      anomaly 0.25       - independent behavioural signal, correlated but not redundant with trust
      hist_fail_rate 0.20- direct evidence of past verification failures for this worker
      uncertainty 0.10   - model-side risk: low-confidence results are cheaper to get wrong silently
      latency_dev 0.07   - deviation from predicted service time often accompanies misbehaviour
      queue_load 0.03    - small positive term: under load, an unverified error propagates further
    These are priors to be tested, not fitted values. The M6 sweep reports sensitivity to them.
    """

    name: str = "heuristic_linear_v1"
    weights: dict[str, float] = field(
        default_factory=lambda: {
            "distrust": 0.35,
            "anomaly": 0.25,
            "hist_fail_rate": 0.20,
            "uncertainty": 0.10,
            "latency_dev": 0.07,
            "queue_load": 0.03,
        }
    )

    def __post_init__(self) -> None:
        total = sum(self.weights.values())
        if not math.isclose(total, 1.0, abs_tol=1e-6):
            raise ValueError(f"risk weights must sum to 1.0, got {total}")

    def estimate(self, features: RiskFeatures) -> float:
        v = features.as_vector()
        return _clip01(sum(self.weights[k] * v[k] for k in self.weights))


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    risk_score: float
    replicas: int
    rationale: str
    explored: bool = False

    @property
    def cost_units(self) -> float:
        """Execution units consumed *in addition* to the primary attempt."""
        return {
            Decision.ACCEPT: 0.0,
            Decision.VERIFY_1: 1.0,
            Decision.VERIFY_N: float(self.replicas),
            Decision.RE_EXECUTE: 1.0,
            Decision.QUARANTINE: 1.0,
        }[self.decision]


class VerificationPolicy(Protocol):
    name: str

    def decide(self, features: RiskFeatures) -> PolicyDecision: ...


@dataclass
class RiskAdaptivePolicy:
    """The proposed mechanism. See module docstring for the formal spec."""

    estimator: RiskEstimator = field(default_factory=HeuristicRiskEstimator)
    tau_low: float = 0.25
    tau_high: float = 0.60
    epsilon: float = 0.05
    max_replicas: int = 3
    quarantine_floor: float = 0.25
    rng: random.Random = field(default_factory=lambda: random.Random(42), repr=False)
    name: str = "risk_adaptive"

    def __post_init__(self) -> None:
        if not 0.0 <= self.tau_low <= self.tau_high <= 1.0:
            raise ValueError("require 0 <= tau_low <= tau_high <= 1")
        if not 0.0 <= self.epsilon <= 1.0:
            raise ValueError("epsilon must be in [0,1]")
        if self.max_replicas < 1:
            raise ValueError("max_replicas must be >= 1")

    def decide(self, features: RiskFeatures) -> PolicyDecision:
        raw = self.estimator.estimate(features)
        s = SENSITIVITY_VALUE.get(features.sensitivity, 0.5)
        risk = _clip01(raw * (0.5 + 0.5 * s))

        if self.epsilon > 0 and self.rng.random() < self.epsilon:
            return PolicyDecision(
                Decision.VERIFY_1, risk, 1, "forced exploration sample (anti-gaming floor)", True
            )
        if risk < self.tau_low:
            return PolicyDecision(Decision.ACCEPT, risk, 0, f"risk {risk:.3f} < tau_low {self.tau_low}")
        if risk < self.tau_high:
            return PolicyDecision(
                Decision.VERIFY_1, risk, 1, f"tau_low <= risk {risk:.3f} < tau_high {self.tau_high}"
            )
        if features.trust < self.quarantine_floor:
            return PolicyDecision(
                Decision.QUARANTINE, risk, 1,
                f"trust {features.trust:.3f} below floor {self.quarantine_floor}: re-run elsewhere",
            )
        span = max(1e-9, 1.0 - self.tau_high)
        n = 1 + math.ceil((risk - self.tau_high) / span * (self.max_replicas - 1))
        n = int(min(self.max_replicas, max(1, n)))
        return PolicyDecision(Decision.VERIFY_N, risk, n, f"high risk {risk:.3f}: {n} replicas")


# ---------------------------------------------------------------------------
# Baseline policies (brief §10 requires all of these as comparison arms)
# ---------------------------------------------------------------------------


@dataclass
class NoVerificationPolicy:
    name: str = "no_verification"

    def decide(self, features: RiskFeatures) -> PolicyDecision:
        return PolicyDecision(Decision.ACCEPT, 0.0, 0, "baseline: accept everything")


@dataclass
class FixedReplicationPolicy:
    """Always verify with exactly `replicas` independent executions."""

    replicas: int = 1
    name: str = ""

    def __post_init__(self) -> None:
        if self.replicas < 1:
            raise ValueError("replicas must be >= 1")
        self.name = self.name or f"fixed_replication_{self.replicas}"

    def decide(self, features: RiskFeatures) -> PolicyDecision:
        d = Decision.VERIFY_1 if self.replicas == 1 else Decision.VERIFY_N
        return PolicyDecision(d, 0.0, self.replicas, f"baseline: always {self.replicas} replica(s)")


@dataclass
class RandomVerificationPolicy:
    """Verify a fixed random fraction of tasks (BOINC-style spot checking)."""

    rate: float = 0.3
    rng: random.Random = field(default_factory=lambda: random.Random(7), repr=False)
    name: str = "random_spotcheck"

    def decide(self, features: RiskFeatures) -> PolicyDecision:
        if self.rng.random() < self.rate:
            return PolicyDecision(Decision.VERIFY_1, 0.0, 1, f"random spot-check p={self.rate}")
        return PolicyDecision(Decision.ACCEPT, 0.0, 0, "random: skip")


@dataclass
class RuleBasedPolicy:
    """Hand-written operational rules, no learned or scored risk. The 'what a sensible engineer
    would write' arm, which the adaptive policy must beat to justify its complexity."""

    trust_threshold: float = 0.5
    name: str = "rule_based"

    def decide(self, features: RiskFeatures) -> PolicyDecision:
        if features.sensitivity == "high":
            return PolicyDecision(Decision.VERIFY_N, 0.0, 2, "rule: high sensitivity -> 2 replicas")
        if features.trust < self.trust_threshold:
            return PolicyDecision(Decision.VERIFY_1, 0.0, 1, "rule: low trust -> 1 replica")
        return PolicyDecision(Decision.ACCEPT, 0.0, 0, "rule: trusted worker -> accept")


POLICY_REGISTRY = {
    "no_verification": NoVerificationPolicy,
    "fixed_1": lambda: FixedReplicationPolicy(1),
    "fixed_3": lambda: FixedReplicationPolicy(3),
    "random_spotcheck": RandomVerificationPolicy,
    "rule_based": RuleBasedPolicy,
    "risk_adaptive": RiskAdaptivePolicy,
}


def get_policy(name: str, **kwargs):
    if name not in POLICY_REGISTRY:
        raise KeyError(f"unknown policy {name!r}; available: {sorted(POLICY_REGISTRY)}")
    factory = POLICY_REGISTRY[name]
    return factory(**kwargs) if kwargs else factory()
