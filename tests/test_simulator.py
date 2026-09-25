"""Tests for the fault/attack simulator, workload generator and report generator."""

import json

import pytest

from simulator.attack_scenarios import (
    EXPECTATIONS,
    SCENARIOS,
    DetectableBy,
    declared_but_unimplemented,
    get_scenario,
    implemented_scenarios,
)
from simulator.fault_injection import FaultInjector
from simulator.workload_generator import SENSITIVITY_MIX, WorkloadGenerator


# --------------------------------------------------------------- scenarios
def test_brief_requires_ten_scenarios_and_we_declare_them_all():
    """The brief lists 10 fault/attack scenarios. All must be declared, even the ones we cannot
    yet implement — an undeclared gap is an invisible gap."""
    assert len(SCENARIOS) >= 10
    assert len(implemented_scenarios()) >= 8
    unimplemented = declared_but_unimplemented()
    assert {s.id for s in unimplemented} == {"queue_backlog", "network_delay"}
    for s in unimplemented:
        assert s.notes, f"{s.id} must explain why it is not implemented"


def test_every_scenario_states_how_it_should_be_detected():
    for s in SCENARIOS.values():
        assert isinstance(s.detectable_by, DetectableBy)
        assert s.expected_signal
        assert 0.0 <= s.default_fault_rate <= 1.0


def test_unknown_scenario_raises():
    with pytest.raises(KeyError):
        get_scenario("no_such_scenario")


def test_unimplemented_scenario_refuses_to_run():
    with pytest.raises(NotImplementedError):
        FaultInjector("queue_backlog")


# --------------------------------------------------------- workload generator
@pytest.mark.parametrize("regime", ["uniform", "bursty", "skewed"])
def test_workload_generator_regimes(regime):
    tasks = WorkloadGenerator(n_tasks=100, regime=regime, seed=3).generate()
    assert len(tasks) == 100
    assert all(t.sensitivity in SENSITIVITY_MIX[regime] for t in tasks)
    assert all(t.inter_arrival_ms >= 0 for t in tasks)
    assert all(len(t.features) == 64 for t in tasks)


def test_workload_generator_is_deterministic():
    a = WorkloadGenerator(n_tasks=50, regime="bursty", seed=9).generate()
    b = WorkloadGenerator(n_tasks=50, regime="bursty", seed=9).generate()
    assert [(t.sensitivity, t.inter_arrival_ms) for t in a] == \
           [(t.sensitivity, t.inter_arrival_ms) for t in b]


def test_workload_generator_seeds_differ():
    a = WorkloadGenerator(n_tasks=50, seed=1).generate()
    b = WorkloadGenerator(n_tasks=50, seed=2).generate()
    assert [t.sensitivity for t in a] != [t.sensitivity for t in b]


def test_skewed_regime_is_actually_skewed():
    tasks = WorkloadGenerator(n_tasks=400, regime="skewed", seed=5).generate()
    low = sum(1 for t in tasks if t.sensitivity == "low")
    high = sum(1 for t in tasks if t.sensitivity == "high")
    assert low > high * 5


def test_bursty_regime_has_long_gaps():
    tasks = WorkloadGenerator(n_tasks=100, regime="bursty", seed=5, burst_size=20).generate()
    assert max(t.inter_arrival_ms for t in tasks) >= 100.0


def test_workload_generator_validates_input():
    with pytest.raises(ValueError):
        WorkloadGenerator(n_tasks=0)
    with pytest.raises(ValueError):
        WorkloadGenerator(n_tasks=10, regime="nonsense")  # type: ignore[arg-type]


def test_workload_summary():
    s = WorkloadGenerator(n_tasks=60, regime="uniform", seed=2).summary()
    assert s["n_tasks"] == 60 and sum(s["sensitivity_counts"].values()) == 60


# --------------------------------------------------------- fault injection
@pytest.mark.parametrize(
    "scenario,expected_reason",
    [
        ("modified_result", "result_hash_mismatch"),
        ("inconsistent_metadata", "invalid_signature"),
        ("backdated_result", "stale_timestamp"),
        ("model_version_mismatch", "model_version_not_allowed"),
    ],
)
def test_crypto_detectable_scenarios_are_detected(scenario, expected_reason):
    """H4: every cryptographically detectable attack must produce its predicted failure reason."""
    inj = FaultInjector(scenario, n_workers=6, n_faulty=2, policy="fixed_1", seed=42)
    run = inj.run(40)
    reasons = run.failure_reasons()
    assert expected_reason in reasons, f"{scenario}: got {reasons}"
    assert run.metrics()["recall"] == 1.0
    assert run.metrics()["wrong_results_served"] == 0.0
    inj.teardown()


def test_replay_scenario_is_rejected():
    inj = FaultInjector("stale_replay", n_workers=6, n_faulty=2, policy="fixed_1", seed=42)
    run = inj.run(40)
    reasons = set(run.failure_reasons())
    assert reasons & {"task_id_mismatch", "nonce_replay", "stale_timestamp"}
    inj.teardown()


def test_silent_wrong_result_is_invisible_to_crypto_but_caught_by_replication():
    """The central claim of the whole project: signatures cannot catch a correctly-signed wrong
    answer, but replication can."""
    no_ver = FaultInjector("silent_wrong_result", n_workers=6, n_faulty=2,
                           policy="no_verification", seed=42).run(40)
    replicated = FaultInjector("silent_wrong_result", n_workers=6, n_faulty=2,
                               policy="fixed_1", seed=42).run(40)
    assert no_ver.failure_reasons() == {}          # crypto sees nothing
    assert no_ver.metrics()["wrong_results_served"] > 0
    assert replicated.metrics()["recall"] > 0.8    # replication sees it
    assert replicated.metrics()["wrong_results_served"] == 0.0


def test_crash_scenario_preserves_completion():
    """H3 smoke: heavy crashing must not stop the workload completing."""
    run = FaultInjector("worker_crash", n_workers=6, n_faulty=2, policy="fixed_1", seed=42).run(30)
    assert run.metrics()["completion_rate"] == 1.0


def test_high_failure_rate_scenario_survives():
    run = FaultInjector("high_failure_rate", n_workers=8, n_faulty=4,
                        policy="risk_adaptive", seed=42).run(30)
    assert run.metrics()["completion_rate"] >= 0.9


def test_mixed_adversary_produces_multiple_failure_modes():
    run = FaultInjector("mixed_adversary", n_workers=8, n_faulty=3,
                        policy="fixed_1", seed=42).run(80)
    assert len(run.failure_reasons()) >= 2


def test_ground_truth_labels_are_produced_and_consistent():
    run = FaultInjector("modified_result", n_workers=6, n_faulty=2,
                        policy="fixed_1", seed=42).run(30)
    assert len(run.labels) == len(run.outcomes) == 30
    c = run.confusion()
    assert c["tp"] + c["fp"] + c["tn"] + c["fn"] == 30
    assert run.corrupt_tasks == c["tp"] + c["fn"]


def test_honest_pool_yields_no_false_positives():
    """A clean pool must not be flagged: the FPR of the mechanism on honest workers is the cost
    an operator pays in wasted verification and unfair trust damage."""
    run = FaultInjector("modified_result", n_workers=6, n_faulty=0,
                        policy="risk_adaptive", seed=42).run(50)
    m = run.metrics()
    assert m["false_positive_rate"] == 0.0
    assert m["wrong_results_served"] == 0.0
    assert run.failure_reasons() == {}


def test_injector_reset_clears_state():
    inj = FaultInjector("modified_result", n_workers=5, n_faulty=1, policy="fixed_1", seed=42)
    inj.run(10)
    assert inj.system is not None
    assert inj.system.scheduler.stats["tasks"] == 10
    inj.reset()
    assert inj.system.scheduler.stats["tasks"] == 0
    assert len(inj.system.verifier.replay_guard) == 0


def test_injector_runs_are_reproducible():
    def trace(seed):
        run = FaultInjector("mixed_adversary", n_workers=6, n_faulty=2,
                            policy="risk_adaptive", seed=seed).run(25)
        return run.confusion(), run.failure_reasons()

    assert trace(77) == trace(77)


def test_injector_validates_configuration():
    with pytest.raises(ValueError):
        FaultInjector("modified_result", n_workers=2, n_faulty=5)


def test_expectations_cover_every_crypto_scenario():
    for s in implemented_scenarios():
        if s.detectable_by is DetectableBy.CRYPTO and s.id != "mixed_adversary":
            assert s.id in EXPECTATIONS, f"{s.id} has no expectation defined"


# --------------------------------------------------------- report generator
def test_report_generator_builds_valid_html(tmp_path):
    from dashboard.generate_report import build

    mve = {
        "experiment_id": "mve-test", "config": {
            "tasks_per_arm": 10, "workers": 4, "faulty_workers": 1, "fault_rate": 0.4,
            "behaviours": ["tamper_payload"], "seeds": 1},
        "environment": {"model_version": "digits-logreg@1.0.0", "model_test_accuracy": 0.97},
        "aggregate": {
            "fixed_3": {"verification_units_per_task": 3.0, "detection_recall": 1.0,
                        "false_positive_rate": 0.0, "undetected_corruption": 0.0,
                        "p95_latency_ms": 40.0, "mean_trust_faulty": 0.2, "mean_trust_honest": 0.9},
            "risk_adaptive": {"verification_units_per_task": 0.1, "detection_recall": 0.8,
                              "false_positive_rate": 0.0, "undetected_corruption": 1.0,
                              "p95_latency_ms": 18.0, "mean_trust_faulty": 0.4,
                              "mean_trust_honest": 0.9}},
    }
    html = build(mve, None)
    assert html.startswith("<!DOCTYPE html>") and html.rstrip().endswith("</html>")
    assert "TrustProof-Cloud" in html
    assert "<script" not in html.lower()          # no JS: renders in a sandboxed preview
    assert "http://" not in html and "cdn" not in html.lower()  # no external assets
    assert "not production measurements" in html


def test_report_never_embeds_key_material(tmp_path):
    """The dashboard must never surface private keys (brief §12)."""
    from dashboard.generate_report import build

    html = build(None, None)
    assert "PRIVATE KEY" not in html
    assert "private_key" not in html


def test_report_reflects_failed_hypothesis_honestly():
    from dashboard.generate_report import build

    mve = {
        "experiment_id": "x", "config": {"tasks_per_arm": 1, "workers": 1, "faulty_workers": 0,
                                         "fault_rate": 0.0, "behaviours": [], "seeds": 1},
        "environment": {"model_version": "m@1", "model_test_accuracy": 0.9},
        "aggregate": {
            "fixed_3": {"verification_units_per_task": 3.0, "detection_recall": 1.0,
                        "false_positive_rate": 0.0, "undetected_corruption": 0.0,
                        "p95_latency_ms": 1.0, "mean_trust_faulty": 0.0, "mean_trust_honest": 1.0},
            "risk_adaptive": {"verification_units_per_task": 0.1, "detection_recall": 0.5,
                              "false_positive_rate": 0.0, "undetected_corruption": 5.0,
                              "p95_latency_ms": 1.0, "mean_trust_faulty": 0.0,
                              "mean_trust_honest": 1.0}},
    }
    html = build(mve, None)
    assert "half met" in html and "callout bad" in html


def test_experiment_configs_are_valid_json():
    from pathlib import Path

    cfg_dir = Path(__file__).resolve().parents[1] / "experiments" / "configs"
    files = list(cfg_dir.glob("*.json"))
    assert files, "experiment configs must exist"
    for f in files:
        data = json.loads(f.read_text())
        assert "experiment" in data and "description" in data
