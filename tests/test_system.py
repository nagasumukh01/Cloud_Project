"""End-to-end tests: model, workers, registry, trust, policy, scheduler, queue."""

import pytest

from ml.inference_model import MODEL_VERSION, sample_inputs
from services.common.models import TaskStatus, Verdict
from services.risk_model.risk import (
    Decision,
    FixedReplicationPolicy,
    HeuristicRiskEstimator,
    NoVerificationPolicy,
    RiskAdaptivePolicy,
    RiskFeatures,
    RuleBasedPolicy,
    get_policy,
)
from services.scheduler.queue import InMemoryQueue
from services.scheduler.registry import WorkerRegistry
from services.trust_engine.trust import TrustEngine
from services.workers.worker import FaultyWorker, Worker, WorkerError, build_worker_pool


# --------------------------------------------------------------------- ML model
def test_model_trains_and_is_reasonably_accurate(model):
    assert model.n_features == 64
    assert model.test_accuracy is not None and model.test_accuracy > 0.90
    assert model.version == MODEL_VERSION


def test_model_prediction_is_deterministic(model, sample_features):
    a = model.predict_with_uncertainty(sample_features[0]).as_payload()
    b = model.predict_with_uncertainty(sample_features[0]).as_payload()
    assert a == b
    assert 0.0 <= a["entropy"] <= 1.0 and 0.0 <= a["confidence"] <= 1.0


def test_model_rejects_wrong_feature_count(model):
    with pytest.raises(ValueError):
        model.predict_with_uncertainty([1.0, 2.0])


# --------------------------------------------------------------------- workers
def test_honest_workers_agree_bytewise(model, sample_features):
    """Critical property: two honest workers must produce identical result hashes, otherwise
    replica disagreement would measure float noise instead of injected faults."""
    pool = build_worker_pool(3, model, seed=1)
    hashes = {w.execute("t1", sample_features[0], "c" * 64).envelope.result_hash for w in pool}
    assert len(hashes) == 1


def test_worker_signs_verifiably(model, sample_features):
    from crypto.signatures import verify_signed_result

    w = Worker("w-x", model)
    signed = w.execute("t1", sample_features[0], "c" * 64)
    assert verify_signed_result(signed, public_key_hex=w.public_key_hex).ok


def test_each_worker_has_a_distinct_key(model):
    pool = build_worker_pool(5, model, seed=3)
    assert len({w.public_key_hex for w in pool}) == 5


def test_faulty_worker_crash_behaviour(model, sample_features):
    w = FaultyWorker("w-bad", model, fault_rate=1.0, behaviours=("crash",))
    with pytest.raises(WorkerError):
        w.execute("t1", sample_features[0], "c" * 64)


@pytest.mark.parametrize(
    "behaviour", ["tamper_payload", "tamper_transit", "forge_signature", "stale", "wrong_model"]
)
def test_faulty_behaviours_are_reproducible(model, sample_features, behaviour):
    w = FaultyWorker("w-bad", model, fault_rate=1.0, behaviours=(behaviour,))
    signed = w.execute("t1", sample_features[0], "c" * 64)
    assert signed is not None
    assert w.last_behaviour == behaviour
    assert w.is_tampering_behaviour()


def test_build_worker_pool_places_faulty_workers_last(model):
    pool = build_worker_pool(5, model, n_faulty=2, seed=9)
    assert [isinstance(w, FaultyWorker) for w in pool] == [False, False, False, True, True]


# --------------------------------------------------------------------- registry
def test_registry_register_and_lookup(model):
    reg = WorkerRegistry()
    w = Worker("w-1", model)
    rec = reg.register(w)
    assert reg.public_key_of("w-1") == w.public_key_hex
    assert rec.fingerprint == w.public_key_hex[:16] and len(rec.fingerprint) == 16
    assert len(reg.available("digits_classification")) == 1


def test_registry_rejects_silent_key_rebinding(model):
    reg = WorkerRegistry()
    reg.register(Worker("w-1", model))
    with pytest.raises(ValueError):
        reg.register(Worker("w-1", model))  # same id, new keypair


def test_circuit_breaker_opens_and_recovers(model):
    reg = WorkerRegistry(failure_threshold=2, open_seconds=0.05)
    reg.register(Worker("w-1", model))
    reg.record_failure("w-1")
    assert reg.available()
    reg.record_failure("w-1")
    assert not reg.available()  # circuit open
    import time

    time.sleep(0.06)
    assert reg.available()  # half-open probe allowed
    reg.record_success("w-1")
    assert reg.get("w-1").consecutive_failures == 0


def test_quarantine_and_release(model):
    reg = WorkerRegistry()
    reg.register(Worker("w-1", model))
    reg.quarantine("w-1")
    assert not reg.available()
    reg.release("w-1")
    assert reg.available()


def test_unreachable_pruning(model):
    reg = WorkerRegistry(heartbeat_ttl_s=-1)
    reg.register(Worker("w-1", model))
    assert reg.prune_unreachable() == ["w-1"]
    assert not reg.available()


# --------------------------------------------------------------------- trust
def test_trust_starts_at_prior_not_one():
    t = TrustEngine(prior=0.7)
    assert t.score("new-worker") == 0.7


def test_trust_rises_with_success_and_falls_with_failure():
    t = TrustEngine(alpha=0.3)
    for _ in range(20):
        t.record("good", "success")
    for _ in range(20):
        t.record("bad", "integrity_failure")
    assert t.score("good") > 0.95
    assert t.score("bad") < 0.05


def test_integrity_failure_penalised_harder_than_disagreement():
    a, b = TrustEngine(alpha=0.2), TrustEngine(alpha=0.2)
    a.record("w", "integrity_failure")
    b.record("w", "disagreement")
    assert a.score("w") < b.score("w")


def test_trust_is_bounded():
    t = TrustEngine(alpha=0.9)
    for _ in range(50):
        t.record("w", "success")
        t.record("w", "integrity_failure")
    assert 0.0 <= t.score("w") <= 1.0


def test_quarantine_requires_evidence():
    t = TrustEngine(alpha=0.9, quarantine_floor=0.25)
    t.record("w", "integrity_failure")
    assert not t.should_quarantine("w", min_events=5)  # one event is not enough
    for _ in range(5):
        t.record("w", "integrity_failure")
    assert t.should_quarantine("w", min_events=5)


def test_trust_explain_is_transparent_and_caveated():
    t = TrustEngine()
    t.record("w", "success", latency_ms=10)
    e = t.explain("w")
    assert {"trust_score", "events", "successes", "alpha", "note"} <= set(e)
    assert "not proof of intent" in e["note"]


def test_unknown_event_type_rejected():
    with pytest.raises(ValueError):
        TrustEngine().record("w", "nonsense")


# --------------------------------------------------------------------- policy
def test_risk_weights_must_sum_to_one():
    with pytest.raises(ValueError):
        HeuristicRiskEstimator(weights={"distrust": 0.5, "anomaly": 0.2, "hist_fail_rate": 0.1,
                                        "uncertainty": 0.1, "latency_dev": 0.05, "queue_load": 0.01})


def test_risk_score_is_monotonic_in_distrust():
    est = HeuristicRiskEstimator()
    lo = est.estimate(RiskFeatures(trust=0.95))
    hi = est.estimate(RiskFeatures(trust=0.05))
    assert 0.0 <= lo < hi <= 1.0


def test_adaptive_policy_accepts_low_risk():
    p = RiskAdaptivePolicy(epsilon=0.0)
    d = p.decide(RiskFeatures(trust=0.99, sensitivity="low"))
    assert d.decision == Decision.ACCEPT and d.cost_units == 0.0


def test_adaptive_policy_escalates_high_risk():
    p = RiskAdaptivePolicy(epsilon=0.0, quarantine_floor=0.0)
    d = p.decide(RiskFeatures(trust=0.05, anomaly=0.9, hist_fail_rate=0.9,
                              uncertainty=0.8, sensitivity="high"))
    assert d.decision == Decision.VERIFY_N and d.replicas >= 2


def test_adaptive_policy_quarantines_on_floor_breach():
    p = RiskAdaptivePolicy(epsilon=0.0, quarantine_floor=0.3)
    d = p.decide(RiskFeatures(trust=0.02, anomaly=1.0, hist_fail_rate=1.0, sensitivity="high"))
    assert d.decision == Decision.QUARANTINE


def test_sensitivity_modulates_verification():
    p = RiskAdaptivePolicy(epsilon=0.0)
    base = RiskFeatures(trust=0.5, anomaly=0.5)
    low = p.decide(RiskFeatures(**{**base.__dict__, "sensitivity": "low"}))
    high = p.decide(RiskFeatures(**{**base.__dict__, "sensitivity": "high"}))
    assert high.risk_score > low.risk_score
    assert high.cost_units >= low.cost_units


def test_exploration_forces_occasional_verification():
    """Anti-gaming floor (T11): even a perfectly trusted worker must sometimes be checked."""
    p = RiskAdaptivePolicy(epsilon=1.0)
    d = p.decide(RiskFeatures(trust=1.0, sensitivity="low"))
    assert d.decision == Decision.VERIFY_1 and d.explored


def test_exploration_rate_is_approximately_honoured():
    p = RiskAdaptivePolicy(epsilon=0.1)
    f = RiskFeatures(trust=1.0, sensitivity="low")
    explored = sum(p.decide(f).explored for _ in range(4000))
    assert 0.07 < explored / 4000 < 0.13


def test_policy_parameter_validation():
    with pytest.raises(ValueError):
        RiskAdaptivePolicy(tau_low=0.8, tau_high=0.2)
    with pytest.raises(ValueError):
        RiskAdaptivePolicy(epsilon=1.5)
    with pytest.raises(ValueError):
        FixedReplicationPolicy(0)


def test_baseline_policies_behave_as_specified():
    f = RiskFeatures(trust=0.9, sensitivity="low")
    assert NoVerificationPolicy().decide(f).decision == Decision.ACCEPT
    assert FixedReplicationPolicy(3).decide(f).replicas == 3
    assert RuleBasedPolicy().decide(f).decision == Decision.ACCEPT
    assert RuleBasedPolicy().decide(RiskFeatures(trust=0.1)).decision == Decision.VERIFY_1
    assert RuleBasedPolicy().decide(RiskFeatures(trust=0.9, sensitivity="high")).replicas == 2


def test_policy_registry_and_unknown_policy():
    assert get_policy("fixed_3").replicas == 3
    with pytest.raises(KeyError):
        get_policy("does_not_exist")


def test_policy_decisions_are_reproducible_under_seed():
    f = RiskFeatures(trust=0.6, anomaly=0.3)
    a = [RiskAdaptivePolicy(rng=__import__("random").Random(1)).decide(f).decision for _ in range(1)]
    b = [RiskAdaptivePolicy(rng=__import__("random").Random(1)).decide(f).decision for _ in range(1)]
    assert a == b


# --------------------------------------------------------------------- queue
def test_queue_publish_consume_ack():
    q = InMemoryQueue()
    q.publish({"task": 1})
    msg = q.consume()
    assert msg and msg.payload == {"task": 1} and q.in_flight() == 1
    q.ack(msg.message_id)
    assert q.in_flight() == 0 and q.depth() == 0


def test_queue_nack_redelivers_then_dead_letters():
    q = InMemoryQueue(max_deliveries=2)
    q.publish({"task": 1})
    m1 = q.consume()
    q.nack(m1.message_id)
    m2 = q.consume()
    assert m2.attempts == 2
    q.nack(m2.message_id)
    assert len(q.dead_letter) == 1 and q.depth() == 0


def test_queue_reset():
    q = InMemoryQueue()
    q.publish({"a": 1})
    q.reset()
    assert q.depth() == 0


# --------------------------------------------------------------------- scheduler
def test_end_to_end_honest_pool_completes(system, sample_features):
    out = system.scheduler.submit(sample_features[0], sensitivity="low")
    assert out.status == TaskStatus.COMPLETED
    assert out.verdict in (Verdict.ACCEPTED, Verdict.ACCEPTED_AFTER_VERIFICATION)
    assert out.result is not None and "label" in out.result
    assert not out.integrity_failure


def test_scheduler_result_matches_direct_model_output(system, sample_features, model):
    out = system.scheduler.submit(sample_features[1], sensitivity="low")
    assert out.result == model.predict_with_uncertainty(sample_features[1]).as_payload()


def test_integrity_failure_is_caught_and_recovered(model):
    """A worker that mutates the payload after signing must be caught by the hash check, and the
    task must still complete via re-execution on another worker."""
    from services.common.bootstrap import build_system

    sysobj = build_system(n_workers=4, n_faulty=1, fault_rate=1.0,
                          behaviours=("tamper_transit",), policy="risk_adaptive")
    feats = sample_inputs(1, seed=11)[0]
    caught = False
    for _ in range(30):
        out = sysobj.scheduler.submit(feats, sensitivity="high")
        if out.integrity_failure:
            caught = True
            assert "result_hash_mismatch" in out.integrity_failure_reasons
            assert out.status in (TaskStatus.COMPLETED, TaskStatus.REJECTED)
            break
    assert caught, "tampering worker was never selected in 30 tasks (raise attempts or check selection)"


def test_replay_attack_is_detected(model):
    from services.common.bootstrap import build_system

    sysobj = build_system(n_workers=3, n_faulty=1, fault_rate=1.0,
                          behaviours=("replay",), policy="fixed_1")
    feats = sample_inputs(1, seed=13)[0]
    reasons = []
    for _ in range(40):
        out = sysobj.scheduler.submit(feats, sensitivity="high")
        reasons.extend(out.integrity_failure_reasons)
    assert any(r in ("nonce_replay", "result_hash_mismatch", "task_id_mismatch") for r in reasons)


def test_wrong_model_version_is_rejected(model):
    from services.common.bootstrap import build_system

    sysobj = build_system(n_workers=3, n_faulty=1, fault_rate=1.0,
                          behaviours=("wrong_model",), policy="fixed_1")
    feats = sample_inputs(1, seed=17)[0]
    reasons = []
    for _ in range(40):
        reasons.extend(sysobj.scheduler.submit(feats).integrity_failure_reasons)
    assert "model_version_not_allowed" in reasons


def test_crashing_workers_are_survived(model):
    """H3 smoke test: with 2 of 5 workers crashing constantly, tasks must still complete."""
    from services.common.bootstrap import build_system

    sysobj = build_system(n_workers=5, n_faulty=2, fault_rate=1.0,
                          behaviours=("crash",), policy="no_verification")
    feats = sample_inputs(20, seed=19)
    completed = sum(sysobj.scheduler.submit(f).status == TaskStatus.COMPLETED for f in feats)
    assert completed == 20


def test_scheduler_fails_gracefully_with_no_workers(model):
    from services.common.bootstrap import build_system

    sysobj = build_system(n_workers=2, policy="no_verification")
    for w in sysobj.workers:
        sysobj.registry.quarantine(w.worker_id)
    out = sysobj.scheduler.submit(sample_inputs(1, seed=3)[0])
    assert out.status == TaskStatus.FAILED and "no worker available" in out.detail


def test_replicas_are_disjoint_from_primary(system, sample_features):
    sysobj = system
    sysobj.scheduler.policy = FixedReplicationPolicy(2)
    out = sysobj.scheduler.submit(sample_features[0])
    assert len(set(out.executed_by)) == len(out.executed_by)
    assert out.replicas_used == 2


def test_cost_accounting_reflects_replication(system, sample_features):
    sysobj = system
    sysobj.scheduler.policy = NoVerificationPolicy()
    cheap = sysobj.scheduler.submit(sample_features[0]).cost_units
    sysobj.scheduler.policy = FixedReplicationPolicy(3)
    pricey = sysobj.scheduler.submit(sample_features[0]).cost_units
    assert cheap == 1.0 and pricey == 4.0  # primary + 3 replicas


def test_adaptive_policy_costs_less_than_fixed3_on_honest_pool(model):
    """H1 smoke test (not the full experiment): on an all-honest pool the adaptive policy must
    spend strictly fewer verification units than fixed 3-replication."""
    from services.common.bootstrap import build_system

    feats = sample_inputs(40, seed=23)
    costs = {}
    for name in ("risk_adaptive", "fixed_3"):
        sysobj = build_system(n_workers=6, n_faulty=0, policy=name)
        costs[name] = sum(sysobj.scheduler.submit(f, sensitivity="low").cost_units for f in feats)
    assert costs["risk_adaptive"] < costs["fixed_3"]


def test_system_reset_clears_state(system, sample_features):
    system.scheduler.submit(sample_features[0])
    assert system.scheduler.stats["tasks"] == 1
    system.reset()
    assert system.scheduler.stats["tasks"] == 0
    assert len(system.verifier.replay_guard) == 0


def test_merkle_batch_accumulates_verified_envelopes(system, sample_features):
    before = system.verifier.batch_size()
    for f in sample_features:
        system.scheduler.submit(f)
    assert system.verifier.batch_size() > before
    root, size, tree = system.verifier.seal_batch()
    assert size > 0 and len(root) == 64 and tree.size == size
    assert system.verifier.batch_size() == 0
