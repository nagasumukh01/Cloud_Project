"""Task Manager / Scheduler — the orchestration core.

Responsibilities: worker selection, primary execution, integrity verification, adaptive
verification decision, replica fan-out, agreement, retries, trust updates, and persistence of the
audit trail.

M2 runs this synchronously in-process. The queue abstraction (`TaskQueue`) is declared in
`services/scheduler/queue.py` and the Redis Streams adapter lands in M3; the orchestration logic
below is written against worker *handles* and does not assume co-location.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any

from crypto.hashing import canonical_json, input_commitment
from crypto.signatures import SignedResult
from services.common.models import (
    Attempt,
    GroundTruth,
    SignatureRecord,
    Task,
    TaskStatus,
    TrustEvent,
    Verdict,
    VerificationRecord,
    new_id,
    utcnow,
)
from services.common.models import (
    Worker as WorkerRow,
)
from services.risk_model.risk import Decision, PolicyDecision, RiskFeatures
from services.scheduler.registry import WorkerRecord, WorkerRegistry
from services.trust_engine.trust import TrustEngine
from services.verifier.verifier import VerificationService
from services.workers.worker import FaultyWorker, WorkerError


@dataclass
class TaskOutcome:
    task_id: str
    status: TaskStatus
    verdict: Verdict
    result: dict | None
    executed_by: list[str]
    risk_score: float
    decision: str
    replicas_used: int
    cost_units: float
    latency_ms: float
    verification_latency_ms: float
    integrity_failure: bool
    integrity_failure_reasons: list[str] = field(default_factory=list)
    detail: str = ""


class Scheduler:
    def __init__(
        self,
        *,
        registry: WorkerRegistry,
        verifier: VerificationService,
        trust: TrustEngine,
        policy,
        session_factory=None,
        max_retries: int = 2,
        seed: int = 42,
        selection: str = "trust_weighted",
        record_ground_truth: bool = False,
    ):
        self.registry = registry
        self.verifier = verifier
        self.trust = trust
        self.policy = policy
        self.session_factory = session_factory
        self.max_retries = max_retries
        self.rng = random.Random(seed)
        self.selection = selection
        self.record_ground_truth = record_ground_truth
        self.stats = {"tasks": 0, "completed": 0, "failed": 0, "rejected": 0, "cost_units": 0.0}

    # ------------------------------------------------------------------
    # Worker selection
    # ------------------------------------------------------------------
    def select_worker(self, capability: str, exclude: set[str] | None = None) -> WorkerRecord | None:
        candidates = self.registry.available(capability, exclude or set())
        if not candidates:
            return None
        if self.selection == "random":
            return self.rng.choice(candidates)
        if self.selection == "round_robin":
            return candidates[self.stats["tasks"] % len(candidates)]
        # trust_weighted: softmax-free proportional sampling on trust^2, which keeps some
        # exploration (a low-trust worker is not permanently starved, so it can recover) while
        # strongly preferring reliable workers.
        weights = [max(self.trust.score(c.worker_id), 0.01) ** 2 for c in candidates]
        return self.rng.choices(candidates, weights=weights, k=1)[0]

    def select_replicas(self, capability: str, n: int, exclude: set[str]) -> list[WorkerRecord]:
        """Disjoint from the primary and from each other: correlated executors prove nothing."""
        picks: list[WorkerRecord] = []
        used = set(exclude)
        for _ in range(n):
            rec = self.select_worker(capability, used)
            if rec is None:
                break
            picks.append(rec)
            used.add(rec.worker_id)
        return picks

    # ------------------------------------------------------------------
    # Execution with timeout + retry
    # ------------------------------------------------------------------
    def _execute_on(
        self, rec: WorkerRecord, task_id: str, features: list[float], commitment: str
    ) -> tuple[SignedResult | None, float, str | None, bool]:
        """Returns (signed_result, latency_ms, error, was_tampering_ground_truth)."""
        t0 = time.perf_counter()
        try:
            signed = rec.handle.execute(task_id, features, commitment)
            latency = (time.perf_counter() - t0) * 1000.0
            gt = isinstance(rec.handle, FaultyWorker) and rec.handle.is_tampering_behaviour()
            self.registry.record_success(rec.worker_id)
            return signed, latency, None, gt
        except WorkerError as exc:
            latency = (time.perf_counter() - t0) * 1000.0
            self.registry.record_failure(rec.worker_id)
            return None, latency, str(exc), False
        except Exception as exc:  # defensive: a worker must never take the scheduler down
            latency = (time.perf_counter() - t0) * 1000.0
            self.registry.record_failure(rec.worker_id)
            return None, latency, f"unexpected worker error: {type(exc).__name__}", False

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def submit(
        self,
        features: list[float],
        *,
        task_type: str = "digits_classification",
        sensitivity: str = "medium",
        task_id: str | None = None,
        experiment_id: str | None = None,
        timeout_ms: float | None = None,
    ) -> TaskOutcome:
        t_start = time.perf_counter()
        task_id = task_id or new_id()
        commitment = input_commitment(features)
        self.stats["tasks"] += 1

        executed_by: list[str] = []
        integrity_reasons: list[str] = []
        verification_ms = 0.0
        cost_units = 1.0  # the primary execution itself
        attempts_rows: list[tuple[Attempt, SignedResult | None, Any, bool]] = []

        # --- 1. primary execution, with retry on a *different* worker --------
        primary: SignedResult | None = None
        primary_rec: WorkerRecord | None = None
        primary_latency = 0.0
        tried: set[str] = set()
        last_error = "no worker available"
        gt_tampered = False

        for _attempt_no in range(self.max_retries + 1):
            rec = self.select_worker(task_type, tried)
            if rec is None:
                break
            tried.add(rec.worker_id)
            signed, latency, error, gt = self._execute_on(rec, task_id, features, commitment)
            executed_by.append(rec.worker_id)
            if signed is None:
                last_error = error or "unknown failure"
                self.trust.record(rec.worker_id, "crash", latency)
                cost_units += 1.0
                continue
            if timeout_ms is not None and latency > timeout_ms:
                last_error = f"deadline exceeded ({latency:.1f}ms > {timeout_ms}ms)"
                self.trust.record(rec.worker_id, "timeout", latency)
                self.registry.record_failure(rec.worker_id)
                cost_units += 1.0
                continue
            primary, primary_rec, primary_latency, gt_tampered = signed, rec, latency, gt
            break

        if primary is None or primary_rec is None:
            return self._finalise_failure(task_id, executed_by, cost_units, t_start, last_error)

        # --- 2. integrity verification (always; it is cheap) ------------------
        integ = self.verifier.check_integrity(
            primary, expected_task_id=task_id, expected_input_commitment=commitment
        )
        verification_ms += integ.latency_ms
        attempts_rows.append((self._attempt_row(task_id, primary_rec.worker_id, "primary",
                                                primary, primary_latency, integ.ok, integ.reason),
                              primary, integ, gt_tampered))

        if not integ.ok:
            integrity_reasons.append(integ.reason)
            self.trust.record(primary_rec.worker_id, "integrity_failure", primary_latency)
            # Cryptographic failure is decisive: re-execute elsewhere rather than trust the result.
            replicas = self.select_replicas(task_type, 1, tried)
            if replicas:
                rec = replicas[0]
                signed2, lat2, err2, gt2 = self._execute_on(rec, task_id, features, commitment)
                executed_by.append(rec.worker_id)
                cost_units += 1.0
                if signed2 is not None:
                    integ2 = self.verifier.check_integrity(
                        signed2, expected_task_id=task_id, expected_input_commitment=commitment
                    )
                    verification_ms += integ2.latency_ms
                    attempts_rows.append(
                        (self._attempt_row(task_id, rec.worker_id, "replica", signed2, lat2,
                                           integ2.ok, integ2.reason), signed2, integ2, gt2)
                    )
                    if integ2.ok:
                        self.trust.record(rec.worker_id, "success", lat2)
                        outcome = self._finalise(
                            task_id, TaskStatus.COMPLETED, Verdict.ACCEPTED_AFTER_VERIFICATION,
                            signed2.payload, executed_by, 0.0, "re_execute", 1, cost_units,
                            t_start, verification_ms, True, integrity_reasons,
                            "primary failed integrity; re-executed on another worker",
                        )
                        self._persist(task_id, task_type, sensitivity, commitment, features,
                                      attempts_rows, outcome, experiment_id)
                        return outcome
            outcome = self._finalise(
                task_id, TaskStatus.REJECTED, Verdict.REJECTED_INTEGRITY, None, executed_by,
                0.0, "re_execute", 0, cost_units, t_start, verification_ms, True,
                integrity_reasons, f"integrity check failed: {integ.reason}",
            )
            self._persist(task_id, task_type, sensitivity, commitment, features, attempts_rows,
                          outcome, experiment_id)
            return outcome

        # --- 3. adaptive verification decision --------------------------------
        st = self.trust.get(primary_rec.worker_id)
        latency_dev = 0.0
        if st.latency_ewma_ms > 0:
            latency_dev = min(1.0, abs(primary_latency - st.latency_ewma_ms) / max(st.latency_ewma_ms, 1.0))
        feats = RiskFeatures(
            trust=st.score,
            anomaly=0.0,  # M4 plugs the anomaly detector in here
            uncertainty=float(primary.payload.get("entropy", 0.0)) if isinstance(primary.payload, dict) else 0.0,
            sensitivity=sensitivity,
            latency_dev=latency_dev,
            hist_fail_rate=(st.integrity_failures + st.disagreements) / st.n_events if st.n_events else 0.0,
            queue_load=0.0,  # M3 plugs queue depth in here
        )
        pd: PolicyDecision = self.policy.decide(feats)

        if pd.decision == Decision.ACCEPT:
            self.trust.record(primary_rec.worker_id, "success", primary_latency)
            outcome = self._finalise(
                task_id, TaskStatus.COMPLETED, Verdict.ACCEPTED, primary.payload, executed_by,
                pd.risk_score, pd.decision.value, 0, cost_units, t_start, verification_ms, False,
                integrity_reasons, pd.rationale,
            )
            self._persist(task_id, task_type, sensitivity, commitment, features, attempts_rows,
                          outcome, experiment_id)
            return outcome

        # --- 4. replicated corroboration ---------------------------------------
        n_replicas = max(1, pd.replicas)
        replicas = self.select_replicas(task_type, n_replicas, tried)
        replica_results: list[SignedResult] = []
        for rec in replicas:
            signed_r, lat_r, err_r, gt_r = self._execute_on(rec, task_id, features, commitment)
            executed_by.append(rec.worker_id)
            cost_units += 1.0
            if signed_r is None:
                self.trust.record(rec.worker_id, "crash", lat_r)
                continue
            integ_r = self.verifier.check_integrity(
                signed_r, expected_task_id=task_id, expected_input_commitment=commitment
            )
            verification_ms += integ_r.latency_ms
            attempts_rows.append(
                (self._attempt_row(task_id, rec.worker_id, "replica", signed_r, lat_r,
                                   integ_r.ok, integ_r.reason), signed_r, integ_r, gt_r)
            )
            if not integ_r.ok:
                integrity_reasons.append(integ_r.reason)
                self.trust.record(rec.worker_id, "integrity_failure", lat_r)
                continue
            replica_results.append(signed_r)

        if not replica_results:
            # No corroboration obtained. We do NOT silently accept: report unresolved.
            outcome = self._finalise(
                task_id, TaskStatus.COMPLETED, Verdict.UNRESOLVED, primary.payload, executed_by,
                pd.risk_score, pd.decision.value, 0, cost_units, t_start, verification_ms,
                bool(integrity_reasons), integrity_reasons,
                "verification requested but no replica produced a valid result",
            )
            self._persist(task_id, task_type, sensitivity, commitment, features, attempts_rows,
                          outcome, experiment_id)
            return outcome

        weights = {r.envelope.worker_id: self.trust.score(r.envelope.worker_id)
                   for r in [primary, *replica_results]}
        agreement = self.verifier.check_agreement([primary, *replica_results], weights)

        if agreement.agreed:
            for r in [primary, *replica_results]:
                self.trust.record(r.envelope.worker_id, "verified_agreement")
            outcome = self._finalise(
                task_id, TaskStatus.COMPLETED, Verdict.ACCEPTED_AFTER_VERIFICATION,
                primary.payload, executed_by, pd.risk_score, pd.decision.value,
                len(replica_results), cost_units, t_start, verification_ms,
                # A replica that failed its integrity check is a detection event for the task even
                # when the surviving replicas agree; it must not be silently dropped.
                bool(integrity_reasons),
                integrity_reasons, f"{pd.rationale}; all replicas agreed",
            )
        else:
            majority = agreement.majority_hash
            winner = next(
                (r for r in [primary, *replica_results] if r.envelope.result_hash == majority), None
            )
            for r in [primary, *replica_results]:
                self.trust.record(
                    r.envelope.worker_id,
                    "disagreement" if r.envelope.worker_id in agreement.disagreeing_workers
                    else "verified_agreement",
                )
            for wid in agreement.disagreeing_workers:
                if self.trust.should_quarantine(wid):
                    self.registry.quarantine(wid, "sustained disagreement")
            outcome = self._finalise(
                task_id,
                TaskStatus.COMPLETED if winner else TaskStatus.FAILED,
                Verdict.ACCEPTED_AFTER_VERIFICATION if winner else Verdict.REJECTED_DISAGREEMENT,
                winner.payload if winner else None, executed_by, pd.risk_score,
                pd.decision.value, len(replica_results), cost_units, t_start, verification_ms,
                bool(integrity_reasons), integrity_reasons,
                f"disagreement among {agreement.disagreeing_workers}; "
                f"{'majority accepted' if winner else 'unresolved'}",
            )
        self._persist(task_id, task_type, sensitivity, commitment, features, attempts_rows,
                      outcome, experiment_id)
        return outcome

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _attempt_row(self, task_id, worker_id, role, signed, latency, ok, reason) -> Attempt:
        return Attempt(
            id=new_id(), task_id=task_id, worker_id=worker_id, role=role,
            result_hash=signed.envelope.result_hash if signed else None,
            result_payload=canonical_json(signed.payload) if signed else None,
            model_version=signed.envelope.model_version if signed else None,
            latency_ms=latency, succeeded=bool(ok), error=None if ok else reason,
        )

    def _finalise(self, task_id, status, verdict, result, executed_by, risk, decision, replicas,
                  cost, t_start, verification_ms, integrity_failure, reasons, detail) -> TaskOutcome:
        self.stats["cost_units"] += cost
        if status == TaskStatus.COMPLETED:
            self.stats["completed"] += 1
        elif status == TaskStatus.REJECTED:
            self.stats["rejected"] += 1
        else:
            self.stats["failed"] += 1
        return TaskOutcome(
            task_id=task_id, status=status, verdict=verdict, result=result,
            executed_by=executed_by, risk_score=risk, decision=decision,
            replicas_used=replicas, cost_units=cost,
            latency_ms=(time.perf_counter() - t_start) * 1000.0,
            verification_latency_ms=verification_ms, integrity_failure=integrity_failure,
            integrity_failure_reasons=reasons, detail=detail,
        )

    def _finalise_failure(self, task_id, executed_by, cost, t_start, detail) -> TaskOutcome:
        self.stats["failed"] += 1
        return TaskOutcome(
            task_id=task_id, status=TaskStatus.FAILED, verdict=Verdict.UNRESOLVED, result=None,
            executed_by=executed_by, risk_score=0.0, decision="none", replicas_used=0,
            cost_units=cost, latency_ms=(time.perf_counter() - t_start) * 1000.0,
            verification_latency_ms=0.0, integrity_failure=False, detail=detail,
        )

    def _persist(self, task_id, task_type, sensitivity, commitment, features, attempts_rows,
                 outcome: TaskOutcome, experiment_id) -> None:
        if self.session_factory is None:
            return
        with self.session_factory() as s:
            for wid in {a[0].worker_id for a in attempts_rows}:
                if s.get(WorkerRow, wid) is None:
                    rec = self.registry.get(wid)
                    s.add(WorkerRow(id=wid, public_key=rec.public_key if rec else "",
                                    capabilities=canonical_json(list(rec.capabilities) if rec else []),
                                    trust_score=self.trust.score(wid)))
            s.add(Task(
                id=task_id, task_type=task_type, sensitivity=sensitivity,
                input_commitment=commitment, input_payload=canonical_json(features),
                status=outcome.status.value, verdict=outcome.verdict.value,
                final_result=canonical_json(outcome.result) if outcome.result is not None else None,
                completed_at=utcnow(), total_latency_ms=outcome.latency_ms,
                experiment_id=experiment_id,
            ))
            for row, signed, integ, gt in attempts_rows:
                s.add(row)
                if signed is not None:
                    s.add(SignatureRecord(
                        attempt_id=row.id, envelope_json=canonical_json(signed.envelope.to_dict()),
                        envelope_hash=integ.envelope_hash, signature_hex=signed.signature_hex,
                        verified=integ.ok, failure_reason=integ.reason,
                        checks_json=canonical_json(integ.checks),
                    ))
                if self.record_ground_truth:
                    s.add(GroundTruth(attempt_id=row.id, task_id=task_id, was_tampered=bool(gt),
                                      scenario="injected" if gt else "none"))
            s.add(VerificationRecord(
                task_id=task_id, policy=getattr(self.policy, "name", "unknown"),
                decision=outcome.decision, risk_score=outcome.risk_score,
                replicas_used=outcome.replicas_used, cost_units=outcome.cost_units,
                agreed=None if outcome.replicas_used == 0 else
                (outcome.verdict == Verdict.ACCEPTED_AFTER_VERIFICATION),
                integrity_failure=outcome.integrity_failure,
                verification_latency_ms=outcome.verification_latency_ms,
            ))
            for wid in {a[0].worker_id for a in attempts_rows}:
                s.add(TrustEvent(worker_id=wid, event_type="scheduler_update", delta=0.0,
                                 score_after=self.trust.score(wid), note=outcome.decision))
            s.commit()

    def reset_stats(self) -> None:
        self.stats = {"tasks": 0, "completed": 0, "failed": 0, "rejected": 0, "cost_units": 0.0}
