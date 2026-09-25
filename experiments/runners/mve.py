"""Minimum Viable Experiment (MVE) runner — M2 scope.

Runs the six comparison arms required by the brief against an identical task stream and worker
pool, and writes CSV + JSON. This is the smallest experiment that can support or falsify H1/H4.

What this experiment DOES measure:
  * verification cost (execution units per task), the quantity the adaptive policy is meant to save
  * end-to-end and verification latency
  * detection of *cryptographically detectable* corruption (H4)
  * detection of *silently wrong but correctly signed* results, via replica disagreement (H1/H2)
  * task completion rate

What it does NOT yet measure (M4/M6): ML-based anomaly detection quality, learned risk estimation,
workload prediction, and the full ablation sweep. Those arms are not reported until implemented.

Usage:
    python -m experiments.runners.mve --tasks 300 --seeds 3
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ml.inference_model import get_model, sample_inputs
from services.common.bootstrap import build_system
from services.common.config import get_settings
from services.common.models import TaskStatus, Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = REPO_ROOT / "experiments" / "results"

ARMS = ["no_verification", "fixed_1", "fixed_3", "random_spotcheck", "rule_based", "risk_adaptive"]
SELECTION = {"random_spotcheck": "random"}  # arm 4 of the brief: random worker selection


@dataclass
class ArmResult:
    arm: str
    seed: int
    tasks: int
    completed: int
    failed: int
    rejected: int
    mean_cost_units: float
    verification_units_per_task: float
    mean_latency_ms: float
    p95_latency_ms: float
    mean_verification_latency_ms: float
    corrupt_attempts: int          # ground truth: attempts that were tampered/corrupted
    integrity_detections: int      # caught by cryptography alone
    disagreement_detections: int   # caught by replication
    undetected_corruption: int     # accepted a task whose served result came from a bad attempt
    detection_recall: float
    false_positive_rate: float
    mean_trust_faulty: float
    mean_trust_honest: float
    wall_clock_s: float


@dataclass
class ExperimentReport:
    experiment_id: str
    created_at: str
    config: dict
    arms: list[dict] = field(default_factory=list)
    environment: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def run_arm(arm: str, *, tasks: int, n_workers: int, n_faulty: int, fault_rate: float,
            behaviours: tuple[str, ...], seed: int, sensitivity: str) -> ArmResult:
    t0 = time.perf_counter()
    system = build_system(
        n_workers=n_workers, n_faulty=n_faulty, fault_rate=fault_rate, behaviours=behaviours,
        policy=arm, selection=SELECTION.get(arm, "trust_weighted"), persist=False, seed=seed,
    )
    faulty_ids = {w.worker_id for w in system.workers[n_workers - n_faulty:]} if n_faulty else set()
    honest_ids = {w.worker_id for w in system.workers} - faulty_ids

    inputs = sample_inputs(tasks, seed=seed + 1000)
    # Reference (ground-truth) prediction from the unmodified model, computed outside the workers.
    reference = {i: system.model.predict_with_uncertainty(x).as_payload() for i, x in enumerate(inputs)}

    latencies: list[float] = []
    ver_latencies: list[float] = []
    costs: list[float] = []
    completed = failed = rejected = 0
    integrity_detections = disagreement_detections = 0
    undetected = 0
    corrupt_attempts = 0
    false_positives = 0
    clean_tasks = 0

    for i, x in enumerate(inputs):
        before = {w.worker_id: getattr(w, "executions", 0) for w in system.workers}
        out = system.scheduler.submit(x, sensitivity=sensitivity,
                                      timeout_ms=system.settings.task_timeout_ms)
        latencies.append(out.latency_ms)
        ver_latencies.append(out.verification_latency_ms)
        costs.append(out.cost_units)

        # Ground truth for this task: did any *faulty* worker actually misbehave on it?
        # Read from the injector-controlled worker objects, never from scheduler state.
        task_corrupted = any(
            w.worker_id in faulty_ids
            and getattr(w, "executions", 0) > before[w.worker_id]
            and getattr(w, "last_behaviour", "honest") not in ("honest", "slow")
            for w in system.workers
        )
        if task_corrupted:
            corrupt_attempts += 1
        else:
            clean_tasks += 1

        if out.status == TaskStatus.COMPLETED:
            completed += 1
        elif out.status == TaskStatus.REJECTED:
            rejected += 1
        else:
            failed += 1

        detected = out.integrity_failure or out.verdict in (
            Verdict.REJECTED_DISAGREEMENT, Verdict.REJECTED_INTEGRITY
        ) or "disagreement" in out.detail
        if detected:
            if out.integrity_failure:
                integrity_detections += 1
            if "disagreement" in out.detail:
                disagreement_detections += 1
            if not task_corrupted:
                false_positives += 1

        # A served result is *wrong* if it differs from the reference prediction.
        if out.result is not None and out.result != reference[i]:
            undetected += 1

    faulty_trust = [system.trust.score(w) for w in faulty_ids] or [float("nan")]
    honest_trust = [system.trust.score(w) for w in honest_ids] or [float("nan")]

    detected_total = integrity_detections + disagreement_detections
    return ArmResult(
        arm=arm, seed=seed, tasks=tasks, completed=completed, failed=failed, rejected=rejected,
        mean_cost_units=round(statistics.fmean(costs), 4),
        verification_units_per_task=round(statistics.fmean(costs) - 1.0, 4),
        mean_latency_ms=round(statistics.fmean(latencies), 3),
        p95_latency_ms=round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 3),
        mean_verification_latency_ms=round(statistics.fmean(ver_latencies), 4),
        corrupt_attempts=corrupt_attempts,
        integrity_detections=integrity_detections,
        disagreement_detections=disagreement_detections,
        undetected_corruption=undetected,
        detection_recall=round(min(detected_total, corrupt_attempts) / corrupt_attempts, 4)
        if corrupt_attempts else 0.0,
        false_positive_rate=round(false_positives / clean_tasks, 4) if clean_tasks else 0.0,
        mean_trust_faulty=round(statistics.fmean(faulty_trust), 4),
        mean_trust_honest=round(statistics.fmean(honest_trust), 4),
        wall_clock_s=round(time.perf_counter() - t0, 2),
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="TrustProof-Cloud minimum viable experiment")
    ap.add_argument("--tasks", type=int, default=200)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--faulty", type=int, default=2)
    ap.add_argument("--fault-rate", type=float, default=0.4)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--sensitivity", default="medium", choices=["low", "medium", "high"])
    ap.add_argument("--behaviours", default="tamper_payload,tamper_transit",
                    help="comma-separated fault behaviours from the injector")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    behaviours = tuple(b.strip() for b in args.behaviours.split(",") if b.strip())
    exp_id = f"mve-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    get_model(cache_dir=get_settings().data_dir / "models")

    report = ExperimentReport(
        experiment_id=exp_id,
        created_at=datetime.now(UTC).isoformat(),
        config={
            "tasks_per_arm": args.tasks, "workers": args.workers, "faulty_workers": args.faulty,
            "fault_rate": args.fault_rate, "behaviours": list(behaviours),
            "sensitivity": args.sensitivity, "seeds": args.seeds, "arms": ARMS,
        },
        environment={
            "python": __import__("platform").python_version(),
            "platform": __import__("platform").platform(),
            "model_version": get_model().version,
            "model_test_accuracy": get_model().test_accuracy,
        },
        notes=[
            "Simulation results under an injected fault model; not production measurements.",
            "Latency includes synthetic per-worker service time, capped for test speed.",
            "M2 scope: no learned risk estimator or anomaly detector yet, so the risk_adaptive arm "
            "uses the documented heuristic estimator. ML arms are reported from M4 onward.",
        ],
    )

    print(f"\n{'arm':<18}{'seed':>5}{'cost/task':>11}{'ver.u/task':>12}"
          f"{'p95 ms':>9}{'recall':>8}{'FPR':>7}{'wrong served':>14}{'compl.':>8}")
    print("-" * 92)
    for seed in range(args.seeds):
        for arm in ARMS:
            r = run_arm(arm, tasks=args.tasks, n_workers=args.workers, n_faulty=args.faulty,
                        fault_rate=args.fault_rate, behaviours=behaviours, seed=42 + seed,
                        sensitivity=args.sensitivity)
            report.arms.append(asdict(r))
            print(f"{r.arm:<18}{r.seed:>5}{r.mean_cost_units:>11.3f}"
                  f"{r.verification_units_per_task:>12.3f}{r.p95_latency_ms:>9.1f}"
                  f"{r.detection_recall:>8.3f}{r.false_positive_rate:>7.3f}"
                  f"{r.undetected_corruption:>14d}{r.completed:>8d}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / f"{exp_id}.json"
    json_path.write_text(json.dumps(asdict(report), indent=2))

    import csv

    csv_path = RESULTS_DIR / f"{exp_id}.csv"
    with csv_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(report.arms[0].keys()))
        writer.writeheader()
        writer.writerows(report.arms)

    # aggregate across seeds
    print("\nAggregated across seeds (mean):")
    print(f"{'arm':<18}{'ver.u/task':>12}{'recall':>9}{'FPR':>8}{'wrong served':>14}{'p95 ms':>9}")
    print("-" * 70)
    agg = {}
    for arm in ARMS:
        rows = [a for a in report.arms if a["arm"] == arm]
        agg[arm] = {
            "verification_units_per_task": round(statistics.fmean(r["verification_units_per_task"] for r in rows), 4),
            "detection_recall": round(statistics.fmean(r["detection_recall"] for r in rows), 4),
            "false_positive_rate": round(statistics.fmean(r["false_positive_rate"] for r in rows), 4),
            "undetected_corruption": round(statistics.fmean(r["undetected_corruption"] for r in rows), 2),
            "p95_latency_ms": round(statistics.fmean(r["p95_latency_ms"] for r in rows), 2),
            "mean_trust_faulty": round(statistics.fmean(r["mean_trust_faulty"] for r in rows), 4),
            "mean_trust_honest": round(statistics.fmean(r["mean_trust_honest"] for r in rows), 4),
        }
        a = agg[arm]
        print(f"{arm:<18}{a['verification_units_per_task']:>12.3f}{a['detection_recall']:>9.3f}"
              f"{a['false_positive_rate']:>8.3f}{a['undetected_corruption']:>14.1f}"
              f"{a['p95_latency_ms']:>9.1f}")

    report_dict = asdict(report)
    report_dict["aggregate"] = agg
    json_path.write_text(json.dumps(report_dict, indent=2))

    print(f"\nwrote {json_path.relative_to(REPO_ROOT)}")
    print(f"wrote {csv_path.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
