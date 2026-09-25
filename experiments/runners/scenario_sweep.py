"""Scenario sweep: every implemented attack scenario x several verification policies.

Where the MVE answers "is the adaptive policy cheaper?", this answers "which layer catches which
attack?" — the breakdown the threat model claims and therefore the one that has to be verified
empirically rather than asserted.

It also self-checks: if a scenario the threat model says is cryptographically detectable produces
zero integrity detections, the run is flagged FAILED-EXPECTATION rather than quietly reported.

Usage:
    python -m experiments.runners.scenario_sweep --tasks 80 --seeds 2
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ml.inference_model import get_model
from services.common.config import get_settings
from simulator.attack_scenarios import (
    EXPECTATIONS,
    declared_but_unimplemented,
    implemented_scenarios,
)
from simulator.fault_injection import FaultInjector
from simulator.workload_generator import WorkloadGenerator

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = REPO_ROOT / "experiments" / "results"

DEFAULT_POLICIES = ["no_verification", "fixed_1", "fixed_3", "risk_adaptive"]


@dataclass
class SweepRow:
    scenario: str
    policy: str
    seed: int
    tasks: int
    corrupt_tasks: int
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    completion_rate: float
    wrong_results_served: int
    mean_cost_units: float
    mean_latency_ms: float
    failure_reasons: dict = field(default_factory=dict)
    expectation: str = "n/a"


def check_expectation(scenario_id: str, row: SweepRow) -> str:
    """Compare observed behaviour against what the threat model predicts."""
    exp = EXPECTATIONS.get(scenario_id)
    if exp is None:
        return "n/a"
    if row.policy == "no_verification" and exp.min_disagreements > 0:
        return "n/a (arm cannot detect by design)"
    reasons = set(row.failure_reasons)
    if exp.reasons_expected and not (reasons & set(exp.reasons_expected)):
        return (f"FAILED-EXPECTATION: expected one of {exp.reasons_expected}, observed {sorted(reasons) or 'none'}")
    if row.tp < exp.min_integrity_detections:
        return f"FAILED-EXPECTATION: expected >= {exp.min_integrity_detections} detections, got {row.tp}"
    return "met"


def run_cell(scenario_id: str, policy: str, seed: int, tasks: int,
             n_workers: int, n_faulty: int) -> SweepRow:
    injector = FaultInjector(scenario_id, n_workers=n_workers, n_faulty=n_faulty,
                             policy=policy, seed=seed)
    workload = WorkloadGenerator(n_tasks=tasks, regime="uniform", seed=seed).generate()
    run = injector.run(workload)
    m = run.metrics()
    row = SweepRow(
        scenario=scenario_id, policy=policy, seed=seed, tasks=run.n_tasks,
        corrupt_tasks=run.corrupt_tasks,
        tp=int(m["tp"]), fp=int(m["fp"]), tn=int(m["tn"]), fn=int(m["fn"]),
        precision=m["precision"], recall=m["recall"], f1=m["f1"],
        false_positive_rate=m["false_positive_rate"], completion_rate=m["completion_rate"],
        wrong_results_served=int(m["wrong_results_served"]),
        mean_cost_units=m["mean_cost_units"], mean_latency_ms=m["mean_latency_ms"],
        failure_reasons=run.failure_reasons(),
    )
    row.expectation = check_expectation(scenario_id, row)
    injector.teardown()
    return row


def main() -> int:
    ap = argparse.ArgumentParser(description="TrustProof-Cloud attack-scenario sweep")
    ap.add_argument("--tasks", type=int, default=80)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--faulty", type=int, default=2)
    ap.add_argument("--seeds", type=int, default=2)
    ap.add_argument("--policies", default=",".join(DEFAULT_POLICIES))
    args = ap.parse_args()

    policies = [p.strip() for p in args.policies.split(",") if p.strip()]
    scenarios = implemented_scenarios()
    get_model(cache_dir=get_settings().data_dir / "models")

    exp_id = f"sweep-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    rows: list[SweepRow] = []

    print(f"\n{'scenario':<24}{'policy':<18}{'recall':>8}{'prec':>7}{'FPR':>7}"
          f"{'wrong':>7}{'cost':>7}{'compl':>8}  expectation")
    print("-" * 104)
    for sc in scenarios:
        for policy in policies:
            cells = [run_cell(sc.id, policy, 42 + s, args.tasks, args.workers, args.faulty)
                     for s in range(args.seeds)]
            rows.extend(cells)
            agg_recall = statistics.fmean(c.recall for c in cells)
            agg_prec = statistics.fmean(c.precision for c in cells)
            agg_fpr = statistics.fmean(c.false_positive_rate for c in cells)
            agg_wrong = statistics.fmean(c.wrong_results_served for c in cells)
            agg_cost = statistics.fmean(c.mean_cost_units for c in cells)
            agg_compl = statistics.fmean(c.completion_rate for c in cells)
            exps = {c.expectation for c in cells}
            verdict = ("met" if exps == {"met"}
                       else "n/a" if all(e.startswith("n/a") for e in exps)
                       else sorted(e for e in exps if e.startswith("FAILED"))[0][:46])
            print(f"{sc.id:<24}{policy:<18}{agg_recall:>8.3f}{agg_prec:>7.3f}{agg_fpr:>7.3f}"
                  f"{agg_wrong:>7.1f}{agg_cost:>7.3f}{agg_compl:>8.3f}  {verdict}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "experiment_id": exp_id,
        "created_at": datetime.now(UTC).isoformat(),
        "config": {"tasks": args.tasks, "workers": args.workers, "faulty": args.faulty,
                   "seeds": args.seeds, "policies": policies,
                   "scenarios": [s.id for s in scenarios]},
        "not_implemented": {s.id: s.notes for s in declared_but_unimplemented()},
        "rows": [asdict(r) for r in rows],
        "notes": [
            "Simulation results under an injected fault model; not production measurements.",
            "'wrong' = results served that differ from the reference prediction - the metric that "
            "matters to a user, independent of whether anything was flagged.",
        ],
    }
    (RESULTS_DIR / f"{exp_id}.json").write_text(json.dumps(payload, indent=2))

    with (RESULTS_DIR / f"{exp_id}.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=[k for k in asdict(rows[0]) if k != "failure_reasons"])
        w.writeheader()
        for r in rows:
            d = asdict(r)
            d.pop("failure_reasons")
            w.writerow(d)

    failures = [r for r in rows if r.expectation.startswith("FAILED")]
    print(f"\nexpectation checks: {len(rows) - len(failures)}/{len(rows)} met")
    if failures:
        print("FAILED expectations (reported, not suppressed):")
        for r in failures[:10]:
            print(f"  {r.scenario}/{r.policy}/seed{r.seed}: {r.expectation}")

    skipped = declared_but_unimplemented()
    if skipped:
        print(f"\nnot run ({len(skipped)} scenarios declared but not implemented):")
        for s in skipped:
            print(f"  {s.id}: {s.notes}")

    print(f"\nwrote experiments/results/{exp_id}.json and .csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
