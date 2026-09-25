# Research Methodology

## 1. Hypotheses and pre-registered success criteria

Criteria are fixed **before** each experiment runs. A hypothesis that fails is reported as failed.

| ID | Hypothesis | Measurable criterion | Status |
|---|---|---|---|
| **H1** | Risk-adaptive verification reduces verification overhead vs fixed replication under low-risk workloads | Adaptive uses ≤ 60 % of the verification units of `fixed_3` while retaining ≥ 90 % of its tampering-detection recall | **Partially supported (M2).** Cost criterion met by a wide margin (3 % of `fixed_3` units); recall criterion **not** met (76 % of `fixed_3`). See §5. |
| **H2** | ML-based worker anomaly detection outperforms a tuned statistical threshold | IsolationForest beats a 3σ threshold baseline on F1 at equal FPR, over ≥ 5 seeds | **Not yet tested** — anomaly detector is M4 |
| **H3** | Adaptive worker selection improves task completion under simulated worker failures | Completion rate under 40 % crashing workers ≥ that of random selection, p < 0.05 over ≥ 10 seeds | **Not yet tested** — partial smoke evidence only (see §5) |
| **H4** | Cryptographic integrity verification detects modified result artifacts | 100 % detection of `tamper_transit`, `forge_signature`, `stale`, `wrong_model`, `replay` under the injector | **Supported (M2)** by unit tests + MVE; see §5 |
| **H5** | The proposed policy maintains acceptable latency while increasing verification for high-risk tasks | p95 latency ≤ 1.2 × `fixed_1`, and mean verification units on high-sensitivity tasks > on low-sensitivity | **Supported (M2)** for the latency half; sensitivity monotonicity verified by test |

## 2. Experimental design

- **Arms** (all six required by the brief): `no_verification`, `fixed_1`, `fixed_3`,
  `random_spotcheck` (random worker selection + spot checks), `rule_based`, `risk_adaptive`.
- **Controlled across arms:** task stream (same inputs, same order), worker pool size and
  composition, model version and weights, fault behaviours and rate, RNG seed.
- **Varied:** the verification policy only. This is what makes the comparison a controlled one.
- **Repetitions:** ≥ 3 seeds in the MVE, ≥ 5 for any result reported as a finding.
- **Reproducibility:** every stochastic component takes an injected `random.Random`; no library
  code calls `random.seed()` (enforced by `tests/test_research_integrity.py`). A test asserts that
  two systems built with the same seed produce identical decision traces, and that different seeds
  produce different ones.

## 3. Metrics

**Cost.** `cost_units` = number of worker executions consumed by a task (primary = 1). Reported as
`verification_units_per_task = mean(cost_units) − 1`, i.e. the *extra* compute the verification
policy spent. Currency cost is not modelled; nothing in this project is billable.

**Detection.**
- *Ground truth*: the fault injector labels each execution as tampered or not. Labels live in a
  quarantined table/attribute that decision code cannot read (enforced by a static-analysis test).
- *Detection event*: an integrity failure, a replica disagreement, or a rejection verdict.
- `recall = detected_corrupt_tasks / corrupt_tasks`, `FPR = flagged_clean_tasks / clean_tasks`.
- *Wrong-result-served*: the served result differs from the reference prediction computed outside
  the worker pool. **This is the metric that actually matters to a user** — a detection that still
  serves a wrong answer is not a success.

**Latency.** End-to-end wall clock per task (mean and p95), and verification latency separately so
cryptographic cost can be distinguished from replication cost.

**Trust separation.** Mean trust of faulty vs honest workers at the end of a run: a policy that
cannot separate them cannot route around them.

## 4. Parameter selection (no undocumented magic numbers)

| Parameter | Default | How it was chosen | Swept in |
|---|---|---|---|
| `tau_low` | 0.25 | Cost model: accept-without-check is rational while `P(corrupt) × damage < cost of one replica`. With damage normalised to 1 and replica cost ≈ 1 execution, the indifference point sits near 0.25 for the MVE's fault rate. An initial value, not a fitted one. | M6 |
| `tau_high` | 0.60 | Point above which a single corroboration is judged insufficient; set so that ≲ 10 % of tasks escalate to multi-replica under a nominal 20 % faulty-worker mix | M6 |
| `epsilon` | 0.05 | Anti-gaming floor (T11). Bounds long-run undetected defection at the cost of 5 % extra executions. | M6 |
| `alpha` (trust EWMA) | 0.15 | Event influence decays below 5 % after ≈ 18 events — recovery within a few dozen tasks, while persistent defection crosses the quarantine floor quickly | M6 |
| `trust_prior` | 0.70 | Unknown ≠ trusted; below `tau`-relevant range but above the quarantine floor | M6 |
| Risk weights | see `services/risk_model/risk.py` | Stated priors with written rationale per weight, constrained to sum to 1 (enforced by a test) | M6 |
| Payload rounding | 6 dp | Smallest precision at which honest workers agree byte-wise across runs | fixed |

**Until the M6 sweep has actually been run, none of these may be described as "tuned".**

## 5. Results obtained so far (M2)

Command: `python -m experiments.runners.mve --tasks 150 --seeds 3`
Config: 8 workers (2 faulty), fault rate 0.4, behaviours `tamper_payload` + `tamper_transit`,
sensitivity `medium`, seeds 42/43/44, `digits-logreg@1.0.0`, CPU only.

Means across 3 seeds (450 tasks per arm):

| Arm | ver. units/task | detection recall | FPR | wrong results served | p95 latency (ms) |
|---|---|---|---|---|---|
| no_verification | 0.022 | 0.597 | 0.000 | 2.7 | 13.6 |
| fixed_1 | 1.000 | **1.000** | 0.000 | **0.0** | 23.9 |
| fixed_3 | 2.978 | **1.000** | 0.000 | **0.0** | 44.4 |
| random_spotcheck | 0.389 | 0.774 | 0.000 | 4.0 | 21.8 |
| rule_based | 0.035 | 0.681 | 0.000 | 2.3 | 14.1 |
| **risk_adaptive** | **0.091** | 0.764 | 0.000 | 1.7 | 18.1 |

Raw data: `experiments/results/mve-*.json` and `.csv`.

### Honest reading of these numbers

1. **H1 is only half-supported.** The adaptive policy spends 0.091 verification units per task
   versus 2.978 for `fixed_3` — a ~97 % reduction, far beyond the ≤ 60 % criterion. But its recall
   is 0.764 against `fixed_3`'s 1.000, i.e. 76 % rather than the required ≥ 90 %. **H1 as
   pre-registered is not met at M2.** The cost/detection trade-off is real but currently sits at a
   worse point than the criterion demanded.

2. **Why.** The M2 risk estimator has no anomaly-detector input (`anomaly` is hard-wired to 0.0
   pending M4) and workers start at trust 0.70. A fresh tampering worker therefore scores below
   `tau_low` and is accepted unverified; only the 5 % exploration floor can catch it. This
   cold-start blindness is visible directly in `scripts/demo.py` step 5, where a 100 %-tampering
   worker went undetected across 25 tasks. It is a limitation of the current estimator, not a bug.

3. **`no_verification` scoring 0.597 recall is not a contradiction.** Integrity checks run on
   *every* task regardless of policy, because they are cheap. That arm therefore still catches the
   crypto-detectable behaviours (`tamper_transit`); it catches none of the `tamper_payload` ones,
   which is why it still served 2.7 wrong results per run.

4. **H4 is supported.** Every crypto-detectable behaviour was caught: `tamper_transit` →
   `result_hash_mismatch`, `forge_signature` → `invalid_signature`, `stale` → `stale_timestamp`,
   `wrong_model` → `model_version_not_allowed`, `replay` → rejected via task-binding/nonce. Covered
   by both unit tests and the MVE.

5. **A bug this experiment caught.** The first MVE run reported `fixed_3` recall *below* `fixed_1`,
   which is impossible under a correct implementation. Investigation showed replica-level integrity
   failures were not being surfaced in the task outcome. Fixed in `services/scheduler/scheduler.py`;
   the table above is from the post-fix run. Recorded here because an unexplained non-monotonicity
   is exactly the kind of signal that should never be smoothed over.

6. **Not yet measured:** anomaly-detection quality (H2), statistically tested failure-tolerance
   (H3), CPU/memory usage, communication overhead, recovery time, Merkle batch-audit benchmarking,
   and all ablations. These are M4–M6 and are reported as absent, not estimated.

## 6. Statistical treatment

For any result reported as a finding: ≥ 5 seeds, median and IQR (or mean ± 95 % CI), and a
non-parametric test (Mann–Whitney U) for between-arm comparisons, with the n, statistic and
p-value stated. The M2 table above is 3 seeds and is presented as **preliminary**, without
significance claims.

## 7. Reproduction

```bash
python -m pip install -r requirements.txt
python -m pytest tests/ -q                       # 127 tests
python scripts/demo.py                            # guided walkthrough
python -m experiments.runners.mve --tasks 150 --seeds 3
```

Results land in `experiments/results/<experiment_id>.{json,csv}` with the full config, environment
(Python version, platform, model version, model accuracy) and per-seed rows embedded, so a run can
be traced back to its exact conditions.

## 8. Known threats to validity

See `RESEARCH_GAP.md` §5 and `docs/limitations.md`. In brief: synthetic fault model, synthetic
latency, single machine, small model, and detection metrics that are only meaningful against the
injector's own definition of misbehaviour.
