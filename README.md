# TrustProof-Cloud

**Risk-Adaptive Cryptographically Verifiable Machine Learning Inference in Distributed Cloud Environments**

A research prototype of a distributed ML inference platform where results come back from workers
that may be faulty, slow, or adversarial. Every result is cryptographically bound to its worker,
model version, input and timestamp — and instead of verifying everything by brute-force
replication, the platform estimates per-task risk and spends verification budget where it matters.

> **Status:** Milestone M2 of 8 complete, plus the full fault/attack simulator and a static
> research dashboard. The system runs end to end, **159 tests pass**, lint is clean, and two
> experiments produce real numbers — including one where the current policy **fails its own
> pre-registered criterion**. That result is reported, not hidden (see §5).
>
> Research prototype. Not audited. No novelty or patentability claim is made. Zero cost: no paid
> API, no GPU, no cloud account, no credit card.

---

## 1. The problem

When you offload inference to workers you don't control, you face two separate problems:

1. **Integrity** — was this result really produced by an authorised worker, on my input, with the
   model version it claims, and not replayed? *Cryptography solves this.*
2. **Correctness** — did the worker actually compute the right answer? *Cryptography cannot solve
   this.* A worker with a valid key can sign a wrong answer, and every signature check will pass.

The standard answer to (2) is `k`-way replication: run everything `k` times and compare. That
multiplies your compute bill by `k` for every task, including the overwhelming majority that were
never at risk.

**TrustProof-Cloud asks:** can a learned risk signal decide *per task* how much verification to
buy, and get most of the detection for a fraction of the cost?

## 2. Quick start (≈2 minutes, fully offline)

```bash
cd trustproof-cloud
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

pytest tests/ -q                                         # 159 tests
python scripts/demo.py                                   # guided walkthrough
python -m experiments.runners.mve --tasks 150 --seeds 3  # six-arm policy comparison
python -m experiments.runners.scenario_sweep             # 10 attack scenarios x 4 policies
python dashboard/generate_report.py                      # static HTML research report
uvicorn services.api.main:app --port 8000                # API + Swagger at /docs
```

No accounts, no downloads beyond PyPI, no containers required.

## 3. How it works

```
client ──▶ API Gateway ──▶ Scheduler ──select worker──▶ Worker W_i
                              │                           │  run model
                              │                           │  hash(result)
                              │                           │  Ed25519-sign envelope
                              │◀────── SignedResult ──────┘
                              ▼
                   Verification Service
                     ├─ signature valid?
                     ├─ payload matches committed result_hash?
                     ├─ nonce unseen, timestamp fresh?
                     └─ model_version allowed?
                              ▼
              risk-adaptive decision  ──▶  accept │ verify×1 │ verify×N │ re-execute │ quarantine
                              ▼
               Aggregator (trust-weighted agreement) ──▶ verdict + audit record ──▶ trust update
```

**The signed envelope** binds seven fields, each defeating a specific attack:

```json
{ "task_id": "...", "worker_id": "w-03", "model_version": "digits-logreg@1.0.0",
  "input_commitment": "blake2b-256...", "result_hash": "sha256...",
  "timestamp": "2026-09-25T18:12:19Z", "nonce": "128-bit hex" }
```

**The adaptive policy** scores risk from worker trust, anomaly signal, model uncertainty, task
sensitivity, latency deviation and verification history, then thresholds it:

```
r' < tau_low   -> accept unverified
r' < tau_high  -> one independent verification
otherwise      -> n replicas, scaled with risk (or quarantine on trust-floor breach)
plus: an epsilon=5% exploration floor, so a strategic worker cannot farm trust and then defect
```

Full spec, pseudocode and complexity analysis: `services/risk_model/risk.py` docstring and
`docs/research-methodology.md`.

## 4. What's actually built (M2)

| Component | State |
|---|---|
| Ed25519 signed envelopes, full verification chain | ✅ working, 43 crypto tests |
| Merkle batch auditing (RFC-6962-style domain separation) | ✅ working |
| AES-256-GCM artifact encryption, scrypt KDF | ✅ working |
| Replay protection (nonce cache + freshness window) | ✅ working |
| Worker registry, circuit breaker, health checks, quarantine | ✅ working |
| Scheduler: trust-weighted selection, timeouts, retries, disjoint replicas | ✅ working |
| Explainable EWMA trust engine | ✅ working |
| Risk-adaptive policy + 5 baseline arms | ✅ working (heuristic estimator) |
| Fault injector: 8 adversarial behaviours, 10 declared scenarios | ✅ working, labelled ground truth |
| Workload generator: uniform / bursty / skewed regimes | ✅ working |
| Static research dashboard (inline SVG, zero dependencies) | ✅ working |
| FastAPI gateway, API-key auth, input validation | ✅ working, 25 API tests |
| SQLAlchemy persistence + append-only audit trail | ✅ working |
| Two experiment runners (MVE + scenario sweep), CSV/JSON export | ✅ working |
| Anomaly detection, workload prediction, learned policy | ⬜ M4/M6 — `anomaly` feature is currently hard-wired to 0.0 |
| Redis Streams, MinIO, Prometheus, Streamlit dashboard | ⬜ M3/M7 — interfaces defined |
| Docker / Compose | ⚠️ authored, **not executed** (no Docker daemon in the dev sandbox) |

`docs/limitations.md` has the complete gap list.

## 5. Results so far — including the part that didn't work

`python -m experiments.runners.mve --tasks 150 --seeds 3`
8 workers (2 faulty, fault rate 0.4), 450 tasks per arm, seeds 42/43/44, CPU only.

| Arm | verification units/task | detection recall | FPR | wrong results served | p95 latency (ms) |
|---|---|---|---|---|---|
| no_verification | 0.022 | 0.597 | 0.000 | 2.7 | 13.6 |
| fixed_1 | 1.000 | **1.000** | 0.000 | **0.0** | 23.9 |
| fixed_3 | 2.978 | **1.000** | 0.000 | **0.0** | 44.4 |
| random_spotcheck | 0.389 | 0.774 | 0.000 | 4.0 | 21.8 |
| rule_based | 0.035 | 0.681 | 0.000 | 2.3 | 14.1 |
| **risk_adaptive** | **0.091** | 0.764 | 0.000 | 1.7 | 18.1 |

**Pre-registered criterion for H1:** adaptive must use ≤ 60 % of `fixed_3`'s verification units
*while keeping ≥ 90 % of its recall*.

**Verdict: half met.** Cost — 0.091 vs 2.978 units, a 97 % reduction, far beyond the requirement.
Recall — 0.764 vs 1.000, i.e. 76 %, **below the 90 % bar. H1 as stated is not met at M2.**

**Why**, diagnosed rather than glossed: the M2 risk estimator has no anomaly input yet
(`anomaly = 0.0`) and workers start at trust 0.70, so a freshly-defecting worker scores under
`tau_low` and gets accepted unverified — only the 5 % exploration floor can catch it. You can watch
this happen live in `scripts/demo.py` step 5. Fixing this cold-start blindness is precisely what
M4 (anomaly detection) and M6 (learned policy) exist to do.

Two things this table does establish:
- **H4 supported:** every cryptographically detectable attack was caught — tampered payloads
  (`result_hash_mismatch`), forged signatures, stale envelopes, wrong model versions, replays.
- **The cost lever is real:** `rule_based` and `risk_adaptive` cost near-nothing versus `fixed_3`,
  so there is genuine headroom to trade back into detection once the risk signal improves.

> **A bug this experiment caught.** The first run reported `fixed_3` recall *below* `fixed_1`,
> which is impossible if the code is correct. Replica-level integrity failures weren't being
> surfaced in the task outcome. Fixed, then re-run — the table above is post-fix. Recorded in
> `docs/research-methodology.md` §5 because unexplained non-monotonicity should never be smoothed
> over.

### The scenario sweep isolates exactly where it breaks

`python -m experiments.runners.scenario_sweep --tasks 80 --seeds 2` runs all 10 declared attack
scenarios against 4 policies. **80/80 threat-model expectation checks met** — every scenario the
threat model calls cryptographically detectable produced its predicted failure reason.

Detection recall, selected rows:

| Scenario | no_verification | fixed_1 | fixed_3 | risk_adaptive |
|---|---|---|---|---|
| modified_result (tampered in transit) | 1.000 | 1.000 | 1.000 | 1.000 |
| inconsistent_metadata (forged signature) | 1.000 | 1.000 | 1.000 | 1.000 |
| backdated_result (stale timestamp) | 1.000 | 1.000 | 1.000 | 1.000 |
| model_version_mismatch | 1.000 | 1.000 | 1.000 | 1.000 |
| stale_replay | 1.000 | 1.000 | 1.000 | 1.000 |
| **silent_wrong_result** (signed, but wrong) | **0.000** | **1.000** | **1.000** | **0.038** |

That last row is the whole thesis in one line. Cryptography catches everything it is theoretically
able to catch — and catches *nothing* when a worker simply computes the wrong answer and signs it
honestly. Only replication sees that, and the M2 adaptive policy currently declines to buy it
(recall 0.038, 8 wrong answers served per run). **Diagnosed, quantified, and left visible** as the
target for M4/M6.

Raw data with full config and environment: `experiments/results/*.json` / `*.csv`, and a
self-contained HTML report at `experiments/reports/report.html`.

### The dashboard

`python dashboard/generate_report.py` builds a single self-contained HTML file — inline CSS,
hand-built SVG charts, no JavaScript, no CDN, no network. It renders in any browser or sandboxed
preview, and it is committed as a reproducible artifact. Worker keys appear only as 16-character
fingerprints; a test asserts no private key material can reach it.

## 6. Repository layout

```
trustproof-cloud/
├── PROJECT_PLAN.md          milestones, assumptions, dependency list, risk register
├── ARCHITECTURE.md          services, request path, data model, local→cloud mapping
├── RESEARCH_GAP.md          problem statement, gap analysis, RQ1–RQ5, validity threats
├── THREAT_MODEL.md          trust assumptions, adversary model, T1–T12 matrix, non-claims
├── crypto/                  hashing, keys, signatures, merkle_tree, encryption, replay_protection
├── ml/                      inference_model (+ M4: anomaly detection, workload prediction)
├── services/
│   ├── api/                 FastAPI gateway
│   ├── scheduler/           orchestration, registry, queue port
│   ├── workers/             honest + fault-injected workers
│   ├── verifier/            integrity checks, agreement, Merkle batching
│   ├── trust_engine/        explainable EWMA trust
│   ├── risk_model/          risk estimation + all policy arms
│   └── common/              config, ORM models, schemas, composition root
├── simulator/               fault injection, workload generator, 10 attack scenarios
├── experiments/
│   ├── configs/             pre-registered experiment + ablation configs
│   ├── runners/             MVE runner, scenario sweep → CSV/JSON
│   ├── results/             committed raw results (the evidence behind §5)
│   └── reports/             generated HTML research report
├── dashboard/               dependency-free static report generator
├── tests/                   159 tests incl. research-integrity guards
├── docs/                    protocol, methodology, limitations, deployment, prior-art checklist
└── scripts/demo.py          guided walkthrough
```

## 7. Research-integrity guards

The test suite protects the *validity of the results*, not just the behaviour of the code:

- **No ground-truth leakage** — AST analysis asserts that no decision-making module can read the
  fault injector's labels, and that the scheduler never branches on them.
- **No global RNG seeding** in library code — randomness is always injected, so seeding means
  something.
- **Reproducibility** — same seed ⇒ identical decision traces; different seeds ⇒ different traces
  (both asserted).
- **No embedded key material** anywhere in the source.
- **No usable default** for the artifact encryption key.
- **No unsupported claims** — a test scans the docs for asserted novelty, patentability and
  absolute-security language, and fails if any appears outside an explicit disclaimer.

## 8. Explicit non-claims

- **Not novel, not patentable, not "the first".** No prior-art search has been done;
  `docs/prior-art-checklist.md` specifies the search that would be required first.
- **No security guarantees** beyond the assumptions in `THREAT_MODEL.md`. Never audited.
- **A local Docker stack is not a production cloud cluster.** See `ARCHITECTURE.md` §6 for where
  the analogy breaks.
- **A trust score is not evidence of malicious intent** — it's a behavioural statistic under a
  synthetic fault model.
- **No third-party free tier is permanently free or risk-free.**
- All numbers here are **simulation results under an injected fault model**, on synthetic latency,
  from 3 seeds, with no significance testing.

## 9. Next milestone (M3)

Worker registry as a service, Redis Streams queue adapter, containerised workers, deadline
propagation, and the remaining fault scenarios (queue backlog, network delay) — keeping the suite
green and the system runnable throughout.

## 10. Licence

Apache-2.0. Datasets: scikit-learn `digits` (bundled, public-domain-derived) and synthetic data.
All dependencies are free and OSI-licensed — see `PROJECT_PLAN.md` §6.
