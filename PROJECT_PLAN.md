# PROJECT_PLAN.md — TrustProof-Cloud

**Full title:** TrustProof-Cloud: Risk-Adaptive Cryptographically Verifiable Machine Learning
Inference in Distributed Cloud Environments

**Status of this document:** living plan. Updated at the end of every milestone.
**Last updated:** Milestone M2 complete, plus the fault/attack simulator and static reporting pulled forward from M3/M7 (see checklist below).

---

## 1. One-paragraph summary

TrustProof-Cloud is a cloud-native, distributed ML inference platform in which a pool of
independent (and possibly unreliable or adversarial) workers execute inference tasks. Every
result is cryptographically bound to the worker identity, the model version, the input, and a
timestamp. Instead of verifying every result by fixed replication — which is expensive — the
platform estimates a *per-task risk* from ML signals (worker anomaly score, trust history,
predicted latency deviation, model uncertainty, task sensitivity) and spends verification budget
only where the expected damage is highest. The research question is whether this risk-adaptive
verification achieves detection quality comparable to fixed replication at materially lower
verification overhead.

## 2. Scope decisions (and why)

| Decision | Choice | Rationale |
|---|---|---|
| Cost | Strictly zero-cost, offline-capable | Requirement. No paid API, no GPU, no billing-enabled cloud. |
| Primary environment | Local simulation (Mode A) | Reproducibility + zero cost. Docker Compose is the packaging target; plain Python processes are the fallback when Docker is unavailable. |
| Public cloud | Optional, read-only demo only (Mode B) | Free tiers cannot host long-running distributed workers reliably; documented in `docs/deployment.md`. |
| Datasets | Synthetic + openly licensed (scikit-learn `digits`, `covtype` subset, synthetic tabular streams) | No licensing or download-cost risk; CPU-friendly. |
| ML models | scikit-learn first (LogReg/RandomForest/IsolationForest), PyTorch/XGBoost only if they add measurable value | Laptop-CPU budget; avoids heavy deps for the core result. |
| Crypto | Ed25519 + SHA-256/BLAKE2b + HMAC + AES-GCM + Merkle trees, all from `cryptography`/`hashlib` | Established primitives only. No custom cryptography. |
| Transport (MVP) | In-process queue behind a `TaskQueue` interface | Keeps M2 runnable with zero infrastructure; Redis Streams is a drop-in implementation at M3. |

**Assumption log** (things the prompt left open, resolved toward "simplest free option"):
- A1. "Task sensitivity" is a task-level attribute in `{low, medium, high}` supplied by the client, defaulting to `medium`.
- A2. Ground truth for detection metrics comes from the fault injector, which labels each task as tampered / not tampered. This label is *never* visible to the policy.
- A3. "Cost" is measured in *verification units* (one worker execution = 1 unit) and wall-clock ms, not currency.
- A4. Trust score is an explainable weighted statistic, not an ML black box (Section 5C of the brief).

## 3. Non-goals

- Not a CRUD app, chatbot, or monitoring dashboard clone.
- Not a production security product. No claim of security guarantees beyond what the threat model states.
- No novelty/patentability claim. `docs/prior-art-checklist.md` defines the search that *would* be required before any such claim; it has not been performed.
- No zero-knowledge proofs or verifiable computation (zkML) in the core system — out of CPU budget; discussed as future work.

## 4. Minimum Viable Experiment (MVE)

The smallest experiment that can falsify or support the core claim. Defined **before** coding the policy.

- **Setup:** 8 simulated workers, of which `k` are faulty (tampering with probability `p_tamper`).
  Workload: 500 image-classification tasks (sklearn `digits`, LogisticRegression, CPU).
- **Arms:** (1) no verification, (2) fixed 1-replica verification, (3) fixed 3-replica verification,
  (4) random worker selection + fixed 1 replica, (5) rule-based, (6) risk-adaptive (proposed).
- **Controlled:** same seed, same task stream, same worker pool, same model version per arm.
- **Metrics:** tampered-result detection recall, false-positive rate, mean verification units per
  task, p50/p95 end-to-end latency, task success rate, re-execution count.
- **Success criterion (pre-registered):** the adaptive arm reaches ≥ 90 % of the detection recall of
  fixed 3-replica while using ≤ 60 % of its verification units, at p95 latency no worse than +20 %
  relative to fixed 1-replica. If it does not, that is reported as a negative result.

Full protocol: `docs/research-methodology.md`. Hypotheses H1–H5 with measurable criteria are in
the same file.

## 5. Milestone checklist

| # | Milestone | Exit criteria | State |
|---|---|---|---|
| M1 | Planning | PROJECT_PLAN, ARCHITECTURE, RESEARCH_GAP, THREAT_MODEL, MVE, dependency list | ✅ done |
| M2 | Minimum working system | API + scheduler + 2 workers + 1 ML task + result store + Ed25519 signature verification + passing tests | ✅ done |
| M2.5 | Simulator + reporting (pulled forward) | 10 declared attack scenarios, labelled ground truth, workload regimes, scenario sweep runner, dependency-free HTML report | ✅ done |
| M3 | Distributed architecture | Redis Streams queue adapter, containerised workers, deadline propagation, queue-backlog and network-delay scenarios | ⬜ next |
| M4 | ML components | Workload prediction (baseline vs RF/XGB), anomaly detection (threshold vs IsolationForest vs AE), trust engine, metrics recorded | ⬜ |
| M5 | Cryptography (full) | Merkle batching, replay protection windows, key rotation, AES-GCM artifact store, benchmark individual vs batch verification | ⬜ |
| M6 | Adaptive mechanism | Formal spec + pseudocode + complexity + config + ablations, vs all baselines | ⬜ |
| M7 | Dashboard & experiments | Streamlit dashboard, experiment runner, CSV/JSON export, charts | ⬜ |
| M8 | Deployment & paper pack | Dockerfile, compose, local verified run, optional free read-only demo, full docs set | ⬜ |

Rule: the system must be runnable and the full test suite green at the end of every milestone.

## 6. Free dependency list

Runtime (all OSI-licensed, all free, all CPU):

| Package | Licence | Used for | Required at |
|---|---|---|---|
| fastapi | MIT | API gateway, service HTTP interfaces | M2 |
| uvicorn | BSD-3 | ASGI server | M2 |
| pydantic (v2) | MIT | schema + input validation | M2 |
| sqlalchemy | MIT | persistence layer over SQLite | M2 |
| cryptography | Apache-2.0 / BSD | Ed25519, AES-GCM, HMAC | M2 |
| numpy / pandas | BSD-3 | data handling, metrics | M2 |
| scikit-learn | BSD-3 | inference model, IsolationForest, RF | M2 |
| networkx | BSD-3 | service/task graph for architecture view | M7 |
| matplotlib | PSF-like | charts | M7 |
| streamlit | Apache-2.0 | research dashboard | M7 |
| pytest (+ hypothesis) | MIT | tests, property tests | M2 |
| redis (client) | MIT | Redis Streams queue backend | M3 |
| xgboost | Apache-2.0 | optional stronger workload predictor | M4 |
| torch (CPU) | BSD-3 | optional autoencoder / temporal model | M4, optional |
| prometheus-client | Apache-2.0 | metrics endpoint | M7 |
| mlflow | Apache-2.0 | optional local experiment tracking | M4, optional |

Infrastructure (local, free): Docker CE, Docker Compose, Redis (OSS image), MinIO (AGPL, local
only), Prometheus, Grafana OSS. `stdlib` only: `hashlib` (SHA-256/BLAKE2b), `hmac`, `secrets`.

**Nothing in this list requires a credit card, an account, or a paid tier.**

## 7. Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| Docker unavailable in the dev sandbox | Cannot validate compose | Ship compose files but make the pure-Python launcher (`scripts/run_local.py`) the verified path; mark compose as "authored, not executed here". |
| Adaptive policy shows no benefit | Core hypothesis fails | Pre-registered criteria; report negative result honestly (Section 10 of the brief). |
| Detection metrics inflated by leakage of injector labels | Invalid research | Labels stored in a separate table never read by policy code; test `test_no_label_leakage` enforces it. |
| Overfitting to one synthetic workload | Weak external validity | ≥ 3 workload regimes (uniform, bursty, skewed) and ≥ 5 seeds per arm. |
| Scope explosion | Nothing finished | Strict milestone gates; optional items (torch, MLflow, Grafana) can be dropped without breaking claims. |
