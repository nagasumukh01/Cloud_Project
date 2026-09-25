# ARCHITECTURE.md — TrustProof-Cloud

> Canonical architecture reference. `docs/architecture.md` is a symlink-equivalent pointer to this
> file to satisfy the requested repository layout.

## 1. Design principles

1. **Ports and adapters.** Every infrastructure concern (queue, blob store, clock, key store) sits
   behind a small Python `Protocol`. The MVP uses in-process/SQLite/local-filesystem adapters;
   M3+ swaps in Redis Streams / MinIO without touching domain logic.
2. **Domain logic is transport-agnostic.** Scheduling, trust, risk and verification are pure
   functions over dataclasses. They are unit-testable without a server running.
3. **Security-relevant state is append-only.** Verification outcomes and signature records are
   never updated in place; this is what makes the audit trail and Merkle batching meaningful.
4. **Ground truth is quarantined.** Fault-injector labels live in a table that policy code has no
   import path to.

## 2. Logical services

| # | Service | Responsibility | MVP form (M2) | Target form (M3+) |
|---|---|---|---|---|
| 1 | API Gateway | Auth (API key), input validation, task submission, status, results | FastAPI app | same, + rate limit |
| 2 | Task Manager / Scheduler | Task lifecycle, worker selection, replica fan-out, retry, timeout | in-process module | separate container, Redis Streams consumer |
| 3 | Risk Prediction Service | Per-task risk score from features | heuristic scorer w/ stable interface | RF / cost-sensitive classifier |
| 4 | Worker Registry | Registration, public keys, capabilities, health, discovery | SQLite table | + heartbeat TTL, circuit breaker |
| 5 | Worker Execution Service | Runs the ML model, signs the result envelope | in-process worker objects | container per worker |
| 6 | Trust Scoring Service | Explainable per-worker trust from history | EWMA over outcomes | + anomaly-score fusion |
| 7 | Verification Service | Signature, hash, replay, cross-replica agreement | implemented | + Merkle batch verify |
| 8 | Result Aggregator | Majority / weighted agreement across replicas, final verdict | implemented (simple majority) | trust-weighted quorum |
| 9 | Fault & Attack Simulator | 10 controlled scenarios, reset-after-run | tamper + crash (2 of 10) | all 10 |
| 10 | Monitoring | Counters, latency histograms, health | SQLite + `/metrics` JSON | Prometheus + Grafana |
| 11 | Experiment Runner | Arms, seeds, repetitions, CSV/JSON export | skeleton | full |
| 12 | Dashboard | Research UI | — | Streamlit |

## 3. Request path (M2, verified working)

```
client ──POST /tasks──▶ API Gateway
                          │ validate (pydantic), authn (X-API-Key)
                          ▼
                       Scheduler ── select_worker(registry, trust, risk) ──▶ Worker W_i
                          │                                                     │
                          │                                             run model → result
                          │                                             hash(result)
                          │                                             Ed25519 sign envelope
                          │                                                     │
                          │◀──────────── SignedResult ──────────────────────────┘
                          ▼
                    Verification Service
                       ├─ signature valid?      (Ed25519 over canonical bytes)
                       ├─ result_hash matches payload?
                       ├─ nonce unseen & timestamp fresh?   (replay protection)
                       └─ model_version allowed?
                          ▼
                  risk-adaptive decision: {ACCEPT | VERIFY_1 | VERIFY_N | RE_EXECUTE | QUARANTINE}
                          ▼  (if replication requested, fan out to disjoint workers and compare)
                    Result Aggregator ──▶ persist task + verdict + audit record ──▶ trust update
```

## 4. The signed envelope

The bytes that are signed are a canonical JSON serialisation (sorted keys, no whitespace, UTF-8) of:

```json
{
  "task_id":          "uuid",
  "worker_id":        "w-03",
  "model_version":    "digits-logreg@1.0.0",
  "input_commitment": "blake2b-256 hex of canonical input",
  "result_hash":      "sha256 hex of canonical result payload",
  "timestamp":        "RFC3339 UTC",
  "nonce":            "128-bit hex, unique per envelope"
}
```

Binding all seven fields is what defeats: result swapping (result_hash), cross-task replay
(task_id + nonce), stale replay (timestamp window), identity spoofing (signature + registry key),
model downgrade (model_version) and input substitution (input_commitment). Rationale and the
attacks each field stops: `docs/cryptographic-protocol.md`.

## 5. Data model (SQLite, SQLAlchemy)

- `workers(id, public_key, capabilities, status, registered_at, last_seen)`
- `tasks(id, payload_ref, task_type, sensitivity, status, created_at, completed_at, final_result, verdict)`
- `attempts(id, task_id, worker_id, role[primary|replica], result_hash, latency_ms, created_at)`
- `signatures(id, attempt_id, envelope_json, signature_hex, verified, failure_reason)`
- `verifications(id, task_id, decision, replicas_used, agreed, cost_units, detected_tamper)`
- `trust_events(id, worker_id, event_type, delta, score_after, created_at)`
- `ground_truth(id, attempt_id, was_tampered, scenario)`  ← **quarantined; evaluation-only**
- `nonces(nonce, worker_id, seen_at)` ← replay protection, TTL-pruned

## 6. Mapping local → real cloud (and where the analogy breaks)

| Local component | Cloud analogue | Honest limitation |
|---|---|---|
| Docker Compose service | K8s Deployment / ECS Service | No real scheduler, node failure, or network partition. |
| In-process queue → Redis Streams | SQS / Kafka / Managed Redis | No cross-AZ durability, no consumer-group rebalancing at scale. |
| SQLite → Postgres | RDS / Aurora | Single-writer; no replication or failover testing. |
| Local MinIO | S3 | No IAM, versioning-at-scale, or cross-region durability. |
| Simulated worker crash | Node/pod eviction | Failures are injected, not organic; timing distributions are synthetic. |
| API key auth | IAM / OIDC / mTLS | Coarse-grained; no key management service. |

**A local Docker environment is not equivalent to a production cloud cluster.** All results are
reported as *simulation results under a stated fault model*, not as production measurements.

## 7. Failure handling (M3 target, interfaces stubbed in M2)

- Per-attempt timeout with deadline propagation.
- Bounded retries with exponential backoff + jitter; retries go to a *different* worker.
- Circuit breaker per worker: `CLOSED → OPEN` after `n` consecutive failures, `HALF_OPEN` probe.
- Health checks: `/health` (liveness) and `/ready` (dependencies) per service; registry TTL
  marks silent workers `UNREACHABLE`.
- Quarantine is *simulated and reversible* — it downgrades a worker's eligibility, and is never
  presented as evidence of malicious intent.
