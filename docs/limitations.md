# Limitations

Stated plainly, because a research artifact that overstates itself is worth less than one that
draws its own boundaries.

## 1. Simulation, not production

- Everything runs on **one machine**. There is no real network, no cross-AZ latency, no partition,
  no clock drift, no noisy neighbour, no node eviction.
- Worker service time is **synthetic** (`gauss(base, jitter)`, capped at 50 ms to keep tests fast).
  Latency figures are therefore internally comparable between arms but have **no external meaning**.
- **A local Docker Compose stack is not equivalent to a production Kubernetes/AWS cluster.** The
  mapping table in `ARCHITECTURE.md` §6 lists exactly where the analogy breaks.

## 2. The adversary is one we wrote

Detection rates are measured against **our own fault injector**. A real adversary is not obliged to
tamper at a fixed rate, to act independently, or to be detectable by replication at all. In
particular:

- The injector's faulty workers currently defect *randomly*, not strategically. A worker that
  defects only on tasks it predicts will not be verified is far harder, and the stealth-attacker
  scenario is written up but not yet implemented.
- Collusion is modelled only as independent workers happening to be faulty. Coordinated colluders
  agreeing on the *same* wrong answer would defeat majority agreement, and the current experiments
  do not measure that.

## 3. Known gaps in the current build (M2)

| Area | Status |
|---|---|
| Anomaly detection (IsolationForest / autoencoder) | **Not implemented.** The `anomaly` risk feature is hard-wired to 0.0. |
| Workload prediction (RF / XGBoost / LSTM) | **Not implemented.** The `queue_load` feature is hard-wired to 0.0. |
| Learned policy (contextual bandit / cost-sensitive) | **Not implemented.** Only the documented heuristic baseline exists. |
| Redis Streams / RabbitMQ | Interface defined (`TaskQueue`), in-memory adapter only. |
| MinIO / object storage | Not wired in. |
| Prometheus / Grafana / OpenTelemetry | `/metrics` returns JSON, not Prometheus exposition format. |
| Streamlit dashboard | Not built. |
| Key rotation | Documented design only. |
| Merkle batch-vs-individual benchmark | Tree implemented and tested; **timing comparison not run**, so no overhead numbers are claimed. |
| Fault scenarios | 8 of the 10 required behaviours exist; queue backlog and network delay need the M3 queue. |
| Docker Compose | Authored, **not executed** in the development sandbox (no Docker daemon available). Marked unverified. |
| CPU/memory/communication-overhead metrics | Not collected. |

## 4. Where the current results fall short

The pre-registered H1 criterion was **not met** at M2: the adaptive policy achieves ~97 % cost
savings against `fixed_3` but only 76 % of its detection recall, against a ≥ 90 % requirement.
The cause is diagnosed (cold-start blindness with no anomaly signal) and is the specific target of
M4/M6. It is not presented as a success.

## 5. Cryptographic caveats

- Signatures prove **provenance, not correctness**. A worker with a valid key can sign a wrong
  answer and every check will pass.
- Result payloads are rounded to 6 decimal places before hashing so honest workers agree byte-wise.
  Tampering below that precision is invisible to the hash.
- The nonce cache is in-process in M2 and is cleared by a restart, which re-opens a replay window
  bounded by the freshness check.
- Worker enrolment is **trusted**. There is no PKI, no attestation, and no real Sybil resistance.
- AES-GCM at rest is not privacy from the control plane and is not differential privacy.
- **Nothing here has been audited, pen-tested, or formally verified.**

## 6. Statistical limitations

The M2 table is 3 seeds, one workload regime, one fault mix. No significance testing has been
performed and none is claimed. Any finding promoted to a conclusion needs ≥ 5 seeds, multiple
workload regimes, and a stated test statistic.

## 7. Claims explicitly NOT made

- Not novel, not patentable, not "the first" anything. No prior-art search has been performed;
  `docs/prior-art-checklist.md` defines what such a search would require.
- No security guarantee beyond the assumptions in `THREAT_MODEL.md`.
- No claim that a trust score indicates malicious intent. It is a behavioural statistic computed
  under a synthetic fault model.
- No claim that any third-party free tier is permanently free or risk-free.
