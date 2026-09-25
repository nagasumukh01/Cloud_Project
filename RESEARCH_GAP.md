# RESEARCH_GAP.md — TrustProof-Cloud

## 1. Problem statement

When ML inference is offloaded to a pool of heterogeneous, partially untrusted cloud workers
(spot instances, volunteer/edge nodes, multi-tenant serverless backends, third-party inference
vendors), the submitting party cannot directly observe whether a returned prediction was actually
produced by the claimed model on the claimed input. Two independent problems appear:

1. **Integrity** — was the result produced by an authorised worker, from the stated input, with the
   stated model version, and not replayed or altered in transit or at rest?
2. **Correctness under adversarial or faulty execution** — a worker can sign a *correct-looking but
   wrong* result. Signatures prove provenance, not computational honesty.

Problem (1) is solved by standard cryptography. Problem (2), in practice, is solved by
**redundant execution**: run the task on `k` workers and compare. That is a blunt instrument —
`k`-fold replication multiplies compute cost by `k` for every task, including the overwhelming
majority of low-risk tasks run by well-behaved workers.

## 2. The gap this project targets

The literature families that touch this problem each leave a specific hole:

| Family | What it gives | What it does not give |
|---|---|---|
| Verifiable computation / zkML (SNARK-proved inference) | Cryptographically strong correctness | Prover cost is orders of magnitude above inference; infeasible on a CPU budget and for general models today |
| Trusted execution environments (SGX/SEV/Nitro) | Hardware-attested execution | Requires specific paid hardware; side-channel and attestation-trust caveats; not available in a zero-cost student setting |
| BFT / N-version replication (classical distributed systems) | Tolerates `f` faulty of `3f+1` | Static redundancy factor; cost paid uniformly regardless of risk |
| Reputation / trust systems for volunteer computing (BOINC-style spot-checking) | Cheap probabilistic checking | Typically fixed or randomly-scheduled spot-check rates; usually not cryptographically bound to model version/input; rarely uses learned risk signals |
| ML-based anomaly detection for cloud workers | Detects behavioural outliers | Detection is decoupled from the *verification-spending decision* and from cryptographic evidence |

**The gap:** there is no readily available, reproducible, zero-cost research artifact that *closes
the loop* — i.e. uses learned per-task/per-worker risk estimates to decide, online and per task,
**how much cryptographic and replicative verification to spend**, and then evaluates that decision
policy against the full ladder of fixed baselines under a controlled fault/attack model.

## 3. Research contribution (as claimed — deliberately modest)

We propose and evaluate a **risk-adaptive cryptographic verification and worker-selection
mechanism**: an online policy that maps `(worker trust, anomaly score, workload-prediction
deviation, model uncertainty, task sensitivity, queue state, verification history)` to a
verification action in `{accept, verify×1, verify×N, re-execute, retry-elsewhere, quarantine}`,
where every executed attempt is bound to an Ed25519-signed envelope committing to task, input,
model version, result and freshness.

We claim, subject to experimental confirmation:
- a **cost/detection trade-off curve** that dominates fixed replication over a stated risk regime, and
- an **open, reproducible, laptop-scale harness** for studying this trade-off.

We explicitly **do not** claim: novelty over the full prior art, patentability, security guarantees
beyond the threat model, or that the results transfer to production cloud workloads.
`docs/prior-art-checklist.md` lists the search (IEEE Xplore, ACM DL, USENIX, arXiv, Google Patents,
Espacenet, USPTO/WIPO classes) that must be completed before any novelty statement is made. **That
search has not been performed as part of this project.**

## 4. Research questions

- **RQ1** Can a learned risk signal reduce mean verification cost per task at equal tampering-detection recall, relative to fixed `k`-replication?
- **RQ2** Does ML-based worker anomaly detection beat a tuned statistical threshold on precision/recall/FPR under the same fault model?
- **RQ3** Does risk-aware worker *selection* (not just verification) improve task completion rate and p95 latency under injected worker failures?
- **RQ4** What is the measured overhead of Ed25519 signing/verification and Merkle batch verification relative to inference time, as batch size grows?
- **RQ5** Does the adaptive policy degrade gracefully — i.e. keep latency bounded — when the fraction of faulty workers rises?

RQ1–RQ5 map to hypotheses H1–H5 in `docs/research-methodology.md`, each with a pre-registered,
measurable success criterion.

## 5. Threats to validity (stated up front)

- **Construct validity:** "risk" is defined by our own injector; a real adversary need not behave like it. Mitigated by testing several attack mixes, including one adaptive/stealthy attacker.
- **Internal validity:** label leakage from the injector into the policy. Mitigated by table quarantine + an enforcing test.
- **External validity:** single-machine simulation; synthetic latency distributions; small models. Explicitly not generalised to production clusters.
- **Statistical validity:** multiple seeds, reported with dispersion (median + IQR, or mean ± 95 % CI), not single runs.
