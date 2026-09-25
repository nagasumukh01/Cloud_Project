# THREAT_MODEL.md — TrustProof-Cloud

> Canonical threat model. `docs/threat-model.md` points here.

## 1. System model

Actors:

- **Client** — submits inference tasks, trusts the control plane, wants a correct result.
- **Control plane** — API gateway, scheduler, registry, verifier, aggregator, trust engine.
- **Workers** — `N` independent execution nodes, each holding an Ed25519 private key; some may be
  faulty or adversarial.
- **Adversary** — controls a subset `f < N` of workers and the network between workers and the
  control plane.

## 2. Trust assumptions (explicit)

| Component | Assumed | Justification / consequence |
|---|---|---|
| Control plane | **Trusted** | It performs verification; if it is compromised, the scheme provides nothing. A malicious control plane is out of scope (would require client-side verification + zkML/TEE). |
| Worker private keys | Generated on the worker, never leave it | Key compromise is modelled as a *fully adversarial worker*, not separately. |
| Worker public keys | Authentically registered | Registration bootstrap is trusted (enrolment token). A real system needs PKI/attestation; see Limitations. |
| Cryptographic primitives | Ed25519, SHA-256, BLAKE2b, AES-256-GCM, HMAC-SHA256 are secure | Standard assumptions; no custom cryptography is used or invented. |
| Clock | Loosely synchronised, skew ≤ `SKEW_TOLERANCE_S` (default 30 s) | Required for timestamp-freshness checks; nonce cache is the primary replay defence, timestamps are secondary. |
| Randomness | OS CSPRNG (`secrets`, `os.urandom`) available | Used for nonces, keys, AES-GCM IVs. |

## 3. Adversary capabilities

**Can:** return arbitrary results from controlled workers; replay previously valid signed
envelopes; delay, drop, reorder or duplicate messages; read messages in transit (integrity, not
confidentiality, is the primary goal of the envelope); collude across controlled workers; behave
honestly most of the time and defect selectively (stealth attacker); crash or stall.

**Cannot:** forge Ed25519 signatures without the private key; find SHA-256/BLAKE2b collisions or
preimages; break AES-GCM; compromise the control plane, its database, or its verification logic;
observe or influence the fault-injector ground-truth table; exceed `f < N/2` controlled workers in
experiments where majority agreement is used (stated per experiment).

## 4. Assets

| Asset | Property protected | Mechanism |
|---|---|---|
| Inference result | Integrity, authenticity | Ed25519 signature over result hash |
| Task ↔ result binding | Integrity | `task_id` + `input_commitment` inside signed envelope |
| Model provenance | Integrity | `model_version` inside signed envelope + allow-list check |
| Freshness | Anti-replay | 128-bit nonce cache + timestamp window |
| Batch audit log | Integrity, cheap auditability | Merkle tree over per-attempt envelope hashes |
| Local artifacts (cached inputs, model blobs, logs) | Confidentiality at rest | AES-256-GCM with key from env/keyfile, never hardcoded |
| Worker private keys | Confidentiality | Stored per worker outside the repo; never logged, never surfaced in the dashboard or API |
| API access | Authorisation | API key header; per-role scopes (submit / read / admin) |

## 5. Attack → defence → residual risk matrix

| # | Attack | Defence in TrustProof-Cloud | Residual risk |
|---|---|---|---|
| T1 | Result tampering in transit | Signature covers `result_hash`; mismatch rejected | None if primitives hold |
| T2 | Malicious worker signs a *wrong but well-formed* result | **Not** stopped by crypto. Stopped probabilistically by replication/re-execution driven by the adaptive policy | Undetected if policy chooses `accept` and worker's history looks clean → this is the central measured quantity |
| T3 | Replay of a stale valid envelope | Nonce cache (exactly-once per nonce) + timestamp freshness window | Nonce store must be durable; TTL pruning creates a replay window after TTL → documented, TTL ≫ task lifetime |
| T4 | Cross-task replay (valid result for task A returned for task B) | `task_id` + `input_commitment` bound in envelope | None if primitives hold |
| T5 | Worker identity spoofing | Signature verified against registry public key; unknown key ⇒ reject | Registration bootstrap is trusted (see §2) |
| T6 | Model downgrade / version mismatch | `model_version` in envelope + allow-list per task type | Worker could run a different model and *claim* the right version → falls back to T2 detection |
| T7 | Metadata mutation (timestamp, worker id) | All metadata is inside the signed bytes | None if primitives hold |
| T8 | Collusion: `k` malicious replicas agree on the same wrong result | Trust-weighted, *disjoint* replica selection; workers with correlated failure history are not co-selected | Defeated by a sufficiently large colluding majority — an explicit, stated limit |
| T9 | Sybil / mass worker registration | Enrolment token + registration rate limit (M3) | Not a strong Sybil defence; no proof-of-work or identity attestation |
| T10 | Denial of service via queue flooding | Rate limiting, queue bounds, circuit breaker, bounded retries | Not resistant to a serious DDoS; out of scope |
| T11 | Stealth adversary that games the trust score | Exploration term in worker selection: a small random fraction of tasks is verified regardless of risk | Cannot be eliminated; the floor exploration rate bounds long-run undetected defection and is an ablation parameter |
| T12 | Artifact theft from local disk | AES-256-GCM encryption of artifacts at rest | Key management is basic (env var / local keyfile); no HSM/KMS |

## 6. Out of scope

Malicious control plane; side channels (timing, cache, power); physical attacks; supply-chain
compromise of dependencies; model extraction/inversion and membership inference; adversarial
examples against the inference model itself; full Sybil resistance; production-grade DDoS defence;
formal verification of the protocol.

## 7. Privacy statement

AES-GCM at rest protects confidentiality **only against an attacker without the key**. It does not
provide privacy against the control plane, does not anonymise data, and does not protect data
in use. No differential-privacy claim is made. If DP or secure aggregation is added later, its
mechanism, ε/δ parameters, composition accounting and limitations must be documented before any
privacy claim is stated.

## 8. Security non-claims

- This is a research prototype. It has not been audited, pen-tested, or formally analysed.
- A trust score is a behavioural statistic under a synthetic fault model. **It is not evidence of
  malicious intent** and must not be used to make consequential judgements about real operators.
- Detection rates measured here hold *for the injected attack model only*.
