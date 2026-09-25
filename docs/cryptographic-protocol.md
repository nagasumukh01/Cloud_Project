# Cryptographic Protocol

All primitives are standard and taken from `cryptography` (Apache-2.0/BSD) and the Python
standard library. **No cryptography is invented here.** No security guarantee is claimed beyond
the assumptions in `THREAT_MODEL.md`.

## 1. Primitives

| Purpose | Primitive | Rationale |
|---|---|---|
| Result authenticity | **Ed25519** | Deterministic, no nonce-reuse foot-gun (unlike ECDSA), 32-byte keys, 64-byte signatures, ~50 µs sign / ~130 µs verify on CPU |
| Result commitment | **SHA-256** | Ubiquitous, 256-bit collision target |
| Input commitment | **BLAKE2b-256** | Fast on CPU; a *different* function from the result hash keeps the two commitment domains separate |
| Batch audit | **Merkle tree (SHA-256, RFC-6962 style)** | O(log N) inclusion proofs |
| Artifact confidentiality | **AES-256-GCM** | AEAD: confidentiality + integrity in one pass |
| Password-derived keys | **scrypt** (n=2¹⁴, r=8, p=1) | Memory-hard KDF |
| Randomness | `secrets` / `os.urandom` | OS CSPRNG |

## 2. Canonicalisation (why it comes first)

Signatures are over bytes, not objects. If two parties serialise the same logical result
differently, verification fails for a non-security reason. We therefore define one canonical
encoding (`crypto/hashing.py`): JSON with sorted keys, `(",", ":")` separators, UTF-8, no
NaN/Infinity, and typed rejection of anything not canonicalisable.

Result payloads are additionally **rounded to 6 decimal places** before hashing. Without this,
two honest workers could disagree byte-wise on floating-point noise, and every replica comparison
would report a false disagreement. This is a deliberate trade-off: it means tampering below the
6th decimal place of a confidence score is invisible to the hash. Since the `label` field is an
integer and is what the result actually asserts, that residual is accepted and documented.

## 3. The signed envelope

```
envelope = {
  task_id, worker_id, model_version,
  input_commitment, result_hash, timestamp, nonce
}
sigma = Ed25519-Sign(sk_worker, canonical_bytes(envelope))
message_to_client = { envelope, sigma, payload }
```

Each field defeats a specific attack:

| Field | Attack prevented | Threat ID |
|---|---|---|
| `result_hash` | payload substitution after signing | T1 |
| `task_id` | returning a valid result for a different task | T4 |
| `input_commitment` | computing on a different input than requested | T4 |
| `worker_id` + signature | identity spoofing | T5 |
| `model_version` | silent model downgrade | T6 |
| `timestamp` | replay of an old-but-valid result | T3 |
| `nonce` | replay within the freshness window | T3 |

Anything *outside* the envelope is unauthenticated and must not be trusted.

## 4. Verification algorithm

```
VERIFY(signed, expected_task, expected_input, allowed_models, now):
  1. shape check (field presence, hex formats, parseable timestamp)   -> MALFORMED
  2. public key lookup in registry                                    -> UNKNOWN_WORKER
  3. Ed25519 verify over canonical_bytes(envelope)                    -> BAD_SIGNATURE
  4. SHA-256(canonical_bytes(payload)) == envelope.result_hash        -> HASH_MISMATCH
  5. envelope.task_id == expected_task                                -> TASK_MISMATCH
  6. envelope.input_commitment == expected_input                      -> INPUT_MISMATCH
  7. envelope.model_version in allowed_models                         -> MODEL_NOT_ALLOWED
  8. -skew <= now - timestamp <= max_age                              -> STALE
  9. (worker_id, nonce) not previously seen; then claim it            -> REPLAY
```

Design points:

- **Ordering.** Cheap structural checks precede the ~130 µs signature verification, so malformed
  or unknown-worker traffic cannot force expensive elliptic-curve work (a cheap DoS lever).
- **Step 4 is the one people forget.** A valid signature only proves the *envelope* is authentic.
  A worker can sign envelope A and ship payload B. Re-hashing the payload is what closes that gap.
- **Nonce is claimed last.** Registering a nonce for an envelope that fails an earlier check would
  let an attacker burn a victim worker's nonce space. The nonce is consumed only on full success.
- **Constant-time comparison** (`hmac.compare_digest`) is used for all hash/id equality checks.
- The verifier returns a **structured check vector**, not a bool, so the audit trail records
  exactly which property failed.

## 5. Replay protection

Two mechanisms, neither sufficient alone:

- **Timestamp window** `[now - max_age, now + skew]` — bounds how long any envelope is usable.
  Defaults: `max_age = 300 s`, `skew = 30 s`.
- **Nonce cache**, keyed `(worker_id, nonce)`, 128 bits from the OS CSPRNG.

Memory is bounded because a nonce only has to be remembered for as long as an envelope bearing it
could still pass the freshness check: `TTL = 2 × (max_age + skew)`. Pruning past that point
re-opens nothing, because such an envelope would already fail step 8. **Residual risk:** the cache
is in-process in M2; a control-plane restart clears it. M3 moves it to Redis
(`SET key NX EX ttl`), which gives the same exactly-once semantics across processes and restarts.

## 6. Merkle batching

Verified envelope hashes accumulate into a batch. Sealing builds a binary Merkle tree:

- `leaf = SHA-256(0x00 || envelope_hash)`, `node = SHA-256(0x01 || left || right)`.
- **Domain separation** (`0x00`/`0x01`) prevents second-preimage attacks that pass an internal
  node off as a leaf.
- Odd nodes are **promoted, not duplicated** — duplication causes the CVE-2012-2459 class of root
  collisions where two different leaf sets yield the same root.

Use case: an auditor holding only the published root can verify that a specific attempt is in the
batch with `⌈log₂ N⌉` cheap hashes, instead of re-verifying N Ed25519 signatures.

**Important scoping note:** Merkle batching accelerates *auditing membership of already-verified
records*. It does **not** make initial verification cheaper — every signature must still be checked
once when the result arrives. Any reported speed-up must be labelled as an auditing speed-up. The
quantitative comparison (individual verification vs batch audit, as a function of N) is an M5
deliverable and **has not been measured yet**; no numbers are claimed here.

## 7. Artifact encryption

AES-256-GCM, wire format `nonce(12) || ciphertext || tag(16)`, random 96-bit nonce per message
(safe below ~2³² messages per key), with the context string bound as AAD so a blob cannot be
silently relocated between tasks. Keys come from `TPC_ARTIFACT_KEY` or an explicit argument; there
is **no default key** and a test enforces that.

**Non-claims:** this protects data *at rest from an attacker without the key*. It is not privacy
from the control plane, not protection of data in use, not anonymisation, and not differential
privacy.

## 8. Key management and rotation

- Keys are generated **on the worker**; private material never enters the registry, the API, the
  database, the logs, or the dashboard. `KeyPair.__repr__` and `ArtifactCipher.__repr__` are
  overridden to redact, so an accidental log line cannot leak them.
- On-disk keystore: directory `0700`, files `0600`, optional password encryption (scrypt + PKCS8).
- The registry **refuses to silently re-bind an existing worker id to a new public key** — a silent
  swap would let an attacker inherit an established identity's trust.
- **Rotation (M5, not yet implemented):** overlapping validity windows, `key_id` in the envelope,
  and a registry that accepts either key during the overlap. Until that lands, rotation is
  documented as a gap, not as a feature.

## 9. What this protocol does *not* do

- It does **not** prove that a worker ran the claimed computation correctly. A worker with a valid
  key can sign a wrong answer, and every check above will pass. That is the entire reason the
  adaptive replication policy exists.
- It does not provide non-repudiation to a third party without also publishing the registry state.
- It does not protect against a compromised control plane.
- It has not been formally verified or independently audited.
