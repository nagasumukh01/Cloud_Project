#!/usr/bin/env python3
"""Interactive walkthrough of one verified inference, then one attacked inference.

Run:  python scripts/demo.py
No network, no containers, no accounts. ~5 seconds.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from crypto.signatures import verify_signed_result  # noqa: E402
from ml.inference_model import sample_inputs  # noqa: E402
from services.common.bootstrap import build_system  # noqa: E402


def rule(title: str) -> None:
    print(f"\n\033[1m{title}\033[0m\n" + "-" * len(title))


def main() -> int:
    rule("1. Building the local system (4 honest workers, no infrastructure required)")
    system = build_system(n_workers=4, n_faulty=0, policy="risk_adaptive", persist=False)
    print(f"   model          : {system.model.version} (test accuracy {system.model.test_accuracy:.3f})")
    print(f"   workers        : {[w.worker_id for w in system.workers]}")
    print("   each worker holds its own Ed25519 key; the registry stores only public keys")
    for w in system.workers[:2]:
        print(f"     {w.worker_id}  pubkey {w.public_key_hex[:16]}...  (private key never leaves the worker)")

    rule("2. Submitting one inference task")
    x = sample_inputs(1, seed=5)[0]
    out = system.scheduler.submit(x, sensitivity="medium")
    print(f"   task           : {out.task_id[:8]}")
    print(f"   executed by    : {out.executed_by}")
    print(f"   result         : {out.result}")
    print(f"   risk score     : {out.risk_score:.4f}")
    print(f"   policy decision: {out.decision}  ({out.replicas_used} replica(s))")
    print(f"   verdict        : {out.verdict.value}")
    print(f"   latency        : {out.latency_ms:.2f} ms  (verification {out.verification_latency_ms:.3f} ms)")
    print(f"   cost           : {out.cost_units} execution unit(s)")

    rule("3. Inspecting the signed envelope produced by the worker")
    worker = system.workers[0]
    from crypto.hashing import input_commitment

    signed = worker.execute("demo-task", x, input_commitment(x))
    for k, v in signed.envelope.to_dict().items():
        shown = v if len(str(v)) < 50 else f"{str(v)[:46]}..."
        print(f"   {k:<18}: {shown}")
    print(f"   signature         : {signed.signature_hex[:46]}...")
    res = verify_signed_result(signed, public_key_hex=worker.public_key_hex)
    print(f"   verification      : ok={res.ok}  checks={res.checks}")

    rule("4. Attack: a worker mutates the result after signing it")
    from crypto.signatures import SignedResult

    tampered = SignedResult(signed.envelope, signed.signature_hex,
                            {**signed.payload, "label": (signed.payload["label"] + 1) % 10})
    bad = verify_signed_result(tampered, public_key_hex=worker.public_key_hex)
    print(f"   original label    : {signed.payload['label']}   tampered label: {tampered.payload['label']}")
    print(f"   verification      : ok={bad.ok}  reason={bad.reason}")
    print("   -> the signature still verifies, but the payload no longer matches the committed")
    print("      result_hash, so the result is rejected.")

    rule("5. Attack the scheduler: a faulty worker that returns wrong-but-signed results")
    print("   (cryptography alone CANNOT catch this - it needs replication, which is exactly")
    print("    what the risk-adaptive policy rations)")
    attacked = build_system(n_workers=5, n_faulty=1, fault_rate=1.0,
                            behaviours=("tamper_payload",), policy="risk_adaptive")
    faulty_id = attacked.workers[-1].worker_id
    print(f"   faulty worker  : {faulty_id}")
    detections = 0
    for feats in sample_inputs(25, seed=7):
        o = attacked.scheduler.submit(feats, sensitivity="high")
        if "disagreement" in o.detail or o.integrity_failure:
            detections += 1
    print(f"   25 tasks submitted; {detections} disagreement/integrity events observed")
    if detections == 0:
        print("   \033[33mOBSERVED LIMITATION (M2):\033[0m no detection in this short run. With the")
        print("   heuristic risk estimator, a worker starting at the trust prior (0.70) scores below")
        print("   tau_low, so the policy accepts without replication and only the 5% exploration")
        print("   floor can catch it. Cold-start blindness is exactly what the M4 anomaly detector")
        print("   and the M6 learned policy must fix; it is reported, not hidden.")
    print(f"   trust of faulty worker : {attacked.trust.score(faulty_id):.3f}")
    honest = [w.worker_id for w in attacked.workers[:-1]]
    print(f"   trust of honest workers: "
          f"{ {w: round(attacked.trust.score(w), 3) for w in honest} }")
    print(f"   registry status of {faulty_id}: {attacked.registry.get(faulty_id).status.value}")

    rule("6. Merkle batch audit")
    root, size, tree = attacked.verifier.seal_batch()
    print(f"   sealed {size} verified envelopes into one root")
    print(f"   merkle root   : {root}")
    print(f"   tree depth    : {tree.depth} -> an inclusion proof is {tree.depth - 1} hashes, "
          f"vs {size} signature verifications")

    print("\nNext: `make experiment` runs the six-arm comparison; `make api` starts the gateway.\n")
    print("Reminder: these are simulation results under an injected fault model, not production")
    print("measurements, and no security guarantee is claimed beyond THREAT_MODEL.md.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
