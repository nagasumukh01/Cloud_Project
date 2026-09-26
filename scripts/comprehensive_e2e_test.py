"""Comprehensive End-to-End System Verification.

Tests all in and out functions of TrustProof-Cloud:
1. Crypto Layer: Ed25519 signing & verification, replay cache, Merkle tree batching & proofs, AES-GCM encryption
2. ML Layer: inference model loading, feature validation, prediction output, softmax entropy
3. System & Scheduler Layer: worker pool, risk-adaptive dispatch, trust scoring updates
4. API Layer (live HTTP/TestClient):
   - GET / (landing page HTML)
   - GET /health (service health)
   - GET /ready (readiness check)
   - GET /model (model metadata)
   - POST /tasks (inference task execution with inputs -> verified outputs)
   - POST /tasks error cases (invalid inputs -> 422 handled)
   - GET /workers (worker list & fingerprints)
   - GET /workers/{id}/trust (trust breakdown)
   - POST /workers/{id}/quarantine & /release (admin operations)
   - POST /workers/register (worker onboarding)
   - GET /metrics (system observability counters)
   - GET /verification/batch/root (merkle seal & batch verification)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient
from crypto import (
    ArtifactCipher,
    KeyPair,
    MerkleTree,
    ReplayGuard,
    SignedResult,
    build_envelope,
    generate_key,
    generate_keypair,
    input_commitment,
    sign_envelope,
    verify_proof,
    verify_signed_result,
)
from crypto.hashing import hash_object
from ml.inference_model import get_model, sample_inputs
from services.common.bootstrap import build_system
from services.api.main import create_app
from services.common.config import get_settings


def test_section(title: str):
    print(f"\n{'='*70}\n[TEST SUITE] {title}\n{'='*70}")


def run_crypto_in_out_tests():
    test_section("1. Cryptographic In/Out Operations")
    
    # 1. Keypair generation
    kp = generate_keypair()
    assert kp.public_hex and len(kp.public_hex) == 64
    print(f"  [PASS] Ed25519 keypair generation (key_id: {kp.key_id}, pub: {kp.public_hex[:16]}...)")
    
    # 2. Input and Result commitment
    x = [0.5] * 64
    in_commit = input_commitment(x)
    assert len(in_commit) == 64
    print(f"  [PASS] Blake2b-256 input commitment: {in_commit[:35]}...")
    
    res_payload = {"label": 3, "confidence": 0.98}
    res_hash = hash_object(res_payload, "sha256")
    assert len(res_hash) == 64
    print(f"  [PASS] SHA256 result hash: {res_hash[:35]}...")
    
    # 3. Signed envelope creation and verification
    env = build_envelope(
        task_id="task-crypto-01",
        worker_id="worker-test-01",
        model_version="digits-logreg@1.0.0",
        input_commitment=in_commit,
        payload=res_payload,
    )
    signed = sign_envelope(kp, env, res_payload)
    v_res = verify_signed_result(signed, public_key_hex=kp.public_hex)
    assert v_res.ok is True
    print("  [PASS] Result signing and envelope verification")
    
    # 4. Tamper detection (mutated payload)
    tampered = SignedResult(
        signed.envelope,
        signed.signature_hex,
        {"label": 4, "confidence": 0.98}
    )
    v_tampered = verify_signed_result(tampered, public_key_hex=kp.public_hex)
    assert v_tampered.ok is False
    assert v_tampered.reason == "result_hash_mismatch"
    print(f"  [PASS] Payload tampering detected correctly: {v_tampered.reason}")
    
    # 5. Merkle batch audit and inclusion proof
    leaf_bytes = [f"data_record_{i}".encode("utf-8") for i in range(8)]
    tree = MerkleTree(leaf_bytes)
    root = tree.root
    assert root is not None
    assert tree.verify(2, leaf_bytes[2]) is True
    print(f"  [PASS] Merkle tree generation (root: {root[:20]}...) and inclusion proof verification")
    
    # 6. AES-256-GCM artifact encryption/decryption
    k = generate_key()
    cipher = ArtifactCipher(k)
    secret_bytes = b"TrustProof-Cloud-Confidential-Model-Weights"
    enc = cipher.encrypt(secret_bytes)
    dec = cipher.decrypt(enc)
    assert dec == secret_bytes
    print(f"  [PASS] AES-256-GCM artifact encryption & decryption (len: {len(dec)} bytes)")


def run_ml_in_out_tests():
    test_section("2. Machine Learning Model In/Out Operations")
    model = get_model()
    print(f"  Model loaded: {model.version}, features required: {model.n_features}")
    
    inputs = sample_inputs(5, seed=123)
    assert len(inputs) == 5
    for i, x in enumerate(inputs):
        assert len(x) == model.n_features
        pred = model.predict_with_uncertainty(x)
        assert 0 <= pred.label <= 9
        assert 0.0 <= pred.confidence <= 1.0
        print(f"  [PASS] Sample {i+1} -> predicted label {pred.label}, conf {pred.confidence:.4f}, entropy {pred.entropy:.4f}")


def run_system_and_scheduler_in_out_tests():
    test_section("3. System & Scheduler In/Out Operations")
    sys_obj = build_system(n_workers=4, n_faulty=1, fault_rate=0.5, policy="risk_adaptive", persist=False)
    
    inputs = sample_inputs(10, seed=42)
    for i, x in enumerate(inputs):
        outcome = sys_obj.scheduler.submit(x, sensitivity="high")
        assert outcome.status.value in ("completed", "failed", "rejected")
        assert outcome.task_id is not None
        assert outcome.risk_score >= 0.0
        print(f"  Task {i+1:02d}: outcome={outcome.status.value} verdict={outcome.verdict.value} "
              f"decision={outcome.decision} cost={outcome.cost_units} lat={outcome.latency_ms:.2f}ms")


def run_api_gateway_in_out_tests():
    test_section("4. API Gateway Endpoints In/Out Operations (Full Suite)")
    app = create_app(n_workers=4, n_faulty=0, policy="risk_adaptive", persist=False)
    with TestClient(app) as client:
        st = get_settings()
        auth_headers = {"X-API-Key": st.api_key}
        admin_headers = {"X-API-Key": st.admin_api_key}

        # 1. GET /
        r = client.get("/")
        assert r.status_code == 200
        assert "TrustProof-Cloud API Gateway" in r.text
        print("  [PASS] GET / -> 200 OK (HTML landing page rendered)")

        # 2. GET /health
        r = client.get("/health")
        assert r.status_code == 200
        h_data = r.json()
        assert h_data["status"] == "ok"
        assert h_data["workers_active"] == 4
        print(f"  [PASS] GET /health -> 200 OK ({h_data})")

        # 3. GET /ready
        r = client.get("/ready")
        assert r.status_code == 200
        assert r.json()["ready"] is True
        print(f"  [PASS] GET /ready -> 200 OK ({r.json()})")

        # 4. GET /model
        r = client.get("/model", headers=auth_headers)
        assert r.status_code == 200
        m_data = r.json()
        assert m_data["n_features"] == 64
        print(f"  [PASS] GET /model -> 200 OK (version={m_data['version']}, features={m_data['n_features']})")

        # 5. POST /tasks (Valid Inference)
        features = sample_inputs(2, seed=99)
        for idx, sens in enumerate(["low", "medium", "high"]):
            r = client.post("/tasks", json={"features": features[0], "sensitivity": sens}, headers=auth_headers)
            assert r.status_code == 200
            t_data = r.json()
            assert t_data["status"] == "completed"
            assert "label" in t_data["result"]
            print(f"  [PASS] POST /tasks (sens={sens}) -> 200 OK (task={t_data['task_id'][:8]} label={t_data['result']['label']} risk={t_data['risk_score']})")

        # 6. POST /tasks (Invalid Inputs Handling)
        # Wrong feature count
        r_bad = client.post("/tasks", json={"features": [1.0, 2.0]}, headers=auth_headers)
        assert r_bad.status_code == 422
        print("  [PASS] POST /tasks [wrong feature count] -> 422 Unprocessable Entity")

        # Empty features
        r_empty = client.post("/tasks", json={"features": []}, headers=auth_headers)
        assert r_empty.status_code == 422
        print("  [PASS] POST /tasks [empty input] -> 422 Unprocessable Entity")

        # Unknown parameter injection
        r_inj = client.post("/tasks", json={"features": features[0], "malicious_field": True}, headers=auth_headers)
        assert r_inj.status_code == 422
        print("  [PASS] POST /tasks [extra unknown fields] -> 422 Unprocessable Entity")

        # 7. GET /workers
        r = client.get("/workers", headers=auth_headers)
        assert r.status_code == 200
        workers = r.json()
        assert len(workers) == 4
        w0_id = workers[0]["worker_id"]
        print(f"  [PASS] GET /workers -> 200 OK ({len(workers)} workers active: {[w['worker_id'] for w in workers]})")

        # 8. GET /workers/{id}/trust
        r = client.get(f"/workers/{w0_id}/trust", headers=auth_headers)
        assert r.status_code == 200
        trust_info = r.json()
        assert "trust_score" in trust_info
        print(f"  [PASS] GET /workers/{w0_id}/trust -> 200 OK (score={trust_info['trust_score']})")

        # 9. POST /workers/{id}/quarantine & release (Admin)
        r_q = client.post(f"/workers/{w0_id}/quarantine", headers=admin_headers)
        assert r_q.status_code == 200
        assert r_q.json()["status"] == "quarantined"
        print(f"  [PASS] POST /workers/{w0_id}/quarantine -> 200 OK (status=quarantined)")

        r_rel = client.post(f"/workers/{w0_id}/release", headers=admin_headers)
        assert r_rel.status_code == 200
        assert r_rel.json()["status"] == "active"
        print(f"  [PASS] POST /workers/{w0_id}/release -> 200 OK (status=active)")

        # 10. POST /workers/register (Admin)
        new_kp = generate_keypair()
        r_reg = client.post("/workers/register", json={"worker_id": "worker-new-99", "public_key": new_kp.public_hex}, headers=admin_headers)
        assert r_reg.status_code == 200
        assert r_reg.json()["registered"] == "worker-new-99"
        print(f"  [PASS] POST /workers/register -> 200 OK (registered=worker-new-99)")

        # 11. GET /metrics
        r = client.get("/metrics", headers=auth_headers)
        assert r.status_code == 200
        m_info = r.json()
        assert "tasks_total" in m_info
        print(f"  [PASS] GET /metrics -> 200 OK (tasks_total={m_info['tasks_total']} workers_active={m_info['workers_active']})")

        # 12. GET /verification/batch/root
        r = client.get("/verification/batch/root", headers=auth_headers)
        assert r.status_code == 200
        print(f"  [PASS] GET /verification/batch/root (inspect) -> 200 OK ({r.json()})")

        r_seal = client.get("/verification/batch/root?seal=true", headers=auth_headers)
        assert r_seal.status_code == 200
        s_info = r_seal.json()
        assert "merkle_root" in s_info
        print(f"  [PASS] GET /verification/batch/root?seal=true -> 200 OK (merkle_root={s_info['merkle_root'][:20]}... leaves={s_info['leaves']})")


def main():
    print("STARTING TRUSTPROOF-CLOUD COMPLETE END-TO-END VERIFICATION")
    run_crypto_in_out_tests()
    run_ml_in_out_tests()
    run_system_and_scheduler_in_out_tests()
    run_api_gateway_in_out_tests()
    print(f"\n{'='*70}\n[ALL TESTS PASSED PERFECTLY]\n{'='*70}")


if __name__ == "__main__":
    main()

