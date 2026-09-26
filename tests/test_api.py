"""API gateway tests: endpoints, auth, input validation, and information disclosure."""


import pytest
from fastapi.testclient import TestClient

from ml.inference_model import sample_inputs


@pytest.fixture(scope="module")
def client():
    from services.api.main import create_app

    app = create_app(n_workers=4, n_faulty=0, policy="risk_adaptive", persist=False)
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def features():
    return sample_inputs(3, seed=5)


# --------------------------------------------------------------------- health
def test_health_endpoint(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["service"] == "api-gateway"
    assert body["workers_active"] == 4


def test_ready_endpoint(client):
    r = client.get("/ready")
    assert r.status_code == 200 and r.json()["ready"] is True


def test_openapi_is_served(client):
    assert client.get("/openapi.json").status_code == 200


# --------------------------------------------------------------------- tasks
def test_submit_task_returns_verified_result(client, features):
    r = client.post("/tasks", json={"features": features[0], "sensitivity": "low"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "completed"
    assert 0 <= body["result"]["label"] <= 9
    assert body["executed_by"] and body["latency_ms"] > 0
    assert body["verification_decision"] in ("accept", "verify_1", "verify_n")
    assert body["integrity_failure"] is False


def test_submit_task_rejects_wrong_feature_count(client):
    r = client.post("/tasks", json={"features": [1.0, 2.0]})
    assert r.status_code == 422


def test_submit_task_rejects_empty_and_oversized_input(client):
    assert client.post("/tasks", json={"features": []}).status_code == 422
    assert client.post("/tasks", json={"features": [0.0] * 99999}).status_code == 422


def test_submit_task_rejects_nan_without_leaking_input(client, features):
    """NaN is not valid JSON but Python's parser accepts it. The server must reject the request
    with a 422 whose body is serialisable and does not echo the raw input back."""
    r = client.post("/tasks", content=b'{"features": [NaN]}',
                    headers={"content-type": "application/json"})
    assert r.status_code == 422
    body = r.json()
    assert "finite" in str(body).lower()
    assert "input" not in body["detail"][0]


def test_submit_task_rejects_unknown_fields(client, features):
    r = client.post("/tasks", json={"features": features[0], "admin": True})
    assert r.status_code == 422


def test_submit_task_rejects_bad_sensitivity(client, features):
    r = client.post("/tasks", json={"features": features[0], "sensitivity": "ultra"})
    assert r.status_code == 422


def test_high_sensitivity_costs_more_on_average(client, features):
    """H5-related: the policy is stochastic (exploration), so this is a mean over repeated
    submissions rather than a single-sample comparison."""
    def mean_cost(sens: str, n: int = 25) -> float:
        return sum(
            client.post("/tasks", json={"features": features[0], "sensitivity": sens}).json()["cost_units"]
            for _ in range(n)
        ) / n

    assert mean_cost("high") >= mean_cost("low")


# --------------------------------------------------------------------- workers
def test_list_workers_never_exposes_private_keys(client):
    body = client.get("/workers").json()
    assert len(body) == 4
    raw = client.get("/workers").text
    for w in body:
        assert len(w["public_key_fingerprint"]) == 16
        assert 0.0 <= w["trust_score"] <= 1.0
    assert "private" not in raw.lower() and "BEGIN" not in raw


def test_worker_trust_explanation(client):
    wid = client.get("/workers").json()[0]["worker_id"]
    body = client.get(f"/workers/{wid}/trust").json()
    assert "trust_score" in body and "not proof of intent" in body["note"]


def test_unknown_worker_returns_404(client):
    assert client.get("/workers/does-not-exist/trust").status_code == 404


def test_quarantine_and_release_roundtrip(client):
    wid = client.get("/workers").json()[0]["worker_id"]
    assert client.post(f"/workers/{wid}/quarantine").status_code == 200
    assert client.get("/workers").json()[0]["status"] == "quarantined"
    assert client.post(f"/workers/{wid}/release").status_code == 200
    assert client.get("/workers").json()[0]["status"] == "active"


def test_register_rejects_bad_public_key(client):
    r = client.post("/workers/register",
                    json={"worker_id": "w-new", "public_key": "zz", "capabilities": []})
    assert r.status_code == 422


def test_register_rejects_bad_worker_id(client):
    r = client.post("/workers/register",
                    json={"worker_id": "../../etc/passwd", "public_key": "ab" * 32})
    assert r.status_code == 422


# --------------------------------------------------------------------- ops
def test_metrics_endpoint(client, features):
    client.post("/tasks", json={"features": features[1]})
    m = client.get("/metrics").json()
    assert m["tasks_total"] >= 1 and m["workers_active"] >= 1
    assert m["mean_cost_units"] >= 1.0


def test_model_info_exposes_provenance_not_weights(client):
    body = client.get("/model").json()
    assert body["version"] == "digits-logreg@1.0.0"
    assert len(body["weight_digest"]) == 64
    assert "coef_" not in str(body)


def test_merkle_batch_seal(client, features):
    client.post("/tasks", json={"features": features[2]})
    pending = client.get("/verification/batch/root").json()["pending_leaves"]
    assert pending > 0
    sealed = client.get("/verification/batch/root", params={"seal": True}).json()
    assert len(sealed["merkle_root"]) == 64 and sealed["leaves"] == pending
    assert client.get("/verification/batch/root").json()["pending_leaves"] == 0


# --------------------------------------------------------------------- auth
def test_auth_is_enforced_when_configured(monkeypatch, features):
    monkeypatch.setenv("TPC_REQUIRE_AUTH", "true")
    monkeypatch.setenv("TPC_API_KEY", "test-key-123")
    monkeypatch.setenv("TPC_ADMIN_API_KEY", "admin-key-456")
    import services.common.config as cfg

    cfg.get_settings(refresh=True)
    try:
        from services.api.main import create_app

        with TestClient(create_app(n_workers=2, persist=False)) as c:
            assert c.get("/health").status_code == 200          # health is public
            assert c.get("/workers").status_code == 401         # no key
            assert c.get("/workers", headers={"X-API-Key": "wrong"}).status_code == 401
            assert c.get("/workers", headers={"X-API-Key": "test-key-123"}).status_code == 200
            # a normal key must not reach an admin endpoint
            assert c.post("/workers/w-00/quarantine",
                          headers={"X-API-Key": "test-key-123"}).status_code == 403
            assert c.post("/workers/w-00/quarantine",
                          headers={"X-API-Key": "admin-key-456"}).status_code == 200
    finally:
        monkeypatch.delenv("TPC_API_KEY", raising=False)
        monkeypatch.delenv("TPC_ADMIN_API_KEY", raising=False)
        monkeypatch.setenv("TPC_REQUIRE_AUTH", "false")
        cfg.get_settings(refresh=True)


def test_index_page_renders_html(client):
    """The gateway root serves a human-readable status page, not a 404.

    Regression guard: the preview/browser entry point must render rather than 404.
    """
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    body = r.text
    assert "TrustProof-Cloud" in body
    assert "Worker registry" in body


def test_index_page_never_exposes_private_key_material(client):
    """The landing page must show public fingerprints only."""
    body = client.get("/").text
    for marker in ("-----BEGIN", "PRIVATE", "private_key", "signing_key"):
        assert marker not in body, f"landing page leaked {marker!r}"


def test_index_page_is_self_contained(client):
    """No CDN/remote assets: the page must render offline and in sandboxed frames."""
    body = client.get("/").text
    for remote in ("http://", "https://", "<script"):
        assert remote not in body, f"landing page pulls remote asset or script: {remote!r}"


def test_index_page_flags_disabled_authentication(client):
    """When auth is off, the page must say so rather than look production-ready."""
    body = client.get("/").text
    assert "Authentication is disabled" in body or "disabled (local mode)" in body
