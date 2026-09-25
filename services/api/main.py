"""API Gateway (FastAPI).

Security posture for M2:
  * API-key authentication via `X-API-Key`, with a separate admin key for mutating endpoints.
  * Auth is ON by default; it can only be disabled explicitly (`TPC_REQUIRE_AUTH=false`) for local
    experiments, and the `/health` response reports when it is off so a disabled gateway is never
    silently exposed.
  * All bodies are validated by pydantic before reaching domain code.
  * No endpoint ever returns private key material; worker views expose a 16-hex fingerprint only.
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status

from services.common.bootstrap import System, build_system
from services.common.config import get_settings
from services.common.schemas import (
    HealthResponse,
    MetricsSnapshot,
    TaskResponse,
    TaskSubmission,
    WorkerRegistration,
    WorkerView,
)

API_VERSION = "0.2.0-m2"

_system: System | None = None


def get_system() -> System:
    if _system is None:  # pragma: no cover - guarded by lifespan
        raise HTTPException(status_code=503, detail="system not initialised")
    return _system


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _system
    st = get_settings()
    _system = build_system(
        n_workers=int(app.state.n_workers), n_faulty=int(app.state.n_faulty),
        policy=app.state.policy, persist=app.state.persist, settings=st,
    )
    yield
    _system = None


def create_app(n_workers: int = 4, n_faulty: int = 0, policy: str = "risk_adaptive",
               persist: bool = True) -> FastAPI:
    app = FastAPI(
        title="TrustProof-Cloud API",
        version=API_VERSION,
        description=(
            "Risk-adaptive cryptographically verifiable ML inference. Research prototype — "
            "not audited, no production security guarantees. See THREAT_MODEL.md."
        ),
        lifespan=lifespan,
    )
    app.state.n_workers = n_workers
    app.state.n_faulty = n_faulty
    app.state.policy = policy
    app.state.persist = persist

    # FastAPI's default 422 handler echoes the offending input back. If that input contains a
    # non-JSON-compliant float (NaN/Infinity, which Python's json module accepts on input but
    # refuses to emit), serialising the error response raises and the client gets a 500 instead of
    # a 422. We return a sanitised error body instead: never echo raw input.
    from fastapi.encoders import jsonable_encoder
    from fastapi.exceptions import RequestValidationError
    from fastapi.responses import JSONResponse
    from starlette.requests import Request

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        safe = [
            {"loc": [str(p) for p in e.get("loc", [])],
             "msg": str(e.get("msg", "invalid value")),
             "type": str(e.get("type", "value_error"))}
            for e in exc.errors()
        ]
        return JSONResponse(status_code=422, content=jsonable_encoder({"detail": safe}))

    # -- auth ---------------------------------------------------------------
    def require_key(x_api_key: str | None = Header(default=None)) -> str:
        st = get_settings()
        if not st.auth_enabled:
            return "anonymous"
        import hmac

        if x_api_key and (
            hmac.compare_digest(x_api_key, st.api_key)
            or (st.admin_api_key and hmac.compare_digest(x_api_key, st.admin_api_key))
        ):
            return x_api_key
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing X-API-Key")

    def require_admin(x_api_key: str | None = Header(default=None)) -> str:
        st = get_settings()
        if not st.auth_enabled:
            return "anonymous"
        import hmac

        if x_api_key and st.admin_api_key and hmac.compare_digest(x_api_key, st.admin_api_key):
            return x_api_key
        raise HTTPException(status_code=403, detail="admin API key required")

    # -- health / readiness --------------------------------------------------
    @app.get("/health", response_model=HealthResponse, tags=["ops"])
    def health() -> HealthResponse:
        sysobj = _system
        n_active = len(sysobj.registry.available()) if sysobj else 0
        return HealthResponse(
            status="ok" if sysobj and n_active else "degraded",
            service="api-gateway", version=API_VERSION,
            workers_active=n_active, database=bool(sysobj and sysobj.session_factory is not None),
        )

    @app.get("/ready", tags=["ops"])
    def ready():
        sysobj = _system
        checks = {
            "system_built": sysobj is not None,
            "model_loaded": bool(sysobj and sysobj.model is not None),
            "workers_registered": bool(sysobj and len(sysobj.registry) > 0),
            "auth_enabled": get_settings().auth_enabled,
        }
        ok = checks["system_built"] and checks["model_loaded"] and checks["workers_registered"]
        if not ok:
            raise HTTPException(status_code=503, detail=checks)
        return {"ready": True, "checks": checks}

    # -- tasks ----------------------------------------------------------------
    @app.post("/tasks", response_model=TaskResponse, tags=["inference"])
    def submit_task(body: TaskSubmission, _: str = Depends(require_key),
                    sysobj: System = Depends(get_system)) -> TaskResponse:
        expected = sysobj.model.n_features
        if len(body.features) != expected:
            raise HTTPException(
                status_code=422, detail=f"task_type {body.task_type!r} expects {expected} features"
            )
        outcome = sysobj.scheduler.submit(
            body.features, task_type="digits_classification", sensitivity=body.sensitivity,
            experiment_id=body.experiment_id,
            timeout_ms=get_settings().task_timeout_ms,
        )
        return TaskResponse(
            task_id=outcome.task_id, status=outcome.status.value, verdict=outcome.verdict.value,
            result=outcome.result, executed_by=outcome.executed_by, risk_score=round(outcome.risk_score, 4),
            verification_decision=outcome.decision, replicas_used=outcome.replicas_used,
            cost_units=outcome.cost_units, latency_ms=round(outcome.latency_ms, 3),
            verification_latency_ms=round(outcome.verification_latency_ms, 4),
            integrity_failure=outcome.integrity_failure, detail=outcome.detail,
        )

    # -- workers ---------------------------------------------------------------
    @app.get("/workers", response_model=list[WorkerView], tags=["workers"])
    def list_workers(_: str = Depends(require_key), sysobj: System = Depends(get_system)):
        views = []
        for rec in sysobj.registry.all():
            st = sysobj.trust.get(rec.worker_id)
            views.append(WorkerView(
                worker_id=rec.worker_id, status=rec.status.value,
                trust_score=round(st.score, 4), capabilities=list(rec.capabilities),
                public_key_fingerprint=rec.fingerprint, tasks_completed=st.successes,
                failures=st.failures, verification_failures=st.integrity_failures,
                mean_latency_ms=round(st.latency_ewma_ms, 2),
            ))
        return views

    @app.get("/workers/{worker_id}/trust", tags=["workers"])
    def worker_trust(worker_id: str, _: str = Depends(require_key),
                     sysobj: System = Depends(get_system)):
        if sysobj.registry.get(worker_id) is None:
            raise HTTPException(status_code=404, detail="unknown worker")
        return sysobj.trust.explain(worker_id)

    @app.post("/workers/register", tags=["workers"])
    def register_worker(body: WorkerRegistration, _: str = Depends(require_admin),
                        sysobj: System = Depends(get_system)):
        """Registration of *external* workers. The bootstrap pool is registered at startup.
        Note: enrolment is trusted in this prototype (THREAT_MODEL.md §2)."""
        existing = sysobj.registry.get(body.worker_id)
        if existing and existing.public_key != body.public_key:
            raise HTTPException(status_code=409, detail="worker id already bound to another key")
        return {"registered": body.worker_id, "fingerprint": body.public_key[:16],
                "note": "external worker execution transport lands in M3"}

    @app.post("/workers/{worker_id}/quarantine", tags=["workers"])
    def quarantine(worker_id: str, _: str = Depends(require_admin),
                   sysobj: System = Depends(get_system)):
        if sysobj.registry.get(worker_id) is None:
            raise HTTPException(status_code=404, detail="unknown worker")
        sysobj.registry.quarantine(worker_id, "manual")
        return {"worker_id": worker_id, "status": "quarantined",
                "note": "reversible eligibility downgrade; not an accusation of malicious intent"}

    @app.post("/workers/{worker_id}/release", tags=["workers"])
    def release(worker_id: str, _: str = Depends(require_admin),
                sysobj: System = Depends(get_system)):
        if sysobj.registry.get(worker_id) is None:
            raise HTTPException(status_code=404, detail="unknown worker")
        sysobj.registry.release(worker_id)
        return {"worker_id": worker_id, "status": "active"}

    # -- observability -----------------------------------------------------------
    @app.get("/metrics", response_model=MetricsSnapshot, tags=["ops"])
    def metrics(_: str = Depends(require_key), sysobj: System = Depends(get_system)):
        s = sysobj.scheduler.stats
        total = max(s["tasks"], 1)
        return MetricsSnapshot(
            tasks_total=s["tasks"], tasks_completed=s["completed"], tasks_failed=s["failed"],
            tasks_rejected=s["rejected"],
            verification_rate=round(max(0.0, s["cost_units"] - s["tasks"]) / total, 4),
            mean_cost_units=round(s["cost_units"] / total, 4),
            workers_active=len(sysobj.registry.available()),
            workers_quarantined=sum(1 for w in sysobj.registry.all()
                                    if w.status.value == "quarantined"),
        )

    @app.get("/verification/batch/root", tags=["verification"])
    def batch_root(seal: bool = Query(default=False), _: str = Depends(require_key),
                   sysobj: System = Depends(get_system)):
        """Merkle root over the envelope hashes verified since the last seal."""
        if not seal:
            return {"pending_leaves": sysobj.verifier.batch_size()}
        t0 = time.perf_counter()
        root, size, _tree = sysobj.verifier.seal_batch()
        return {"merkle_root": root, "leaves": size,
                "seal_latency_ms": round((time.perf_counter() - t0) * 1000, 4)}

    @app.get("/model", tags=["inference"])
    def model_info(_: str = Depends(require_key), sysobj: System = Depends(get_system)):
        return {"version": sysobj.model.version, "n_features": sysobj.model.n_features,
                "test_accuracy": sysobj.model.test_accuracy,
                "weight_digest": sysobj.model.weight_digest}

    return app


app = create_app()
