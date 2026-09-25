"""Pydantic v2 schemas. All external input is validated here before touching domain logic."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Sensitivity = Literal["low", "medium", "high"]

MAX_FEATURES = 4096


class TaskSubmission(BaseModel):
    """A client-submitted inference task."""

    model_config = ConfigDict(extra="forbid")

    task_type: str = Field(default="digits_classification", max_length=64)
    features: list[float] = Field(..., min_length=1, max_length=MAX_FEATURES)
    sensitivity: Sensitivity = "medium"
    experiment_id: str | None = Field(default=None, max_length=64)

    @field_validator("features")
    @classmethod
    def finite_features(cls, v: list[float]) -> list[float]:
        import math

        if any(math.isnan(x) or math.isinf(x) for x in v):
            raise ValueError("features must be finite numbers")
        return v

    @field_validator("task_type")
    @classmethod
    def known_type(cls, v: str) -> str:
        if not v.replace("_", "").isalnum():
            raise ValueError("task_type must be alphanumeric/underscore")
        return v


class TaskResponse(BaseModel):
    task_id: str
    status: str
    verdict: str | None = None
    result: Any | None = None
    executed_by: list[str] = Field(default_factory=list)
    risk_score: float | None = None
    verification_decision: str | None = None
    replicas_used: int = 0
    cost_units: float = 0.0
    latency_ms: float | None = None
    verification_latency_ms: float | None = None
    integrity_failure: bool = False
    detail: str | None = None


class WorkerRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    worker_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$")
    public_key: str = Field(..., min_length=64, max_length=64, pattern=r"^[0-9a-f]+$")
    capabilities: list[str] = Field(default_factory=list, max_length=32)


class WorkerView(BaseModel):
    """Public worker view. Contains no private key material by construction."""

    worker_id: str
    status: str
    trust_score: float
    capabilities: list[str]
    public_key_fingerprint: str  # first 16 hex chars only
    tasks_completed: int = 0
    failures: int = 0
    verification_failures: int = 0
    mean_latency_ms: float = 0.0


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded", "error"]
    service: str
    version: str
    workers_active: int = 0
    database: bool = True


class MetricsSnapshot(BaseModel):
    tasks_total: int = 0
    tasks_completed: int = 0
    tasks_failed: int = 0
    tasks_rejected: int = 0
    verification_rate: float = 0.0
    integrity_failures: int = 0
    mean_latency_ms: float = 0.0
    mean_cost_units: float = 0.0
    workers_active: int = 0
    workers_quarantined: int = 0
