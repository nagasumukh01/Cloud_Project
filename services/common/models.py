"""Persistence layer (SQLAlchemy 2.0 ORM over SQLite locally, Postgres-compatible).

Append-only discipline: `Attempt`, `SignatureRecord`, `VerificationRecord` and `TrustEvent` rows
are inserted, never mutated. That is what makes the audit trail and Merkle batching meaningful.

IMPORTANT (research integrity): `GroundTruth` holds the fault-injector labels. No module under
`services/` other than the evaluation code may read it. `tests/test_no_label_leakage.py` enforces
this by static import inspection.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class WorkerStatus(str, enum.Enum):
    ACTIVE = "active"
    DEGRADED = "degraded"
    QUARANTINED = "quarantined"
    UNREACHABLE = "unreachable"


class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"


class Verdict(str, enum.Enum):
    ACCEPTED = "accepted"
    ACCEPTED_AFTER_VERIFICATION = "accepted_after_verification"
    REJECTED_INTEGRITY = "rejected_integrity"
    REJECTED_DISAGREEMENT = "rejected_disagreement"
    UNRESOLVED = "unresolved"


class Worker(Base):
    __tablename__ = "workers"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    public_key: Mapped[str] = mapped_column(String(128), nullable=False)
    capabilities: Mapped[str] = mapped_column(Text, default="[]")  # canonical JSON list
    status: Mapped[str] = mapped_column(String(16), default=WorkerStatus.ACTIVE.value)
    trust_score: Mapped[float] = mapped_column(Float, default=0.7)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)

    attempts: Mapped[list[Attempt]] = relationship(back_populates="worker")


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    task_type: Mapped[str] = mapped_column(String(64), nullable=False)
    sensitivity: Mapped[str] = mapped_column(String(16), default="medium")
    input_commitment: Mapped[str] = mapped_column(String(128), nullable=False)
    input_payload: Mapped[str] = mapped_column(Text)  # canonical JSON; encrypted at rest in M5
    status: Mapped[str] = mapped_column(String(16), default=TaskStatus.PENDING.value)
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    final_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    total_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    experiment_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    attempts: Mapped[list[Attempt]] = relationship(back_populates="task")


class Attempt(Base):
    """One execution of a task by one worker (primary or verification replica)."""

    __tablename__ = "attempts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    worker_id: Mapped[str] = mapped_column(ForeignKey("workers.id"), index=True)
    role: Mapped[str] = mapped_column(String(16), default="primary")  # primary | replica
    result_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    succeeded: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    task: Mapped[Task] = relationship(back_populates="attempts")
    worker: Mapped[Worker] = relationship(back_populates="attempts")


class SignatureRecord(Base):
    __tablename__ = "signatures"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    attempt_id: Mapped[str] = mapped_column(ForeignKey("attempts.id"), index=True)
    envelope_json: Mapped[str] = mapped_column(Text, nullable=False)
    envelope_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    signature_hex: Mapped[str] = mapped_column(String(128), nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    failure_reason: Mapped[str] = mapped_column(String(64), default="none")
    checks_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VerificationRecord(Base):
    __tablename__ = "verifications"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    policy: Mapped[str] = mapped_column(String(48), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    replicas_used: Mapped[int] = mapped_column(Integer, default=0)
    cost_units: Mapped[float] = mapped_column(Float, default=1.0)
    agreed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    integrity_failure: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TrustEvent(Base):
    __tablename__ = "trust_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    worker_id: Mapped[str] = mapped_column(ForeignKey("workers.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    delta: Mapped[float] = mapped_column(Float, default=0.0)
    score_after: Mapped[float] = mapped_column(Float, default=0.0)
    note: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GroundTruth(Base):
    """EVALUATION ONLY. Fault-injector labels. Never read by scheduling/policy code."""

    __tablename__ = "ground_truth"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    attempt_id: Mapped[str] = mapped_column(String(64), index=True)
    task_id: Mapped[str] = mapped_column(String(64), index=True)
    was_tampered: Mapped[bool] = mapped_column(Boolean, default=False)
    scenario: Mapped[str] = mapped_column(String(48), default="none")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


Index("ix_attempts_task_role", Attempt.task_id, Attempt.role)


def make_engine(database_url: str, echo: bool = False):
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, echo=echo, future=True, connect_args=connect_args)


def init_db(database_url: str, echo: bool = False) -> sessionmaker[Session]:
    engine = make_engine(database_url, echo=echo)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def reset_db(database_url: str) -> sessionmaker[Session]:
    """Drop and recreate every table. Required reset hook for the experiment harness (brief §9)."""
    engine = make_engine(database_url)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)
