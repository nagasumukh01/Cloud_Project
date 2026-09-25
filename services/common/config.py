"""Central configuration. Configuration is kept out of code and read from the environment.

Every setting has a safe default so the system runs offline with zero setup, but anything
security-relevant (API keys, artifact encryption key) has no usable default and must be supplied.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    # --- deployment -------------------------------------------------------
    env: str = field(default_factory=lambda: os.environ.get("TPC_ENV", "local"))
    data_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("TPC_DATA_DIR", REPO_ROOT / "data"))
    )
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "TPC_DATABASE_URL", f"sqlite:///{REPO_ROOT / 'data' / 'trustproof.db'}"
        )
    )
    keystore_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("TPC_KEYSTORE_DIR", REPO_ROOT / "data" / "keys"))
    )

    # --- security ---------------------------------------------------------
    api_key: str = field(default_factory=lambda: os.environ.get("TPC_API_KEY", ""))
    admin_api_key: str = field(default_factory=lambda: os.environ.get("TPC_ADMIN_API_KEY", ""))
    require_auth: bool = field(default_factory=lambda: _env_bool("TPC_REQUIRE_AUTH", True))
    max_age_seconds: float = field(default_factory=lambda: _env_float("TPC_MAX_AGE_S", 300.0))
    skew_tolerance_seconds: float = field(default_factory=lambda: _env_float("TPC_SKEW_S", 30.0))

    # --- scheduling / fault tolerance ------------------------------------
    task_timeout_ms: int = field(default_factory=lambda: _env_int("TPC_TASK_TIMEOUT_MS", 5000))
    max_retries: int = field(default_factory=lambda: _env_int("TPC_MAX_RETRIES", 2))
    max_replicas: int = field(default_factory=lambda: _env_int("TPC_MAX_REPLICAS", 3))

    # --- adaptive verification policy (defaults are documented, not arbitrary; see
    #     docs/research-methodology.md §"Parameter selection") -------------
    risk_threshold_low: float = field(default_factory=lambda: _env_float("TPC_RISK_LOW", 0.25))
    risk_threshold_high: float = field(default_factory=lambda: _env_float("TPC_RISK_HIGH", 0.60))
    exploration_rate: float = field(default_factory=lambda: _env_float("TPC_EXPLORE", 0.05))
    trust_ewma_alpha: float = field(default_factory=lambda: _env_float("TPC_TRUST_ALPHA", 0.15))
    trust_prior: float = field(default_factory=lambda: _env_float("TPC_TRUST_PRIOR", 0.70))
    quarantine_trust_floor: float = field(default_factory=lambda: _env_float("TPC_TRUST_FLOOR", 0.25))

    # --- reproducibility ---------------------------------------------------
    seed: int = field(default_factory=lambda: _env_int("TPC_SEED", 42))

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        Path(self.keystore_dir).mkdir(parents=True, exist_ok=True)
        if not 0.0 <= self.exploration_rate <= 1.0:
            raise ValueError("TPC_EXPLORE must be in [0,1]")
        if not 0.0 <= self.risk_threshold_low <= self.risk_threshold_high <= 1.0:
            raise ValueError("require 0 <= TPC_RISK_LOW <= TPC_RISK_HIGH <= 1")

    @property
    def auth_enabled(self) -> bool:
        return self.require_auth and bool(self.api_key)


_settings: Settings | None = None


def get_settings(refresh: bool = False) -> Settings:
    global _settings
    if _settings is None or refresh:
        _settings = Settings()
    return _settings
