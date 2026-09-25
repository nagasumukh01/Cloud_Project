"""Dataset loading. Openly licensed or synthetic only - no downloads, no licence risk.

`digits` ships inside scikit-learn (derived from the UCI/NIST Optical Recognition of Handwritten
Digits set, public domain). Nothing here reaches the network, so experiments run fully offline and
reproducibly.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class DatasetInfo:
    name: str
    n_samples: int
    n_features: int
    n_classes: int
    licence: str
    source: str
    offline: bool = True


DATASETS = {
    "digits": DatasetInfo(
        name="digits", n_samples=1797, n_features=64, n_classes=10,
        licence="Public domain (UCI/NIST derived)",
        source="bundled with scikit-learn (sklearn.datasets.load_digits)",
    ),
    "synthetic_tabular": DatasetInfo(
        name="synthetic_tabular", n_samples=0, n_features=20, n_classes=2,
        licence="Generated locally (no licence constraints)",
        source="sklearn.datasets.make_classification",
    ),
}


def load_digits_xy():
    from sklearn.datasets import load_digits

    return load_digits(return_X_y=True)


def make_synthetic_tabular(n_samples: int = 2000, n_features: int = 20, seed: int = 42):
    """Synthetic fallback, used when a second task type is needed without any external data."""
    from sklearn.datasets import make_classification

    return make_classification(
        n_samples=n_samples, n_features=n_features, n_informative=max(2, n_features // 2),
        n_redundant=2, n_classes=2, random_state=seed,
    )


def worker_telemetry_frame(n_workers: int = 8, n_steps: int = 500, anomalous: tuple[int, ...] = (6, 7),
                           seed: int = 42):
    """Synthetic per-worker telemetry for the M4 anomaly-detection study.

    Columns: latency_ms, cpu_pct, mem_mb, failed_tasks, timeouts, msg_inconsistencies.
    Anomalous workers get heavier tails and more failures. Labels are returned SEPARATELY so they
    can be kept out of any feature matrix by construction.
    """
    rng = np.random.default_rng(seed)
    rows, labels = [], []
    for step in range(n_steps):
        for w in range(n_workers):
            bad = w in anomalous
            latency = rng.gamma(shape=9.0 if bad else 4.0, scale=3.0 if bad else 2.0)
            rows.append({
                "step": step,
                "worker_id": f"w-{w:02d}",
                "latency_ms": float(latency),
                "cpu_pct": float(np.clip(rng.normal(75 if bad else 45, 12), 0, 100)),
                "mem_mb": float(np.clip(rng.normal(420 if bad else 300, 60), 0, None)),
                "failed_tasks": int(rng.poisson(1.2 if bad else 0.1)),
                "timeouts": int(rng.poisson(0.8 if bad else 0.05)),
                "msg_inconsistencies": int(rng.poisson(0.5 if bad else 0.01)),
            })
            labels.append(int(bad))
    import pandas as pd

    return pd.DataFrame(rows), np.array(labels)
