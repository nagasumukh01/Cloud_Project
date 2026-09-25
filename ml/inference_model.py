"""The inference workload: a CPU-only, deterministic classifier over the sklearn `digits` dataset.

Choice rationale:
  * `digits` (8x8 handwritten digits, 1797 samples) is bundled with scikit-learn — no download, no
    licence issue, no network at test time. Public domain (UCI/NIST derived).
  * LogisticRegression trains in ~1 s on a laptop CPU and gives ~95 % test accuracy, which is
    plenty: the research object is the *verification* layer, not the classifier's accuracy.
  * Training is seeded and the fitted artifact is cached, so every worker in a run executes the
    byte-identical model. That is essential — otherwise replica disagreement would be caused by
    model nondeterminism rather than by injected faults.

The model exposes `predict_with_uncertainty`, because predictive uncertainty is one of the input
features of the adaptive verification policy (brief §7).
"""

from __future__ import annotations

import hashlib
import pickle
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import numpy as np

MODEL_NAME = "digits-logreg"
MODEL_SEMVER = "1.0.0"
MODEL_VERSION = f"{MODEL_NAME}@{MODEL_SEMVER}"

_lock = threading.Lock()
_cached: InferenceModel | None = None


@dataclass
class Prediction:
    label: int
    confidence: float
    entropy: float

    def as_payload(self) -> dict:
        """Canonical result payload. Rounded to make cross-worker byte-equality well-defined:
        two honest workers must produce identical bytes, otherwise every replica comparison would
        fail on floating-point noise."""
        return {
            "label": int(self.label),
            "confidence": round(float(self.confidence), 6),
            "entropy": round(float(self.entropy), 6),
        }


class InferenceModel:
    """Wraps a fitted sklearn pipeline plus a content hash of its parameters (model provenance)."""

    def __init__(self, pipeline, version: str = MODEL_VERSION, test_accuracy: float | None = None):
        self.pipeline = pipeline
        self.version = version
        self.test_accuracy = test_accuracy
        self.n_features: int = int(pipeline.named_steps["clf"].n_features_in_)
        self.weight_digest: str = self._digest(pipeline)

    @staticmethod
    def _digest(pipeline) -> str:
        clf = pipeline.named_steps["clf"]
        h = hashlib.sha256()
        for arr in (clf.coef_, clf.intercept_):
            h.update(np.ascontiguousarray(arr, dtype=np.float64).tobytes())
        return h.hexdigest()

    def predict_with_uncertainty(self, features: Sequence[float]) -> Prediction:
        x = np.asarray(features, dtype=np.float64).reshape(1, -1)
        if x.shape[1] != self.n_features:
            raise ValueError(f"expected {self.n_features} features, got {x.shape[1]}")
        proba = self.pipeline.predict_proba(x)[0]
        label = int(np.argmax(proba))
        confidence = float(proba[label])
        # Normalised Shannon entropy in [0,1]: a model-uncertainty signal for the risk policy.
        p = np.clip(proba, 1e-12, 1.0)
        entropy = float(-(p * np.log(p)).sum() / np.log(len(p)))
        return Prediction(label=label, confidence=confidence, entropy=entropy)


def _train(seed: int = 42) -> InferenceModel:
    from sklearn.datasets import load_digits
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    X, y = load_digits(return_X_y=True)
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=seed, stratify=y)
    pipe = Pipeline(
        [
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(max_iter=2000, random_state=seed)),
        ]
    )
    pipe.fit(X_tr, y_tr)
    return InferenceModel(pipe, MODEL_VERSION, test_accuracy=float(pipe.score(X_te, y_te)))


def get_model(cache_dir: str | Path | None = None, seed: int = 42) -> InferenceModel:
    """Load the cached model, training it once if needed. Thread-safe, process-local singleton."""
    global _cached
    with _lock:
        if _cached is not None:
            return _cached
        path = None
        if cache_dir is not None:
            path = Path(cache_dir) / f"{MODEL_NAME}-{MODEL_SEMVER}-seed{seed}.pkl"
            if path.exists():
                try:
                    with path.open("rb") as fh:
                        # S301: pickle is unsafe on untrusted input. This file is written by this
                        # same process into a local, non-shared cache directory and is never
                        # transported or received from a worker. A corrupt file is deleted and the
                        # model retrained. Do not point `cache_dir` at a shared or network path.
                        _cached = pickle.load(fh)  # noqa: S301
                    return _cached
                except Exception:
                    path.unlink(missing_ok=True)  # corrupt cache: retrain
        _cached = _train(seed=seed)
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("wb") as fh:
                pickle.dump(_cached, fh)
        return _cached


def reset_model_cache() -> None:
    global _cached
    with _lock:
        _cached = None


def sample_inputs(n: int = 10, seed: int = 42) -> list[list[float]]:
    """Deterministic sample of real inputs, used by the workload generator and tests."""
    from sklearn.datasets import load_digits

    X, _ = load_digits(return_X_y=True)
    rng = np.random.default_rng(seed)
    idx = rng.choice(len(X), size=min(n, len(X)), replace=False)
    return [X[i].tolist() for i in idx]
