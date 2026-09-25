import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Tests run fully offline with a disposable database and no auth unless a test enables it.
os.environ.setdefault("TPC_DATA_DIR", str(REPO_ROOT / "data"))
os.environ.setdefault("TPC_REQUIRE_AUTH", "false")
os.environ.setdefault("TPC_SEED", "42")


@pytest.fixture(scope="session")
def model():
    from ml.inference_model import get_model

    return get_model(cache_dir=REPO_ROOT / "data" / "models", seed=42)


@pytest.fixture
def sample_features(model):
    from ml.inference_model import sample_inputs

    return sample_inputs(4, seed=7)


@pytest.fixture
def system(model):
    from services.common.bootstrap import build_system

    sysobj = build_system(n_workers=4, n_faulty=0, policy="risk_adaptive", persist=False)
    yield sysobj
    sysobj.reset()
