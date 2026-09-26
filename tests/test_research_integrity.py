"""Research-integrity guards.

These tests protect the *validity of the results*, not the behaviour of the software. They are as
important as the functional tests: a leaked ground-truth label or an unseeded RNG would silently
invalidate every number the project reports.
"""

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Modules that make online decisions. None of them may consult the fault-injector labels.
DECISION_MODULES = [
    "services/risk_model/risk.py",
    "services/trust_engine/trust.py",
    "services/scheduler/registry.py",
    "services/verifier/verifier.py",
    "services/workers/worker.py",
]


def _names_used(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    return names


@pytest.mark.parametrize("rel", DECISION_MODULES)
def test_no_ground_truth_leakage_into_decision_code(rel):
    """Decision-making modules must not reference the ground-truth table at all."""
    names = _names_used(REPO_ROOT / rel)
    forbidden = {"GroundTruth", "was_tampered"}
    assert not (names & forbidden), f"{rel} references ground truth: {names & forbidden}"


def test_scheduler_only_writes_ground_truth_never_reads_it():
    """The scheduler may *record* injector labels for later evaluation (inside `_persist`), but no
    scheduling or verification decision may branch on them. We therefore exempt `_persist` and
    assert the label appears in no control-flow construct anywhere else in the module."""
    src = (REPO_ROOT / "services/scheduler/scheduler.py").read_text(encoding="utf-8")
    tree = ast.parse(src)

    persist_nodes = {
        id(n)
        for fn in ast.walk(tree)
        if isinstance(fn, ast.FunctionDef) and fn.name == "_persist"
        for n in ast.walk(fn)
    }
    gt_names = {"was_tampered", "GroundTruth"}

    for node in ast.walk(tree):
        if id(node) in persist_nodes:
            continue
        if isinstance(node, (ast.If, ast.While, ast.Compare, ast.BoolOp, ast.IfExp)):
            seg = ast.get_source_segment(src, node) or ""
            assert not any(g in seg for g in gt_names), (
                f"ground-truth label used in scheduling control flow: {seg[:120]}"
            )


def test_decision_modules_do_not_seed_global_random():
    """Global `random.seed()` in library code would silently couple unrelated components and make
    experiment seeding a lie. Randomness must be injected as an explicit Random instance."""
    for rel in DECISION_MODULES + ["services/scheduler/scheduler.py"]:
        src = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert "random.seed(" not in src, f"{rel} seeds the global RNG"


def test_no_hardcoded_secrets_in_source():
    """No private keys committed to the repository. Markers are assembled at runtime so that this
    test file does not trip its own check."""
    pem = "-----BEGIN "
    suspicious = [pem + kind + " PRIVATE KEY" for kind in ("", "OPENSSH", "RSA", "EC")]
    for path in REPO_ROOT.rglob("*.py"):
        if any(part in str(path) for part in ("/data/", "/.venv/", "test_research_integrity")):
            continue
        text = path.read_text(errors="ignore")
        for marker in suspicious:
            assert marker not in text, f"{path} contains embedded key material"


def test_artifact_key_has_no_usable_default():
    """The encryption key must never fall back to a built-in constant."""
    import os

    from crypto.encryption import key_from_env

    saved = os.environ.pop("TPC_ARTIFACT_KEY", None)
    try:
        with pytest.raises(RuntimeError):
            key_from_env()
    finally:
        if saved is not None:
            os.environ["TPC_ARTIFACT_KEY"] = saved


def test_experiment_reproducibility_same_seed_same_trace():
    """Two systems built with the same seed must produce identical decision traces. Without this,
    no reported comparison between policy arms is meaningful."""
    from ml.inference_model import sample_inputs
    from services.common.bootstrap import build_system

    feats = sample_inputs(15, seed=31)

    def trace(seed):
        s = build_system(n_workers=5, n_faulty=1, fault_rate=0.5,
                         behaviours=("tamper_payload",), policy="risk_adaptive", seed=seed)
        return [(o.decision, tuple(o.executed_by), o.verdict.value)
                for o in (s.scheduler.submit(f, sensitivity="medium") for f in feats)]

    assert trace(101) == trace(101)


def test_different_seeds_produce_different_traces():
    """Sanity check on the reproducibility test: seeding must actually be doing something."""
    from ml.inference_model import sample_inputs
    from services.common.bootstrap import build_system

    feats = sample_inputs(15, seed=31)

    def trace(seed):
        s = build_system(n_workers=5, n_faulty=1, fault_rate=0.5, policy="risk_adaptive", seed=seed)
        return [tuple(o.executed_by) for o in (s.scheduler.submit(f) for f in feats)]

    assert trace(101) != trace(999)


def test_documentation_contains_no_novelty_or_patent_claims():
    """The brief forbids novelty/patentability claims without a prior-art search (not performed).

    We flag a banned phrase only when it is *asserted*. Explicitly disclaiming it ("no novelty
    claim is made", "not patentable") is exactly the behaviour we want, so a line carrying a
    negation marker is allowed. This keeps the guard useful instead of banning the disclaimers.
    """
    banned = ["patentable", "patent-pending", "novel contribution", "first-ever",
              "world's first", "provably secure", "unbreakable", "completely secure"]
    negations = ("not ", "no ", "never", "without", "non-claim", "cannot", "n't",
                 "forbid", "must not", "nothing", "neither", "avoid", "unsupported",
                 "would be required", "requires a qualified")

    offenders = []
    for doc in list(REPO_ROOT.glob("*.md")) + list((REPO_ROOT / "docs").glob("*.md")):
        for lineno, line in enumerate(doc.read_text(encoding="utf-8").lower().splitlines(), 1):
            for phrase in banned:
                if phrase in line and not any(n in line for n in negations):
                    offenders.append(f"{doc.name}:{lineno}: {phrase!r} -> {line.strip()[:100]}")
    assert not offenders, "unsupported claims asserted in documentation:\n" + "\n".join(offenders)
