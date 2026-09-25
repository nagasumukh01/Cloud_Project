"""Cryptography tests: signatures, hashing, Merkle trees, AES-GCM, replay protection."""

from datetime import UTC, datetime, timedelta

import pytest

from crypto.encryption import (
    ArtifactCipher,
    DecryptionError,
    derive_key_from_password,
    generate_key,
)
from crypto.hashing import canonical_json, hash_object, input_commitment
from crypto.keys import KeyStore, generate_keypair, load_public_key
from crypto.merkle_tree import EMPTY_ROOT, MerkleTree, verify_proof
from crypto.replay_protection import ReplayGuard
from crypto.signatures import (
    FailureReason,
    SignedResult,
    build_envelope,
    sign_envelope,
    verify_signed_result,
)


# --------------------------------------------------------------------------- hashing
def test_canonical_json_is_key_order_independent():
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_canonical_json_rejects_nan():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_hash_object_is_deterministic_and_sensitive():
    a = hash_object({"label": 3, "confidence": 0.5})
    b = hash_object({"confidence": 0.5, "label": 3})
    c = hash_object({"label": 4, "confidence": 0.5})
    assert a == b and a != c and len(a) == 64


def test_input_commitment_differs_from_result_hash_domain():
    payload = [1.0, 2.0, 3.0]
    assert input_commitment(payload) != hash_object(payload)


# --------------------------------------------------------------------------- keys
def test_keypair_repr_never_leaks_private_key():
    kp = generate_keypair("w-1")
    assert "redacted" in repr(kp)
    assert kp.private_key.private_bytes_raw().hex() not in repr(kp)


def test_public_key_roundtrip():
    kp = generate_keypair("w-1")
    assert load_public_key(kp.public_hex).public_bytes_raw().hex() == kp.public_hex


def test_load_public_key_rejects_bad_input():
    with pytest.raises(ValueError):
        load_public_key("not-hex")
    with pytest.raises(ValueError):
        load_public_key("ab" * 10)


def test_keystore_persists_and_reloads(tmp_path):
    ks = KeyStore(tmp_path / "keys")
    kp1 = ks.create("w-01")
    kp2 = ks.load("w-01")
    assert kp1.public_hex == kp2.public_hex
    assert ks.load_or_create("w-02").public_hex != kp1.public_hex


# --------------------------------------------------------------------------- signatures
@pytest.fixture
def signed():
    kp = generate_keypair("w-1")
    payload = {"label": 7, "confidence": 0.93}
    env = build_envelope(
        task_id="task-1", worker_id="w-1", model_version="digits-logreg@1.0.0",
        input_commitment=input_commitment([1, 2, 3]), payload=payload,
    )
    return kp, sign_envelope(kp, env, payload), payload


def test_valid_signature_verifies(signed):
    kp, sr, _ = signed
    res = verify_signed_result(sr, public_key_hex=kp.public_hex)
    assert res.ok and res.reason == FailureReason.NONE
    assert res.checks["signature"] and res.checks["result_hash"]


def test_tampered_payload_is_detected(signed):
    kp, sr, payload = signed
    mutated = SignedResult(sr.envelope, sr.signature_hex, {**payload, "label": 8})
    res = verify_signed_result(mutated, public_key_hex=kp.public_hex)
    assert not res.ok and res.reason == FailureReason.HASH_MISMATCH


def test_forged_signature_is_rejected(signed):
    kp, sr, payload = signed
    raw = bytearray(bytes.fromhex(sr.signature_hex))
    raw[0] ^= 0xFF
    res = verify_signed_result(SignedResult(sr.envelope, raw.hex(), payload),
                               public_key_hex=kp.public_hex)
    assert not res.ok and res.reason == FailureReason.BAD_SIGNATURE


def test_wrong_public_key_is_rejected(signed):
    _, sr, _ = signed
    other = generate_keypair("w-2")
    res = verify_signed_result(sr, public_key_hex=other.public_hex)
    assert not res.ok and res.reason == FailureReason.BAD_SIGNATURE


def test_unknown_worker_is_rejected(signed):
    _, sr, _ = signed
    assert verify_signed_result(sr, public_key_hex=None).reason == FailureReason.UNKNOWN_WORKER


def test_cross_task_replay_is_rejected(signed):
    kp, sr, _ = signed
    res = verify_signed_result(sr, public_key_hex=kp.public_hex, expected_task_id="task-2")
    assert not res.ok and res.reason == FailureReason.TASK_MISMATCH


def test_input_commitment_binding(signed):
    kp, sr, _ = signed
    res = verify_signed_result(sr, public_key_hex=kp.public_hex,
                               expected_input_commitment=input_commitment([9, 9, 9]))
    assert not res.ok and res.reason == FailureReason.INPUT_MISMATCH


def test_model_version_allowlist(signed):
    kp, sr, _ = signed
    res = verify_signed_result(sr, public_key_hex=kp.public_hex,
                               allowed_model_versions={"digits-logreg@2.0.0"})
    assert not res.ok and res.reason == FailureReason.MODEL_NOT_ALLOWED


def test_stale_timestamp_is_rejected():
    kp = generate_keypair("w-1")
    payload = {"label": 1}
    env = build_envelope(task_id="t", worker_id="w-1", model_version="m@1",
                         input_commitment=input_commitment([1]), payload=payload,
                         timestamp="2020-01-01T00:00:00Z")
    res = verify_signed_result(sign_envelope(kp, env, payload), public_key_hex=kp.public_hex)
    assert not res.ok and res.reason == FailureReason.STALE


def test_metadata_mutation_breaks_signature(signed):
    """Any change to envelope metadata must invalidate the signature."""
    from dataclasses import replace

    kp, sr, payload = signed
    for field_name, value in [("worker_id", "w-evil"), ("model_version", "m@9"),
                              ("timestamp", "2031-01-01T00:00:00Z")]:
        mutated = SignedResult(replace(sr.envelope, **{field_name: value}), sr.signature_hex, payload)
        assert verify_signed_result(mutated, public_key_hex=kp.public_hex).reason in (
            FailureReason.BAD_SIGNATURE, FailureReason.MALFORMED,
        ), field_name


def test_malformed_envelope_short_circuits():
    from dataclasses import replace

    kp = generate_keypair("w-1")
    payload = {"label": 1}
    env = build_envelope(task_id="t", worker_id="w-1", model_version="m@1",
                         input_commitment=input_commitment([1]), payload=payload)
    bad = SignedResult(replace(env, nonce="short"), "00" * 64, payload)
    assert verify_signed_result(bad, public_key_hex=kp.public_hex).reason == FailureReason.MALFORMED


# --------------------------------------------------------------------------- merkle
def test_merkle_empty_and_single():
    assert MerkleTree([]).root == EMPTY_ROOT
    t = MerkleTree([b"only"])
    assert t.size == 1 and t.verify(0, b"only")


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 8, 17, 64])
def test_merkle_inclusion_proofs_all_sizes(n):
    leaves = [f"attempt-{i}".encode() for i in range(n)]
    tree = MerkleTree(leaves)
    for i in range(n):
        assert tree.verify(i, leaves[i]), f"leaf {i} of {n}"
    assert not tree.verify(0, b"not-in-tree")


def test_merkle_root_changes_when_any_leaf_changes():
    a = MerkleTree([b"a", b"b", b"c"]).root
    b = MerkleTree([b"a", b"b", b"c!"]).root
    assert a != b


def test_merkle_order_matters():
    assert MerkleTree([b"a", b"b"]).root != MerkleTree([b"b", b"a"]).root


def test_merkle_proof_with_wrong_root_fails():
    leaves = [b"x", b"y", b"z"]
    t = MerkleTree(leaves)
    from crypto.merkle_tree import leaf_hash

    assert not verify_proof(leaf_hash(b"x"), t.proof(0), "00" * 32)


def test_merkle_out_of_range():
    with pytest.raises(IndexError):
        MerkleTree([b"a"]).proof(5)


# --------------------------------------------------------------------------- encryption
def test_aesgcm_roundtrip_and_tamper_detection():
    c = ArtifactCipher(generate_key())
    blob = c.encrypt(b"sensitive artifact", aad=b"task-1")
    assert c.decrypt(blob, aad=b"task-1") == b"sensitive artifact"
    corrupted = bytearray(blob)
    corrupted[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        c.decrypt(bytes(corrupted), aad=b"task-1")


def test_aesgcm_wrong_aad_and_wrong_key_fail():
    c = ArtifactCipher(generate_key())
    blob = c.encrypt(b"data", aad=b"ctx-a")
    with pytest.raises(DecryptionError):
        c.decrypt(blob, aad=b"ctx-b")
    with pytest.raises(DecryptionError):
        ArtifactCipher(generate_key()).decrypt(blob, aad=b"ctx-a")


def test_aesgcm_nonce_is_unique_per_message():
    c = ArtifactCipher(generate_key())
    nonces = {c.encrypt(b"same")[:12] for _ in range(200)}
    assert len(nonces) == 200


def test_encrypt_object_and_file_roundtrip(tmp_path):
    c = ArtifactCipher(generate_key())
    assert c.decrypt_object(c.encrypt_object({"a": [1, 2]}, aad="t"), aad="t") == {"a": [1, 2]}
    src = tmp_path / "in.bin"
    src.write_bytes(b"model-weights")
    c.encrypt_file(src, tmp_path / "enc")
    c.decrypt_file(tmp_path / "enc", tmp_path / "out")
    assert (tmp_path / "out").read_bytes() == b"model-weights"


def test_cipher_repr_hides_key():
    assert "redacted" in repr(ArtifactCipher(generate_key()))


def test_password_kdf_is_deterministic_per_salt():
    salt = b"0" * 16
    assert derive_key_from_password("pw", salt) == derive_key_from_password("pw", salt)
    assert derive_key_from_password("pw", salt) != derive_key_from_password("pw", b"1" * 16)


# --------------------------------------------------------------------------- replay
def test_replay_guard_accepts_once_rejects_twice():
    g = ReplayGuard()
    now = datetime.now(UTC)
    assert g.check_and_register("w-1", "n1", now).accepted
    d = g.check_and_register("w-1", "n1", now)
    assert not d.accepted and d.reason == "replayed_nonce"


def test_replay_guard_is_per_worker():
    g = ReplayGuard()
    now = datetime.now(UTC)
    assert g.check_and_register("w-1", "n1", now).accepted
    assert g.check_and_register("w-2", "n1", now).accepted


def test_replay_guard_rejects_stale_and_future():
    g = ReplayGuard(max_age_seconds=60, skew_tolerance_seconds=10)
    now = datetime.now(UTC)
    assert g.check_and_register("w", "a", now - timedelta(seconds=120)).reason == "stale_timestamp"
    assert g.check_and_register("w", "b", now + timedelta(seconds=60)).reason == "future_timestamp"


def test_replay_guard_does_not_register_rejected_nonces():
    g = ReplayGuard(max_age_seconds=60)
    now = datetime.now(UTC)
    g.check_and_register("w", "n", now - timedelta(seconds=600))
    assert not g.has_seen("w", "n")


def test_replay_guard_prunes_and_resets():
    g = ReplayGuard(max_age_seconds=1, skew_tolerance_seconds=0, ttl_multiplier=1.0)
    now = datetime.now(UTC)
    g.check_and_register("w", "n", now)
    assert len(g) == 1
    g.prune(now + timedelta(seconds=10))
    assert len(g) == 0
    g.check_and_register("w", "n2", datetime.now(UTC))
    g.reset()
    assert len(g) == 0
