"""Cryptographic primitives for TrustProof-Cloud.

Only established primitives are used (Ed25519, SHA-256, BLAKE2b, HMAC-SHA256, AES-256-GCM,
RFC-6962-style Merkle trees). No custom cryptography is invented here, and no security guarantee
is claimed beyond the assumptions recorded in THREAT_MODEL.md.
"""

from .encryption import ArtifactCipher, DecryptionError, generate_key
from .hashing import canonical_bytes, canonical_json, hash_object, input_commitment, sha256_hex
from .keys import KeyPair, KeyStore, generate_keypair, load_public_key, public_key_hex
from .merkle_tree import MerkleTree, verify_proof
from .replay_protection import ReplayGuard
from .signatures import (
    FailureReason,
    ResultEnvelope,
    SignedResult,
    VerificationResult,
    build_envelope,
    sign_envelope,
    verify_signed_result,
)

__all__ = [
    "canonical_bytes", "canonical_json", "hash_object", "input_commitment", "sha256_hex",
    "KeyPair", "KeyStore", "generate_keypair", "load_public_key", "public_key_hex",
    "FailureReason", "ResultEnvelope", "SignedResult", "VerificationResult",
    "build_envelope", "sign_envelope", "verify_signed_result",
    "MerkleTree", "verify_proof",
    "ArtifactCipher", "DecryptionError", "generate_key",
    "ReplayGuard",
]
