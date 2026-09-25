"""Binary Merkle tree over signed-envelope hashes, for batch integrity auditing.

Why: verifying N Ed25519 signatures costs O(N) expensive elliptic-curve operations. If an auditor
only needs to confirm that a *published batch root* still matches the stored attempt records, a
Merkle tree gives O(log N) inclusion proofs and a single O(N) cheap-hash recomputation. M5
benchmarks individual-vs-batch verification; this module is the primitive.

Security notes:
  * Leaves and internal nodes use distinct domain-separation prefixes (0x00 / 0x01) to prevent
    second-preimage attacks that confuse a leaf for an internal node (the classic Bitcoin-style
    flaw described by RFC 6962).
  * Odd nodes are promoted, not duplicated, which avoids CVE-2012-2459-style root collisions.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

__all__ = ["MerkleTree", "MerkleProofStep", "verify_proof", "EMPTY_ROOT"]

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"

EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def leaf_hash(data: bytes) -> str:
    return _h(_LEAF_PREFIX + data)


def node_hash(left_hex: str, right_hex: str) -> str:
    return _h(_NODE_PREFIX + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


@dataclass(frozen=True)
class MerkleProofStep:
    sibling: str
    is_left: bool  # True if the sibling sits on the left of the running hash


class MerkleTree:
    """Immutable Merkle tree. Build once from an ordered sequence of leaf byte-strings."""

    def __init__(self, leaves: Iterable[bytes]):
        self._leaf_data: list[bytes] = list(leaves)
        self._levels: list[list[str]] = []
        self._build()

    def _build(self) -> None:
        if not self._leaf_data:
            self._levels = [[]]
            return
        level = [leaf_hash(d) for d in self._leaf_data]
        self._levels = [level]
        while len(level) > 1:
            nxt: list[str] = []
            for i in range(0, len(level) - 1, 2):
                nxt.append(node_hash(level[i], level[i + 1]))
            if len(level) % 2 == 1:  # promote the odd node unchanged
                nxt.append(level[-1])
            self._levels.append(nxt)
            level = nxt

    @classmethod
    def from_hex_digests(cls, digests: Sequence[str]) -> MerkleTree:
        """Build from already-computed hex digests (e.g. envelope hashes)."""
        return cls(bytes.fromhex(d) for d in digests)

    @property
    def size(self) -> int:
        return len(self._leaf_data)

    @property
    def root(self) -> str:
        if not self._leaf_data:
            return EMPTY_ROOT
        return self._levels[-1][0]

    @property
    def depth(self) -> int:
        return len(self._levels)

    def leaf(self, index: int) -> str:
        return self._levels[0][index]

    def proof(self, index: int) -> list[MerkleProofStep]:
        if not 0 <= index < self.size:
            raise IndexError(f"leaf index {index} out of range (size={self.size})")
        steps: list[MerkleProofStep] = []
        idx = index
        for level in self._levels[:-1]:
            if idx % 2 == 0:
                if idx + 1 < len(level):
                    steps.append(MerkleProofStep(sibling=level[idx + 1], is_left=False))
                # else: promoted node, no sibling at this level
            else:
                steps.append(MerkleProofStep(sibling=level[idx - 1], is_left=True))
            idx //= 2
        return steps

    def verify(self, index: int, data: bytes) -> bool:
        return verify_proof(leaf_hash(data), self.proof(index), self.root)


def verify_proof(leaf_hex: str, proof: Sequence[MerkleProofStep], root_hex: str) -> bool:
    """Recompute the root from a leaf hash and its inclusion proof. O(log N) cheap hashes."""
    running = leaf_hex
    for step in proof:
        running = (
            node_hash(step.sibling, running) if step.is_left else node_hash(running, step.sibling)
        )
    return running == root_hex
