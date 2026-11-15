#!/usr/bin/env python3
"""Independent RFC 9162 Merkle implementation (differential tests only).

NOT part of the TCB (plan.md §2.0): it is never linked into a product binary.
It exists so `gate-tlog` can be compared against a second implementation rather
than against itself (R10: never invent test vectors).

Reads {"leaves": [hex payload, ...]} on stdin, writes
{"roots": [hex per prefix size 0..N],
 "inclusion": [[hex, ...] per index at full size],
 "consistency": [{"m": m, "n": n, "proof": [hex, ...]}]}
on stdout.
"""
import hashlib
import json
import sys


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(payload: bytes) -> bytes:
    return sha(b"\x00" + payload)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha(b"\x01" + left + right)


def mth(leaves):
    n = len(leaves)
    if n == 0:
        return sha(b"")
    if n == 1:
        return leaves[0]
    k = 1 << ((n - 1).bit_length() - 1)  # largest power of two < n
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def path(m, leaves):
    n = len(leaves)
    if n == 1:
        return []
    k = 1 << ((n - 1).bit_length() - 1)
    if m < k:
        return path(m, leaves[:k]) + [mth(leaves[k:])]
    return path(m - k, leaves[k:]) + [mth(leaves[:k])]


def subproof(m, leaves, complete):
    n = len(leaves)
    if m == n:
        return [] if complete else [mth(leaves)]
    k = 1 << ((n - 1).bit_length() - 1)
    if m <= k:
        return subproof(m, leaves[:k], complete) + [mth(leaves[k:])]
    return subproof(m - k, leaves[k:], False) + [mth(leaves[:k])]


def consistency_proof(m, leaves):
    return subproof(m, leaves, True)


def main() -> int:
    request = json.load(sys.stdin)
    payloads = [bytes.fromhex(h) for h in request["leaves"]]
    leaves = [leaf_hash(p) for p in payloads]
    n = len(leaves)
    out = {
        "roots": [mth(leaves[:size]).hex() for size in range(n + 1)],
        "inclusion": [[h.hex() for h in path(i, leaves)] for i in range(n)],
        "consistency": [
            {"m": m, "n": size, "proof": [h.hex() for h in consistency_proof(m, leaves[:size])]}
            for size in range(1, n + 1)
            for m in range(1, size + 1)
        ],
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
