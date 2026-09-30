"""Common primitives shared by the BAKMM-IoD and proposed-protocol simulations.

h(.) is SHA-256 over a length-prefixed concatenation (the '||' operator),
exactly as assumed in Wazid et al. (JSA 2025) Section 7.
Sizes follow the paper: identity 160 bit, random number 160 bit,
hash 256 bit, timestamp 32 bit.
"""
import hashlib
import os
import struct
import time

ID_BYTES = 20      # 160-bit identities / pseudo-identities
RAND_BYTES = 20    # 160-bit random numbers
HASH_BYTES = 32    # SHA-256
TS_BYTES = 4       # 32-bit timestamps

HASH_COUNTER = {"n": 0}


def _enc(x):
    if isinstance(x, bytes):
        return x
    if isinstance(x, int):
        return struct.pack(">I", x & 0xFFFFFFFF)
    if isinstance(x, str):
        return x.encode()
    raise TypeError(type(x))


def h(*parts):
    """One-way hash h(a || b || ...), counted for cost analysis."""
    HASH_COUNTER["n"] += 1
    m = hashlib.sha256()
    for p in parts:
        b = _enc(p)
        m.update(struct.pack(">H", len(b)))
        m.update(b)
    return m.digest()


def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def rnd(n=RAND_BYTES):
    return os.urandom(n)


class Clock:
    """Deterministic simulated clock (seconds) so freshness checks are reproducible."""

    def __init__(self, t=1_700_000_000):
        self.t = t

    def now(self):
        return self.t

    def advance(self, dt=1):
        self.t += dt


def size_bits(msg):
    """Bits on the wire for a dict message (field sizes as in the paper)."""
    total = 0
    for v in msg.values():
        total += (TS_BYTES if isinstance(v, int) else len(v)) * 8
    return total


class AuthError(Exception):
    pass


def reset_hash_counter():
    HASH_COUNTER["n"] = 0


def hashes():
    return HASH_COUNTER["n"]
