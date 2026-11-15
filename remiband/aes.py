"""Pure-Python AES-128, single-block ECB encrypt.

The Mi Band authentication handshake needs exactly one primitive: encrypt a
16-byte nonce under a 16-byte key, AES-128 in ECB mode, no padding.  That is
all this module does.

Deliberately stdlib-only.  The analysis machine has no pip, and pulling in
`cryptography` just to XOR a challenge would be a poor trade.  The S-box is
derived from the GF(2^8) inverse + affine transform at import time rather than
pasted in as a 256 byte table, so there is no transcription risk.

FIPS-197 test vector is asserted in tests/test_aes.py.
"""

from __future__ import annotations

__all__ = [
    "encrypt_block",
    "encrypt_ecb",
    "expand_key",
    "SBOX",
    "BLOCK_SIZE",
    "KEY_SIZE",
]

BLOCK_SIZE = 16
KEY_SIZE = 16


# --------------------------------------------------------------------------
# GF(2^8) arithmetic, polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)
# --------------------------------------------------------------------------

def _gf_mul(a: int, b: int) -> int:
    """Carry-less multiply in GF(2^8), reduced by 0x11b."""
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def _gf_pow(a: int, n: int) -> int:
    r = 1
    while n:
        if n & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        n >>= 1
    return r


def _gf_inv(a: int) -> int:
    """Multiplicative inverse; 0 maps to 0 by AES convention."""
    return 0 if a == 0 else _gf_pow(a, 254)


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox() -> tuple[int, ...]:
    box = []
    for a in range(256):
        b = _gf_inv(a)
        box.append(
            b ^ _rotl8(b, 1) ^ _rotl8(b, 2) ^ _rotl8(b, 3) ^ _rotl8(b, 4) ^ 0x63
        )
    return tuple(box)


SBOX: tuple[int, ...] = _build_sbox()
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


# --------------------------------------------------------------------------
# Key schedule
# --------------------------------------------------------------------------

def expand_key(key: bytes) -> list[list[int]]:
    """Expand a 16-byte key into 11 round keys of 16 bytes each.

    Round key bytes are in column-major order, which is the same layout as the
    AES state, so ``rk[r + 4*c]`` is state byte (row r, column c).
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")

    w: list[list[int]] = [list(key[i:i + 4]) for i in range(0, 16, 4)]

    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]                      # RotWord
            t = [SBOX[b] for b in t]               # SubWord
            t[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])

    return [
        [b for word in w[r * 4:(r + 1) * 4] for b in word]
        for r in range(11)
    ]


# --------------------------------------------------------------------------
# Round transforms.  State is a flat 16-byte list, index = row + 4*column.
# --------------------------------------------------------------------------

def _add_round_key(s: list[int], rk: list[list[int]], rnd: int) -> None:
    k = rk[rnd]
    for i in range(16):
        s[i] ^= k[i]


def _sub_bytes(s: list[int]) -> None:
    for i in range(16):
        s[i] = SBOX[s[i]]


def _shift_rows(s: list[int]) -> None:
    # Row r is rotated left by r positions. Row 0 is untouched.
    for r in (1, 2, 3):
        row = [s[r + 4 * c] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            s[r + 4 * c] = row[c]


def _mix_columns(s: list[int]) -> None:
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
        s[i]     = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        s[i + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        s[i + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        s[i + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)


# --------------------------------------------------------------------------
# Block / ECB entry points
# --------------------------------------------------------------------------

def encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypt one 16-byte block with a 16-byte key."""
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"AES block must be 16 bytes, got {len(block)}")

    rk = expand_key(key)
    s = list(block)

    _add_round_key(s, rk, 0)
    for rnd in range(1, 10):
        _sub_bytes(s)
        _shift_rows(s)
        _mix_columns(s)
        _add_round_key(s, rk, rnd)
    _sub_bytes(s)
    _shift_rows(s)
    _add_round_key(s, rk, 10)

    return bytes(s)


def encrypt_ecb(key: bytes, data: bytes) -> bytes:
    """ECB-encrypt `data`, which must be a whole number of blocks.

    Kept for completeness (firmware blobs are ECB); the auth handshake only
    ever passes a single block.
    """
    if len(data) % BLOCK_SIZE:
        raise ValueError("ECB input length must be a multiple of 16")
    return b"".join(
        encrypt_block(key, data[i:i + BLOCK_SIZE])
        for i in range(0, len(data), BLOCK_SIZE)
    )
