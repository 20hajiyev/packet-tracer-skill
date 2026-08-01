"""
Pure-Python Twofish block cipher.

Twofish was designed by Bruce Schneier, John Kelsey, Doug Whiting, David Wagner,
Chris Hall and Niels Ferguson. It is unpatented, uncopyrighted, and free for all
uses, so it can be vendored directly instead of binding to a compiled bridge.

This module exists so that `pkt_codec` has a runtime that works on a clean
checkout with no compiled artifacts and no environment variables. The ctypes
bridge in `twofish.py` remains supported as an optional accelerator.

Reference: "Twofish: A 128-Bit Block Cipher" (Schneier et al., 1998), and the
official test vectors reproduced in `self_test()` below.

The implementation uses the standard "full keying" optimisation: the key-dependent
S-box and the MDS matrix multiply are folded into four 256-entry word tables at
key-schedule time, so the hot loop is four table lookups and three XORs per g().
"""

from __future__ import annotations

MASK32 = 0xFFFFFFFF
BLOCK_SIZE = 16
ROUNDS = 16

# --- q permutation construction (spec section 4.3.5) ------------------------

_Q0_T = (
    (0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4),
    (0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD),
    (0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1),
    (0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA),
)

_Q1_T = (
    (0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5),
    (0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8),
    (0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF),
    (0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA),
)


def _build_q(t: tuple[tuple[int, ...], ...]) -> tuple[int, ...]:
    table = []
    for x in range(256):
        a0, b0 = x >> 4, x & 0xF
        a1 = a0 ^ b0
        b1 = (a0 ^ ((b0 >> 1) | ((b0 & 1) << 3)) ^ (a0 << 3)) & 0xF
        a2, b2 = t[0][a1], t[1][b1]
        a3 = a2 ^ b2
        b3 = (a2 ^ ((b2 >> 1) | ((b2 & 1) << 3)) ^ (a2 << 3)) & 0xF
        a4, b4 = t[2][a3], t[3][b3]
        table.append((b4 << 4) | a4)
    return tuple(table)


Q0 = _build_q(_Q0_T)
Q1 = _build_q(_Q1_T)

# --- GF(2^8) helpers --------------------------------------------------------

MDS_POLY = 0x169  # x^8 + x^6 + x^5 + x^3 + 1
RS_POLY = 0x14D   # x^8 + x^6 + x^3 + x^2 + 1


def _gf_mul(a: int, b: int, poly: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= poly
    return result & 0xFF


# MDS matrix, by column: column i scaled by y_i contributes to z0..z3.
_MDS_COLUMNS = (
    (0x01, 0x5B, 0xEF, 0xEF),
    (0xEF, 0xEF, 0x5B, 0x01),
    (0x5B, 0xEF, 0x01, 0xEF),
    (0x5B, 0x01, 0xEF, 0x5B),
)

# mds_column_word[i][b] == the 32-bit little-endian word contributed by byte b
# sitting in position i of the MDS input vector.
_MDS_COLUMN_WORD: tuple[tuple[int, ...], ...] = tuple(
    tuple(
        (_gf_mul(column[0], b, MDS_POLY))
        | (_gf_mul(column[1], b, MDS_POLY) << 8)
        | (_gf_mul(column[2], b, MDS_POLY) << 16)
        | (_gf_mul(column[3], b, MDS_POLY) << 24)
        for b in range(256)
    )
    for column in _MDS_COLUMNS
)

_RS_MATRIX = (
    (0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E),
    (0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5),
    (0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19),
    (0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03),
)


def _rs_encode(chunk: bytes) -> int:
    """Map 8 key bytes to one 32-bit S-vector word via the RS matrix."""
    word = 0
    for row_index, row in enumerate(_RS_MATRIX):
        acc = 0
        for coefficient, byte in zip(row, chunk):
            acc ^= _gf_mul(coefficient, byte, RS_POLY)
        word |= acc << (8 * row_index)
    return word


# --- rotations --------------------------------------------------------------


def _rol32(value: int, count: int) -> int:
    count &= 31
    return ((value << count) | (value >> (32 - count))) & MASK32


def _ror32(value: int, count: int) -> int:
    count &= 31
    return ((value >> count) | (value << (32 - count))) & MASK32


# --- h function -------------------------------------------------------------


def _h_byte(position: int, byte: int, l_bytes: list[tuple[int, int, int, int]], k: int) -> int:
    """The q-permutation cascade of h() for one byte position, before MDS."""
    y = byte
    if k == 4:
        y = (Q1, Q0, Q0, Q1)[position][y] ^ l_bytes[3][position]
    if k >= 3:
        y = (Q1, Q1, Q0, Q0)[position][y] ^ l_bytes[2][position]
    y = (Q0, Q1, Q0, Q1)[position][y] ^ l_bytes[1][position]
    y = (Q0, Q0, Q1, Q1)[position][y] ^ l_bytes[0][position]
    return (Q1, Q0, Q1, Q0)[position][y]


def _h(x: int, l_words: list[int], k: int) -> int:
    l_bytes = [
        (word & 0xFF, (word >> 8) & 0xFF, (word >> 16) & 0xFF, (word >> 24) & 0xFF)
        for word in l_words
    ]
    result = 0
    for position in range(4):
        byte = (x >> (8 * position)) & 0xFF
        result ^= _MDS_COLUMN_WORD[position][_h_byte(position, byte, l_bytes, k)]
    return result


class Twofish:
    """Twofish in ECB single-block form, API-compatible with the ctypes bridge."""

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Twofish key must be bytes")
        key = bytes(key)
        if not 0 < len(key) <= 32:
            raise ValueError("invalid Twofish key length")

        # Twofish is defined for 128/192/256-bit keys; shorter keys are
        # zero-padded up to the next legal size, matching the reference library.
        for legal in (16, 24, 32):
            if len(key) <= legal:
                key = key.ljust(legal, b"\x00")
                break

        k = len(key) // 8
        words = [int.from_bytes(key[i : i + 4], "little") for i in range(0, len(key), 4)]
        me = [words[i] for i in range(0, 2 * k, 2)]
        mo = [words[i] for i in range(1, 2 * k, 2)]
        s_words = [_rs_encode(key[8 * i : 8 * (i + 1)]) for i in range(k)]
        s_words.reverse()

        subkeys: list[int] = []
        for i in range(20):
            a = _h((2 * i) * 0x01010101, me, k)
            b = _rol32(_h((2 * i + 1) * 0x01010101, mo, k), 8)
            subkeys.append((a + b) & MASK32)
            subkeys.append(_rol32((a + 2 * b) & MASK32, 9))
        self._k = subkeys

        # Fold the key-dependent S-box and the MDS multiply into four word
        # tables, so g() costs four lookups instead of a full h() evaluation.
        s_bytes = [
            (word & 0xFF, (word >> 8) & 0xFF, (word >> 16) & 0xFF, (word >> 24) & 0xFF)
            for word in s_words
        ]
        self._sbox: list[tuple[int, ...]] = [
            tuple(
                _MDS_COLUMN_WORD[position][_h_byte(position, byte, s_bytes, k)]
                for byte in range(256)
            )
            for position in range(4)
        ]

    def _g(self, x: int) -> int:
        sbox = self._sbox
        return (
            sbox[0][x & 0xFF]
            ^ sbox[1][(x >> 8) & 0xFF]
            ^ sbox[2][(x >> 16) & 0xFF]
            ^ sbox[3][(x >> 24) & 0xFF]
        )

    # The round function is written out longhand rather than calling `_g`,
    # `_rol32` and `_ror32`. In CPython the call overhead dominates: inlining
    # is worth roughly 2x, and these two methods are the whole cost of
    # encoding or decoding a `.pkt`.
    #
    # `g(rol32(r1, 8))` is folded into the lookups: rotating left by 8 permutes
    # the byte positions to (b3, b0, b1, b2), so the rotate never has to happen.

    def encrypt(self, block: bytes) -> bytes:
        if not isinstance(block, (bytes, bytearray)):
            raise TypeError("block must be bytes")
        if len(block) != BLOCK_SIZE:
            raise ValueError("Twofish encrypt expects a 16-byte block")

        k = self._k
        s0, s1, s2, s3 = self._sbox
        r0 = int.from_bytes(block[0:4], "little") ^ k[0]
        r1 = int.from_bytes(block[4:8], "little") ^ k[1]
        r2 = int.from_bytes(block[8:12], "little") ^ k[2]
        r3 = int.from_bytes(block[12:16], "little") ^ k[3]

        for index in range(8, 40, 2):
            t0 = s0[r0 & 0xFF] ^ s1[(r0 >> 8) & 0xFF] ^ s2[(r0 >> 16) & 0xFF] ^ s3[r0 >> 24]
            t1 = s0[r1 >> 24] ^ s1[r1 & 0xFF] ^ s2[(r1 >> 8) & 0xFF] ^ s3[(r1 >> 16) & 0xFF]
            x = r2 ^ ((t0 + t1 + k[index]) & MASK32)
            r0, r1, r2, r3 = (
                (x >> 1) | ((x & 1) << 31),
                (((r3 << 1) & MASK32) | (r3 >> 31)) ^ ((t0 + 2 * t1 + k[index + 1]) & MASK32),
                r0,
                r1,
            )

        # The final swap is undone by reading the registers back in 2,3,0,1 order.
        return (
            (r2 ^ k[4]).to_bytes(4, "little")
            + (r3 ^ k[5]).to_bytes(4, "little")
            + (r0 ^ k[6]).to_bytes(4, "little")
            + (r1 ^ k[7]).to_bytes(4, "little")
        )

    def decrypt(self, block: bytes) -> bytes:
        if not isinstance(block, (bytes, bytearray)):
            raise TypeError("block must be bytes")
        if len(block) != BLOCK_SIZE:
            raise ValueError("Twofish decrypt expects a 16-byte block")

        k = self._k
        s0, s1, s2, s3 = self._sbox
        r0 = int.from_bytes(block[0:4], "little") ^ k[4]
        r1 = int.from_bytes(block[4:8], "little") ^ k[5]
        r2 = int.from_bytes(block[8:12], "little") ^ k[6]
        r3 = int.from_bytes(block[12:16], "little") ^ k[7]

        for index in range(38, 6, -2):
            t0 = s0[r0 & 0xFF] ^ s1[(r0 >> 8) & 0xFF] ^ s2[(r0 >> 16) & 0xFF] ^ s3[r0 >> 24]
            t1 = s0[r1 >> 24] ^ s1[r1 & 0xFF] ^ s2[(r1 >> 8) & 0xFF] ^ s3[(r1 >> 16) & 0xFF]
            x = r3 ^ ((t0 + 2 * t1 + k[index + 1]) & MASK32)
            r0, r1, r2, r3 = (
                (((r2 << 1) & MASK32) | (r2 >> 31)) ^ ((t0 + t1 + k[index]) & MASK32),
                (x >> 1) | ((x & 1) << 31),
                r0,
                r1,
            )

        return (
            (r2 ^ k[0]).to_bytes(4, "little")
            + (r3 ^ k[1]).to_bytes(4, "little")
            + (r0 ^ k[2]).to_bytes(4, "little")
            + (r1 ^ k[3]).to_bytes(4, "little")
        )


# Official Twofish test vectors: the I=3 (128-bit) and I=4 (192/256-bit) cases
# from section B.2 of the Twofish book.
TEST_VECTORS = (
    (
        "9F589F5CF6122C32B6BFEC2F2AE8C35A",
        "D491DB16E7B1C39E86CB086B789F5419",
        "019F9809DE1711858FAAC3A3BA20FBC3",
    ),
    (
        "88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44",
        "39DA69D6BA4997D585B6DC073CA341B2",
        "182B02D81497EA45F9DAACDC29193A65",
    ),
    (
        "D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F",
        "90AFE91BB288544F2C32DC239B2635E6",
        "6CB4561C40BF0A9705931CB6D408E7FA",
    ),
)


def self_test() -> None:
    """Verify against the official vectors. Raises on any mismatch."""
    for key_hex, plain_hex, cipher_hex in TEST_VECTORS:
        key = bytes.fromhex(key_hex)
        plain = bytes.fromhex(plain_hex)
        cipher = bytes.fromhex(cipher_hex)
        engine = Twofish(key)
        if engine.encrypt(plain) != cipher:
            raise ValueError(f"Twofish encrypt vector failed for {len(key) * 8}-bit key")
        if engine.decrypt(cipher) != plain:
            raise ValueError(f"Twofish decrypt vector failed for {len(key) * 8}-bit key")


if __name__ == "__main__":
    self_test()
    print("pure-python twofish: all official vectors pass")
