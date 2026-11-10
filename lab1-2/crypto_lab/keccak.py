"""Реалізація Keccak / SHA-3 (FIPS 202) з нуля.

Конструкція "губки" (sponge): стан 5x5 слів по 64 біти (1600 біт),
перестановка Keccak-f[1600] з 24 раундів (кроки theta, rho, pi, chi, iota).
Підтримуються SHA3-224/256/384/512, SHAKE128/256 та "оригінальний"
Keccak-256 (доповнення 0x01, як у Ethereum).
"""

from __future__ import annotations

MASK64 = (1 << 64) - 1

# Раундові константи RC[i] для кроку iota
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Зсуви r[x][y] для кроку rho
R = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def rot(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64 if n else x


def keccak_round(a: list[list[int]], rc: int) -> list[list[int]]:
    # theta
    c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
    d = [c[(x - 1) % 5] ^ rot(c[(x + 1) % 5], 1) for x in range(5)]
    a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
    # rho та pi
    b = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            b[y][(2 * x + 3 * y) % 5] = rot(a[x][y], R[x][y])
    # chi
    a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)]
         for x in range(5)]
    # iota
    a[0][0] ^= rc
    return a


def keccak_f(a: list[list[int]]) -> list[list[int]]:
    """Перестановка Keccak-f[1600]: 24 раунди."""
    for i in range(24):
        a = keccak_round(a, RC[i])
    return a


def _absorb_block(state, block: bytes) -> list[list[int]]:
    for i in range(len(block) // 8):
        lane = int.from_bytes(block[8 * i: 8 * i + 8], "little")
        x, y = i % 5, i // 5
        state[x][y] ^= lane
    return keccak_f(state)


def _state_bytes(state, rate: int) -> bytes:
    out = b""
    for i in range(rate // 8):
        x, y = i % 5, i // 5
        out += state[x][y].to_bytes(8, "little")
    return out


def sponge(data: bytes, rate_bits: int, out_bits: int, suffix: int) -> bytes:
    """Губка: доповнення, вбирання (absorbing) та віджимання (squeezing)."""
    rate = rate_bits // 8
    # padding pad10*1 з доменним суфіксом (0x06 для SHA-3, 0x1F для SHAKE, 0x01 для Keccak)
    padded = bytearray(data)
    padded.append(suffix)
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80

    state = [[0] * 5 for _ in range(5)]
    for i in range(0, len(padded), rate):
        state = _absorb_block(state, bytes(padded[i: i + rate]))

    out = b""
    out_len = out_bits // 8
    while True:
        out += _state_bytes(state, rate)
        if len(out) >= out_len:
            return out[:out_len]
        state = keccak_f(state)


def sha3_224(data: bytes) -> str:
    return sponge(data, 1152, 224, 0x06).hex()


def sha3_256(data: bytes) -> str:
    return sponge(data, 1088, 256, 0x06).hex()


def sha3_384(data: bytes) -> str:
    return sponge(data, 832, 384, 0x06).hex()


def sha3_512(data: bytes) -> str:
    return sponge(data, 576, 512, 0x06).hex()


def shake128(data: bytes, out_bytes: int) -> str:
    return sponge(data, 1344, out_bytes * 8, 0x1F).hex()


def shake256(data: bytes, out_bytes: int) -> str:
    return sponge(data, 1088, out_bytes * 8, 0x1F).hex()


def keccak256(data: bytes) -> str:
    """Оригінальний Keccak-256 (до стандартизації, використовується в Ethereum)."""
    return sponge(data, 1088, 256, 0x01).hex()
