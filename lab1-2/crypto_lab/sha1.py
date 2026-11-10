"""Реалізація геш-функції SHA-1 (FIPS 180-4) з нуля.

Інтерфейс подібний до hashlib: update(), digest(), hexdigest().
"""

from __future__ import annotations

import struct

MASK32 = 0xFFFFFFFF
H_INIT = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
K = (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6)


def rotl(x: int, n: int) -> int:
    """Циклічний зсув 32-бітного слова вліво на n біт."""
    return ((x << n) | (x >> (32 - n))) & MASK32


def f_t(t: int, b: int, c: int, d: int) -> int:
    """Логічна функція f, що змінюється кожні 20 кроків."""
    if t < 20:
        return (b & c) | (~b & d)          # Ch
    if t < 40:
        return b ^ c ^ d                   # Parity
    if t < 60:
        return (b & c) | (b & d) | (c & d)  # Maj
    return b ^ c ^ d                       # Parity


def compress(h: tuple, chunk: bytes) -> tuple:
    """Функція стиснення: обробка одного 512-бітного блоку."""
    w = list(struct.unpack(">16I", chunk))
    for i in range(16, 80):
        w.append(rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
    a, b, c, d, e = h
    for t in range(80):
        temp = (rotl(a, 5) + f_t(t, b, c, d) + e + K[t // 20] + w[t]) & MASK32
        e = d
        d = c
        c = rotl(b, 30)
        b = a
        a = temp
    return tuple((x + y) & MASK32 for x, y in zip(h, (a, b, c, d, e)))


def pad_message(length_bytes: int) -> bytes:
    """Доповнення: біт 1, нулі до 448 mod 512, довжина у бітах (64 біти, big-endian)."""
    ml = length_bytes * 8
    padding = b"\x80" + b"\x00" * ((55 - length_bytes) % 64)
    return padding + struct.pack(">Q", ml)


class SHA1:
    name = "sha1"
    digest_size = 20
    block_size = 64

    def __init__(self, data: bytes = b""):
        self._h = H_INIT
        self._buffer = b""
        self._length = 0
        if data:
            self.update(data)

    def update(self, data: bytes) -> "SHA1":
        self._length += len(data)
        data = self._buffer + data
        full = len(data) - len(data) % 64
        for i in range(0, full, 64):
            self._h = compress(self._h, data[i: i + 64])
        self._buffer = data[full:]
        return self

    def digest(self) -> bytes:
        tail = self._buffer + pad_message(self._length)
        h = self._h
        for i in range(0, len(tail), 64):
            h = compress(h, tail[i: i + 64])
        return struct.pack(">5I", *h)

    def hexdigest(self) -> str:
        return self.digest().hex()


def sha1(data: bytes) -> str:
    """Зручна функція: повертає геш у вигляді hex-рядка."""
    return SHA1(data).hexdigest()
