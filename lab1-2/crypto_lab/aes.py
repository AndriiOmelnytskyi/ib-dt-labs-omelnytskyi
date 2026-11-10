"""Реалізація блочного шифру AES (FIPS-197) з нуля.

Підтримуються ключі 128, 192 та 256 біт, режими ECB та CBC
з доповненням PKCS#7. Стан (state) зберігається як матриця 4x4 байти
у порядку "по стовпцях", як це визначено у стандарті.
"""

from __future__ import annotations

import os

SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# Обернена таблиця підстановки будується з прямої
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

# Раундові константи Rcon (перший байт слова), x^(i-1) у полі GF(2^8)
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

NB = 4  # кількість стовпців стану (слів) у блоці
BLOCK_SIZE = 16


def xtime(a: int) -> int:
    """Множення на x (тобто на 0x02) у полі GF(2^8) за модулем x^8+x^4+x^3+x+1."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def gmul(a: int, b: int) -> int:
    """Множення двох байтів у полі GF(2^8) (алгоритм "російського селянина")."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


# Попередньо обчислені таблиці множення для MixColumns / InvMixColumns
MUL2 = [gmul(i, 2) for i in range(256)]
MUL3 = [gmul(i, 3) for i in range(256)]
MUL9 = [gmul(i, 9) for i in range(256)]
MUL11 = [gmul(i, 11) for i in range(256)]
MUL13 = [gmul(i, 13) for i in range(256)]
MUL14 = [gmul(i, 14) for i in range(256)]


# ---------------------------------------------------------------- розгортання ключа

def sub_word(word: list[int]) -> list[int]:
    return [SBOX[b] for b in word]


def rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def key_expansion(key: bytes) -> list[list[int]]:
    """KeyExpansion (GetRoundKeys у методичних вказівках).

    Повертає список слів w[0 .. Nb*(Nr+1)-1], кожне слово це 4 байти.
    """
    nk = len(key) // 4
    if len(key) not in (16, 24, 32):
        raise ValueError("Довжина ключа AES має бути 16, 24 або 32 байти")
    nr = nk + 6
    w = [list(key[4 * i: 4 * i + 4]) for i in range(nk)]
    for i in range(nk, NB * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return w


# ---------------------------------------------------------------- перетворення раунду
# Стан зберігається як плоский список з 16 байтів: state[r + 4*c]

def add_round_key(state: list[int], w: list[list[int]], rnd: int) -> None:
    for c in range(4):
        word = w[rnd * NB + c]
        for r in range(4):
            state[r + 4 * c] ^= word[r]


def sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = SBOX[state[i]]


def inv_sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = INV_SBOX[state[i]]


def shift_rows(state: list[int]) -> None:
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        row = row[r:] + row[:r]  # циклічний зсув вліво на r байтів
        for c in range(4):
            state[r + 4 * c] = row[c]


def inv_shift_rows(state: list[int]) -> None:
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        row = row[-r:] + row[:-r]  # циклічний зсув вправо на r байтів
        for c in range(4):
            state[r + 4 * c] = row[c]


def mix_columns(state: list[int]) -> None:
    for c in range(4):
        a0, a1, a2, a3 = state[4 * c: 4 * c + 4]
        state[4 * c + 0] = MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3
        state[4 * c + 1] = a0 ^ MUL2[a1] ^ MUL3[a2] ^ a3
        state[4 * c + 2] = a0 ^ a1 ^ MUL2[a2] ^ MUL3[a3]
        state[4 * c + 3] = MUL3[a0] ^ a1 ^ a2 ^ MUL2[a3]


def inv_mix_columns(state: list[int]) -> None:
    for c in range(4):
        a0, a1, a2, a3 = state[4 * c: 4 * c + 4]
        state[4 * c + 0] = MUL14[a0] ^ MUL11[a1] ^ MUL13[a2] ^ MUL9[a3]
        state[4 * c + 1] = MUL9[a0] ^ MUL14[a1] ^ MUL11[a2] ^ MUL13[a3]
        state[4 * c + 2] = MUL13[a0] ^ MUL9[a1] ^ MUL14[a2] ^ MUL11[a3]
        state[4 * c + 3] = MUL11[a0] ^ MUL13[a1] ^ MUL9[a2] ^ MUL14[a3]


# ---------------------------------------------------------------- клас шифру

class AES:
    """Блочний шифр AES. Один об'єкт відповідає одному ключу."""

    def __init__(self, key: bytes):
        self.key = bytes(key)
        self.nk = len(self.key) // 4
        self.nr = self.nk + 6  # 10, 12 або 14 раундів
        self.round_keys = key_expansion(self.key)

    # --- один блок -------------------------------------------------------
    def encrypt_block(self, block: bytes, trace: list | None = None) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("Блок AES має містити 16 байтів")
        state = list(block)
        add_round_key(state, self.round_keys, 0)
        if trace is not None:
            trace.append(("round 0", bytes(state)))
        for rnd in range(1, self.nr):
            sub_bytes(state)
            shift_rows(state)
            mix_columns(state)
            add_round_key(state, self.round_keys, rnd)
            if trace is not None:
                trace.append((f"round {rnd}", bytes(state)))
        sub_bytes(state)
        shift_rows(state)
        add_round_key(state, self.round_keys, self.nr)
        if trace is not None:
            trace.append((f"round {self.nr}", bytes(state)))
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("Блок AES має містити 16 байтів")
        state = list(block)
        add_round_key(state, self.round_keys, self.nr)
        for rnd in range(self.nr - 1, 0, -1):
            inv_shift_rows(state)
            inv_sub_bytes(state)
            add_round_key(state, self.round_keys, rnd)
            inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, self.round_keys, 0)
        return bytes(state)

    # --- режими роботи ---------------------------------------------------
    def encrypt_ecb(self, data: bytes, pad: bool = True) -> bytes:
        if pad:
            data = pkcs7_pad(data)
        return b"".join(self.encrypt_block(b) for b in split_blocks(data))

    def decrypt_ecb(self, data: bytes, pad: bool = True) -> bytes:
        out = b"".join(self.decrypt_block(b) for b in split_blocks(data))
        return pkcs7_unpad(out) if pad else out

    def encrypt_cbc(self, data: bytes, iv: bytes, pad: bool = True) -> bytes:
        if len(iv) != BLOCK_SIZE:
            raise ValueError("IV має містити 16 байтів")
        if pad:
            data = pkcs7_pad(data)
        prev = iv
        out = []
        for block in split_blocks(data):
            prev = self.encrypt_block(xor_bytes(block, prev))
            out.append(prev)
        return b"".join(out)

    def decrypt_cbc(self, data: bytes, iv: bytes, pad: bool = True) -> bytes:
        prev = iv
        out = []
        for block in split_blocks(data):
            out.append(xor_bytes(self.decrypt_block(block), prev))
            prev = block
        res = b"".join(out)
        return pkcs7_unpad(res) if pad else res


# ---------------------------------------------------------------- допоміжні функції

def split_blocks(data: bytes) -> list[bytes]:
    """DivideIntoBlocks: поділ даних на блоки по 128 біт."""
    if len(data) % BLOCK_SIZE:
        raise ValueError("Довжина даних не кратна 16 байтам")
    return [data[i: i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def pkcs7_pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("Некоректна довжина даних")
    n = data[-1]
    if n < 1 or n > BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("Некоректне доповнення PKCS#7")
    return data[:-n]


def state_to_matrix(block: bytes) -> list[list[int]]:
    """Подання 16 байтів як матриці стану 4x4 (рядки r, стовпці c)."""
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def generate_key(bits: int = 128) -> bytes:
    return os.urandom(bits // 8)
