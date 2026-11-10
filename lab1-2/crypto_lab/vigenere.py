"""Шифр Віженера (базовий рівень): C_i = (P_i + K_j) mod 26.

Літери поза латинським алфавітом не шифруються і не зсувають ключ
(так само працює сервіс cryptii.com у режимі за замовчуванням).
"""

from __future__ import annotations

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _shift(text: str, key: str, sign: int) -> str:
    key = [ALPHABET.index(k) for k in key.upper() if k.upper() in ALPHABET]
    if not key:
        raise ValueError("Ключ має містити хоча б одну латинську літеру")
    out, j = [], 0
    for ch in text:
        up = ch.upper()
        if up in ALPHABET:
            c = ALPHABET[(ALPHABET.index(up) + sign * key[j % len(key)]) % 26]
            out.append(c if ch.isupper() else c.lower())
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def encrypt(plaintext: str, key: str) -> str:
    return _shift(plaintext, key, +1)


def decrypt(ciphertext: str, key: str) -> str:
    return _shift(ciphertext, key, -1)
