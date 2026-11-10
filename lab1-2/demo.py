"""Демонстрація роботи реалізованих алгоритмів.

Запуск:  python demo.py [aes|hash|avalanche|bench|vigenere|all]
"""

import hashlib
import os
import sys
import time

from crypto_lab import AES, sha1, sha3_256, keccak256, vigenere
from crypto_lab.aes import state_to_matrix


def show_matrix(block: bytes) -> str:
    return "\n".join("    " + " ".join(f"{b:02x}" for b in row) for row in state_to_matrix(block))


def demo_aes():
    print("=== AES-128, приклад FIPS-197 (Appendix B) ===")
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    cipher = AES(key)
    print("Ключ:          ", key.hex())
    print("Відкритий блок:", pt.hex())
    print("Стан (state) 4x4:")
    print(show_matrix(pt))
    trace = []
    ct = cipher.encrypt_block(pt, trace)
    for name, st in trace:
        print(f"  {name:>8}: {st.hex()}")
    print("Шифртекст:     ", ct.hex())
    print("Розшифровано:  ", cipher.decrypt_block(ct).hex())
    print("Раундових ключів:", cipher.nr + 1, " останній:",
          b"".join(bytes(w) for w in cipher.round_keys[-4:]).hex())

    print("\n=== AES-256-CBC + PKCS#7, довільний текст ===")
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    msg = "Інформаційна безпека та децентралізовані технології".encode()
    c = AES(key)
    ct = c.encrypt_cbc(msg, iv)
    print("Повідомлення:", msg.decode())
    print("Довжина:", len(msg), "байт ->", len(ct), "байт шифртексту")
    print("Шифртекст:  ", ct.hex())
    print("Розшифровано:", c.decrypt_cbc(ct, iv).decode())


def demo_hash():
    print("=== Геш-функції (власна реалізація / hashlib) ===")
    for msg in [b"", b"abc", "Блокчейн".encode()]:
        print(f"Повідомлення: \"{msg.decode()}\" ({len(msg)} байт)")
        print("  SHA-1     :", sha1(msg), "OK" if sha1(msg) == hashlib.sha1(msg).hexdigest() else "FAIL")
        s3 = sha3_256(msg)
        print("  SHA3-256  :", s3, "OK" if s3 == hashlib.sha3_256(msg).hexdigest() else "FAIL")
        print("  Keccak-256:", keccak256(msg))


def bit_diff(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def demo_avalanche():
    print("=== Лавинний ефект (зміна 1 біта вхідних даних) ===")
    m1 = b"Lab work 1-2: hash"
    m2 = bytearray(m1)
    m2[-1] ^= 0x01
    m2 = bytes(m2)
    print("M1 =", m1, "\nM2 =", m2)
    for name, fn, bits in [("SHA-1", sha1, 160), ("SHA3-256", sha3_256, 256)]:
        h1, h2 = fn(m1), fn(m2)
        d = bit_diff(h1, h2)
        print(f"{name}:\n  H(M1) = {h1}\n  H(M2) = {h2}\n  змінено бітів: {d} з {bits} ({100 * d / bits:.1f} %)")
    key = bytes(16)
    p1, p2 = bytes(16), bytes(15) + b"\x01"
    c1, c2 = AES(key).encrypt_block(p1).hex(), AES(key).encrypt_block(p2).hex()
    d = bit_diff(c1, c2)
    print(f"AES-128:\n  E(P1) = {c1}\n  E(P2) = {c2}\n  змінено бітів: {d} з 128 ({100 * d / 128:.1f} %)")

    # усереднення по 200 випадкових повідомленнях
    totals = {"SHA-1": [], "SHA3-256": [], "AES-128": []}
    for _ in range(200):
        m = bytearray(os.urandom(32))
        mm = bytearray(m)
        bit = int.from_bytes(os.urandom(1), "big") % 256
        mm[bit // 8] ^= 1 << (bit % 8)
        totals["SHA-1"].append(bit_diff(sha1(bytes(m)), sha1(bytes(mm))) / 160)
        totals["SHA3-256"].append(bit_diff(sha3_256(bytes(m)), sha3_256(bytes(mm))) / 256)
        a = AES(os.urandom(16))
        p = bytearray(os.urandom(16))
        pp = bytearray(p)
        b2 = bit % 128
        pp[b2 // 8] ^= 1 << (b2 % 8)
        totals["AES-128"].append(bit_diff(a.encrypt_block(bytes(p)).hex(),
                                          a.encrypt_block(bytes(pp)).hex()) / 128)
    print("Середня частка змінених бітів (200 випробувань):")
    for k, v in totals.items():
        print(f"  {k:9}: {100 * sum(v) / len(v):.2f} %")


def bench(fn, data, n):
    t = time.perf_counter()
    for _ in range(n):
        fn(data)
    return (time.perf_counter() - t) / n


def demo_bench():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    print("=== Порівняння швидкодії (дані 64 КіБ) ===")
    data = os.urandom(64 * 1024)
    key, iv = os.urandom(16), os.urandom(16)
    ours = AES(key)

    def lib_aes(d):
        e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return e.update(d) + e.finalize()

    rows = [
        ("AES-128-CBC", bench(lambda d: ours.encrypt_cbc(d, iv, pad=False), data, 3), bench(lib_aes, data, 50)),
        ("SHA-1", bench(sha1, data, 3), bench(lambda d: hashlib.sha1(d).digest(), data, 200)),
        ("SHA3-256", bench(sha3_256, data, 3), bench(lambda d: hashlib.sha3_256(d).digest(), data, 200)),
    ]
    print(f"{'Алгоритм':<12}{'власна, МБ/с':>14}{'бібліотека, МБ/с':>18}{'різниця, раз':>14}")
    for name, a, b in rows:
        sa, sb = 0.0625 / a, 0.0625 / b
        print(f"{name:<12}{sa:>14.3f}{sb:>18.1f}{sb / sa:>14.0f}")


def demo_vigenere():
    print("=== Шифр Віженера (базовий рівень) ===")
    for text, key in [("ATTACKATDAWN", "LEMON"), ("Hello, World!", "key")]:
        enc = vigenere.encrypt(text, key)
        print(f"P = {text!r}, K = {key!r} -> C = {enc!r} -> {vigenere.decrypt(enc, key)!r}")


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    actions = {"aes": demo_aes, "hash": demo_hash, "avalanche": demo_avalanche,
               "bench": demo_bench, "vigenere": demo_vigenere}
    for name, fn in actions.items():
        if what in (name, "all"):
            fn()
            print()
