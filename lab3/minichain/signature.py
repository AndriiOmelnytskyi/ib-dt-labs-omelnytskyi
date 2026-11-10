"""ECDSA на кривій secp256k1 (як у Bitcoin): класи KeyPair та Signature.

Арифметику еліптичної кривої реалізовано власноруч (додавання, подвоєння,
скалярне множення "double-and-add"). Випадкове число k формується
детерміновано за RFC 6979, що виключає витік ключа через повторне k.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

# Параметри кривої secp256k1: y^2 = x^3 + 7 (mod p)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A, B = 0, 7
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
INF = None  # нескінченно віддалена точка (нейтральний елемент групи)


def is_on_curve(pt) -> bool:
    if pt is INF:
        return True
    x, y = pt
    return (y * y - x * x * x - A * x - B) % P == 0


def point_add(p1, p2):
    if p1 is INF:
        return p2
    if p2 is INF:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return INF                                   # P + (-P) = O
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P   # подвоєння
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P          # додавання
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k: int, pt=G):
    """Скалярне множення k*P методом "подвоєння та додавання"."""
    result, addend = INF, pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def encode_point(pt) -> str:
    """Стиснене подання відкритого ключа (33 байти, hex)."""
    x, y = pt
    return ("02" if y % 2 == 0 else "03") + f"{x:064x}"


def decode_point(s: str):
    prefix, x = s[:2], int(s[2:], 16)
    y2 = (pow(x, 3, P) + A * x + B) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y % 2 == 0) != (prefix == "02"):
        y = P - y
    pt = (x, y)
    if not is_on_curve(pt):
        raise ValueError("Точка не належить кривій")
    return pt


def _hash_int(message: str) -> int:
    return int.from_bytes(hashlib.sha256(message.encode("utf-8")).digest(), "big")


def _rfc6979_k(priv: int, h: int) -> int:
    x = priv.to_bytes(32, "big")
    hb = (h % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


class KeyPair:
    """Ключова пара: особистий ключ (число) та відкритий ключ (точка кривої)."""

    def __init__(self, private_key: int):
        if not 1 <= private_key < N:
            raise ValueError("Особистий ключ поза межами [1, n-1]")
        self.__privateKey = private_key           # доступ лише всередині класу
        self.publicKey = scalar_mult(private_key)  # Q = d x G

    @classmethod
    def genKeyPair(cls) -> "KeyPair":
        return cls(secrets.randbelow(N - 1) + 1)

    @property
    def publicKeyHex(self) -> str:
        return encode_point(self.publicKey)

    def sign(self, message: str) -> str:
        """Підпис виконується без видачі особистого ключа назовні."""
        return Signature.signData(self.__privateKey, message)

    def toString(self) -> str:
        return f"KeyPair(publicKey={self.publicKeyHex})"

    def printKeyPair(self) -> None:
        print(self.toString())

    __str__ = toString


class Signature:
    @staticmethod
    def signData(private_key: int, message: str) -> str:
        """ECDSA-підпис. Повертає r||s (64 байти) у hex."""
        z = _hash_int(message)
        while True:
            k = _rfc6979_k(private_key, z)
            x1, _ = scalar_mult(k)
            r = x1 % N
            if r == 0:
                continue
            s = pow(k, -1, N) * (z + r * private_key) % N
            if s == 0:
                continue
            if s > N // 2:          # нормалізація low-s (захист від пластичності підпису)
                s = N - s
            return f"{r:064x}{s:064x}"

    @staticmethod
    def verifySignature(signature: str, public_key_hex: str, message: str) -> bool:
        try:
            r, s = int(signature[:64], 16), int(signature[64:], 16)
            q = decode_point(public_key_hex)
        except (ValueError, IndexError):
            return False
        if len(signature) != 128 or not (1 <= r < N and 1 <= s < N) or s > N // 2:
            return False
        z = _hash_int(message)
        c = pow(s, -1, N)
        u1, u2 = z * c % N, r * c % N
        pt = point_add(scalar_mult(u1), scalar_mult(u2, q))
        if pt is INF:
            return False
        return pt[0] % N == r

    @staticmethod
    def toString(signature: str) -> str:
        return f"Signature(r={signature[:16]}..., s={signature[64:80]}...)"

    @staticmethod
    def printSignature(signature: str) -> None:
        print(Signature.toString(signature))
