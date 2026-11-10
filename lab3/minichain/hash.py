"""Клас-обгортка Hash для геш-функцій."""

import hashlib


class Hash:
    @staticmethod
    def toSHA1(data: str) -> str:
        """Геш SHA-1 (160 біт) від рядка, результат у вигляді hex-рядка.

        Використовується для формування коротких ідентифікаторів облікових записів.
        """
        return hashlib.sha1(data.encode("utf-8")).hexdigest()

    @staticmethod
    def toSHA256(data: str) -> str:
        """Геш SHA-256 від рядка. Використовується для transactionID та blockID,
        оскільки для SHA-1 вже знайдено практичні колізії (SHAttered, 2017)."""
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def sha256_bytes(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()
