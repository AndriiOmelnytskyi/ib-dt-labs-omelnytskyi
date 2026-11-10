"""Клас Account: обліковий запис (гаманець) учасника системи."""

from __future__ import annotations

from .hash import Hash
from .signature import KeyPair


class Account:
    def __init__(self, name: str = ""):
        self.name = name
        self.wallet: list[KeyPair] = []
        self.balance = 0
        self.accountID = ""

    @classmethod
    def genAccount(cls, name: str = "") -> "Account":
        """Створює обліковий запис з першою ключовою парою.
        accountID = SHA-1(відкритий ключ першої пари), аналогічно до адрес у Bitcoin."""
        acc = cls(name)
        first = KeyPair.genKeyPair()
        acc.wallet.append(first)
        acc.accountID = Hash.toSHA1(first.publicKeyHex)
        return acc

    def addKeyPairToWallet(self, key_pair: KeyPair | None = None) -> None:
        self.wallet.append(key_pair or KeyPair.genKeyPair())

    def updateBalance(self, value: int) -> None:
        """Встановлює баланс. Викликається лише блокчейном після прийняття блоку,
        тому довільна зміна балансу на боці клієнта не впливає на coinDatabase."""
        if value < 0:
            raise ValueError("Баланс не може бути від'ємним")
        self.balance = value

    def createPaymentOp(self, receiver: "Account", amount: int, key_index: int = 0):
        from .operation import Operation
        return Operation.createOperation(self, receiver, amount, key_index)

    def getBalance(self) -> int:
        return self.balance

    def printBalance(self) -> None:
        print(f"{self.name or self.accountID[:10]}: {self.balance}")

    def signData(self, message: str, key_index: int = 0) -> str:
        if not 0 <= key_index < len(self.wallet):
            raise IndexError("Немає ключа з таким індексом у гаманці")
        return self.wallet[key_index].sign(message)

    def publicKeys(self) -> list[str]:
        return [kp.publicKeyHex for kp in self.wallet]

    def toString(self) -> str:
        return (f"Account(name={self.name}, id={self.accountID}, "
                f"keys={len(self.wallet)}, balance={self.balance})")

    def print(self) -> None:
        print(self.toString())

    __str__ = toString
