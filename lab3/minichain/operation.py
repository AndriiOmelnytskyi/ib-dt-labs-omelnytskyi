"""Класи Operation (платіж) та Transaction (набір платежів)."""

from __future__ import annotations

import secrets

from .hash import Hash
from .signature import Signature


class Operation:
    def __init__(self, sender, receiver, amount: int, signature: str,
                 public_key: str, op_nonce: int):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.signature = signature
        self.publicKey = public_key   # яким ключем з гаманця підписано
        self.opNonce = op_nonce       # унікальність операції (захист від повтору)

    @staticmethod
    def payload(sender_id: str, receiver_id: str, amount: int, op_nonce: int) -> str:
        """Дані, що підписуються відправником."""
        return f"PAY|{sender_id}|{receiver_id}|{amount}|{op_nonce}"

    @classmethod
    def createOperation(cls, sender, receiver, amount: int, key_index: int = 0,
                        signature: str | None = None, op_nonce: int | None = None) -> "Operation":
        op_nonce = secrets.randbits(64) if op_nonce is None else op_nonce
        msg = cls.payload(sender.accountID, receiver.accountID, amount, op_nonce)
        if signature is None:
            signature = sender.signData(msg, key_index)
        return cls(sender, receiver, amount, signature,
                   sender.wallet[key_index].publicKeyHex, op_nonce)

    @property
    def message(self) -> str:
        return self.payload(self.sender.accountID, self.receiver.accountID,
                            self.amount, self.opNonce)

    @property
    def operationID(self) -> str:
        # ідентифікатор не залежить від підпису, тому повтор операції з іншим
        # (пластичним) підписом все одно буде виявлено
        return Hash.toSHA256(self.message)

    def verifyOperation(self, sender_balance: int,
                        sender_keys: list[str] | None = None) -> tuple[bool, str]:
        """sender_keys: відкриті ключі відправника з реєстру блокчейну. Якщо не задано,
        використовується гаманець з об'єкта відправника (лише для локальної перевірки)."""
        keys = self.sender.publicKeys() if sender_keys is None else sender_keys
        if not isinstance(self.amount, int) or self.amount <= 0:
            return False, "сума переказу має бути додатним цілим числом"
        if self.sender.accountID == self.receiver.accountID:
            return False, "переказ самому собі заборонено"
        if self.amount > sender_balance:
            return False, f"недостатньо коштів ({self.amount} > {sender_balance})"
        if self.publicKey not in keys:
            return False, "ключ підпису не належить гаманцю відправника"
        if not Signature.verifySignature(self.signature, self.publicKey, self.message):
            return False, "некоректний цифровий підпис"
        return True, "OK"

    def toString(self) -> str:
        return (f"Operation({self.sender.name} -> {self.receiver.name}, "
                f"amount={self.amount}, sig={self.signature[:12]}...)")

    def printOperation(self) -> None:
        print(self.toString())

    __str__ = toString


class Transaction:
    def __init__(self, operations: list[Operation], nonce: int):
        self.setOfOperations = list(operations)
        self.nonce = nonce
        self.transactionID = self.computeID()

    def computeID(self) -> str:
        data = "|".join(op.operationID + op.signature for op in self.setOfOperations)
        return Hash.toSHA256(f"{data}|{self.nonce}")

    @classmethod
    def createTransaction(cls, operations: list[Operation], nonce: int | None = None) -> "Transaction":
        return cls(operations, secrets.randbits(32) if nonce is None else nonce)

    def toString(self) -> str:
        ops = "; ".join(op.toString() for op in self.setOfOperations)
        return f"Transaction(id={self.transactionID[:16]}..., nonce={self.nonce}, ops=[{ops}])"

    def printTransaction(self) -> None:
        print(self.toString())

    __str__ = toString
