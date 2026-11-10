"""Клас Block: блок з транзакціями, пов'язаний з попереднім через prevHash."""

from __future__ import annotations

import time

from .hash import Hash
from .operation import Transaction


def merkle_root(tx_ids: list[str]) -> str:
    """Корінь дерева Меркла над ідентифікаторами транзакцій."""
    if not tx_ids:
        return Hash.toSHA256("")
    level = list(tx_ids)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [Hash.toSHA256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


class Block:
    def __init__(self, transactions: list[Transaction], prev_hash: str, height: int,
                 timestamp: float | None = None, pow_nonce: int = 0):
        self.setOfTransactions = list(transactions)
        self.prevHash = prev_hash
        self.height = height
        self.timestamp = round(time.time(), 3) if timestamp is None else timestamp
        self.merkleRoot = merkle_root([t.transactionID for t in self.setOfTransactions])
        self.powNonce = pow_nonce
        self.blockID = self.computeID()

    def header(self) -> str:
        return f"{self.prevHash}|{self.height}|{self.timestamp}|{self.merkleRoot}|{self.powNonce}"

    def computeID(self) -> str:
        return Hash.toSHA256(self.header())

    @classmethod
    def createBlock(cls, transactions: list[Transaction], prev_hash: str, height: int) -> "Block":
        return cls(transactions, prev_hash, height)

    def mine(self, difficulty: int) -> int:
        """Спрощений Proof-of-Work: blockID має починатися з difficulty нулів (hex).
        Повертає кількість перебраних варіантів."""
        tries = 0
        self.blockID = self.computeID()
        while not self.blockID.startswith("0" * difficulty):
            self.powNonce += 1
            tries += 1
            self.blockID = self.computeID()
        return tries

    def toString(self) -> str:
        return (f"Block #{self.height} id={self.blockID[:16]}... prev={self.prevHash[:16]}... "
                f"txs={len(self.setOfTransactions)} merkle={self.merkleRoot[:12]}...")

    def printBlock(self) -> None:
        print(self.toString())

    __str__ = toString
