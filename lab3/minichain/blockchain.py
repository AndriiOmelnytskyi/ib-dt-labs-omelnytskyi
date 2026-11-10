"""Клас Blockchain: історія блоків, база монет та транзакцій, валідація."""

from __future__ import annotations

from .account import Account
from .block import Block, merkle_root
from .hash import Hash
from .operation import Transaction

GENESIS_PREV = "0" * 64


class Blockchain:
    def __init__(self, faucet_coins: int = 1_000_000, faucet_limit: int = 500, difficulty: int = 0):
        self.coinDatabase: dict[str, int] = {}
        self.blockHistory: list[Block] = []
        self.txDatabase: set[str] = set()
        self.opDatabase: set[str] = set()       # використані операції (захист від повтору)
        self.faucetCoins = faucet_coins
        self.faucetLimit = faucet_limit
        self.difficulty = difficulty
        self.accounts: dict[str, Account] = {}  # реєстр відкритих ключів облікових записів

    # ------------------------------------------------------------ ініціалізація
    @classmethod
    def initBlockchain(cls, **kwargs) -> "Blockchain":
        chain = cls(**kwargs)
        genesis = Block([], GENESIS_PREV, 0, timestamp=0.0)
        if chain.difficulty:
            genesis.mine(chain.difficulty)
        chain.blockHistory.append(genesis)
        return chain

    @property
    def lastBlock(self) -> Block:
        return self.blockHistory[-1]

    def registerAccount(self, account: Account) -> None:
        """Реєстрація облікового запису та його відкритих ключів.
        Перевіряється, що accountID дійсно є гешем першого ключа гаманця."""
        if Hash.toSHA1(account.wallet[0].publicKeyHex) != account.accountID:
            raise ValueError("accountID не відповідає першому ключу гаманця")
        known = self.accounts.get(account.accountID)
        if known is not None and known is not account:
            raise ValueError("Обліковий запис з таким ID вже зареєстровано")
        self.accounts[account.accountID] = account
        self.coinDatabase.setdefault(account.accountID, 0)

    # ------------------------------------------------------------ тестові монети
    def getTokenFromFaucet(self, account: Account, amount: int) -> None:
        if amount <= 0 or amount > self.faucetLimit:
            raise ValueError(f"За один запит можна отримати від 1 до {self.faucetLimit} монет")
        if amount > self.faucetCoins:
            raise ValueError("У крані недостатньо монет")
        self.registerAccount(account)
        self.faucetCoins -= amount
        self.coinDatabase[account.accountID] += amount
        account.updateBalance(self.coinDatabase[account.accountID])

    # ------------------------------------------------------------ валідація блоку
    def validateBlock(self, block: Block) -> tuple[bool, str]:
        # 0. Цілісність самого блоку
        if block.merkleRoot != merkle_root([t.transactionID for t in block.setOfTransactions]):
            return False, "корінь Меркла не відповідає транзакціям"
        if block.blockID != block.computeID():
            return False, "blockID не відповідає вмісту блоку"
        if not block.blockID.startswith("0" * self.difficulty):
            return False, "блок не задовольняє умові Proof-of-Work"
        # 1. Посилання на останній актуальний блок
        if block.prevHash != self.lastBlock.blockID or block.height != len(self.blockHistory):
            return False, "блок не посилається на останній блок історії"
        if not block.setOfTransactions:
            return False, "блок не містить транзакцій"

        temp_balances: dict[str, int] = {}
        seen_tx, seen_ops = set(), set()
        for tx in block.setOfTransactions:
            # 2. Транзакція ще не була додана в історію
            if tx.transactionID != tx.computeID():
                return False, "transactionID не відповідає вмісту транзакції"
            if tx.transactionID in self.txDatabase:
                return False, f"транзакцію {tx.transactionID[:12]}... вже додано в історію"
            if tx.transactionID in seen_tx:
                return False, "транзакція повторюється в межах блоку"
            seen_tx.add(tx.transactionID)
            if not tx.setOfOperations:
                return False, "порожня транзакція"
            for op in tx.setOfOperations:
                op_id = op.operationID
                if op_id in self.opDatabase or op_id in seen_ops:
                    return False, "операцію вже було використано (спроба повтору)"
                seen_ops.add(op_id)
                sender = self.accounts.get(op.sender.accountID)
                if sender is None:
                    return False, "відправник не зареєстрований у системі"
                if op.receiver.accountID not in self.accounts:
                    return False, "отримувач не зареєстрований у системі"
                sid, rid = op.sender.accountID, op.receiver.accountID
                bal = temp_balances.get(sid, self.coinDatabase.get(sid, 0))
                # 4.1 підпис та 4.2 баланс; 3. конфлікти враховуються через temp_balances
                ok, reason = op.verifyOperation(bal, sender.publicKeys())
                if not ok:
                    return False, f"операція {op.sender.name}->{op.receiver.name}: {reason}"
                temp_balances[sid] = bal - op.amount
                temp_balances[rid] = temp_balances.get(rid, self.coinDatabase.get(rid, 0)) + op.amount

        # Усі перевірки пройдено: застосовуємо блок
        self.blockHistory.append(block)
        self.txDatabase.update(seen_tx)
        self.opDatabase.update(seen_ops)
        for aid, value in temp_balances.items():
            self.coinDatabase[aid] = value
            self.accounts[aid].updateBalance(value)
        return True, "блок додано до історії"

    # ------------------------------------------------------------ аудит
    def verifyChain(self) -> tuple[bool, str]:
        """Повна перевірка цілісності історії (може виконати будь-який аудитор)."""
        prev = GENESIS_PREV
        for i, block in enumerate(self.blockHistory):
            if block.merkleRoot != merkle_root([t.transactionID for t in block.setOfTransactions]):
                return False, f"блок #{i}: корінь Меркла не збігається (змінено транзакції)"
            for tx in block.setOfTransactions:
                if tx.transactionID != tx.computeID():
                    return False, f"блок #{i}: вміст транзакції змінено"
            if block.blockID != block.computeID():
                return False, f"блок #{i}: blockID не збігається із заголовком"
            if block.prevHash != prev:
                return False, f"блок #{i}: розірвано зв'язок з попереднім блоком"
            if not block.blockID.startswith("0" * self.difficulty):
                return False, f"блок #{i}: не виконано умову PoW"
            prev = block.blockID
        return True, f"історія коректна, блоків: {len(self.blockHistory)}"

    def showCoinDatabase(self) -> dict[str, int]:
        return dict(self.coinDatabase)

    def createBlock(self, transactions: list[Transaction]) -> Block:
        """Допоміжний метод для валідатора: формує блок на вершині ланцюжка."""
        block = Block.createBlock(transactions, self.lastBlock.blockID, len(self.blockHistory))
        if self.difficulty:
            block.mine(self.difficulty)
        return block

    def toString(self) -> str:
        lines = [b.toString() for b in self.blockHistory]
        lines.append("coinDatabase: " + ", ".join(
            f"{self.accounts[a].name or a[:8]}={v}" for a, v in self.coinDatabase.items()))
        lines.append(f"faucetCoins: {self.faucetCoins}")
        return "\n".join(lines)

    def printBlockchain(self) -> None:
        print(self.toString())

    __str__ = toString
