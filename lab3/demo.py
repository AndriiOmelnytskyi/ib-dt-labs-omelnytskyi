"""Демонстраційний сценарій UniCoin: нормальна робота та спроби атак.

Запуск:  python demo.py
"""

import time

from minichain import Account, Block, Blockchain, Operation, Signature, Transaction


def title(text):
    print(f"\n--- {text} ---")


def submit(chain, label, ops=None, block=None):
    if block is None:
        block = chain.createBlock([Transaction.createTransaction(ops)])
    ok, reason = chain.validateBlock(block)
    print(f"[{'ПРИЙНЯТО' if ok else 'ВІДХИЛЕНО'}] {label}: {reason}")
    return ok


def balances(chain):
    return ", ".join(f"{chain.accounts[a].name}={v}" for a, v in chain.coinDatabase.items())


def main():
    title("1. Ініціалізація блокчейну та облікових записів")
    chain = Blockchain.initBlockchain(faucet_coins=10_000, faucet_limit=500, difficulty=3)
    print("Генезис-блок:", chain.lastBlock.toString())
    student = Account.genAccount("Student")
    student2 = Account.genAccount("Student2")
    canteen = Account.genAccount("Canteen")
    library = Account.genAccount("Library")
    for acc in (student, student2, canteen, library):
        acc.print()
    print("Відкритий ключ Student:", student.wallet[0].publicKeyHex)

    title("2. Нарахування токенів (faucet)")
    chain.getTokenFromFaucet(student, 300)
    chain.getTokenFromFaucet(student2, 150)
    chain.registerAccount(canteen)
    chain.registerAccount(library)
    print("Баланси:", balances(chain), "| у крані:", chain.faucetCoins)

    title("3. Підпис операції")
    op = student.createPaymentOp(canteen, 45)
    print("Дані для підпису:", op.message)
    print(Signature.toString(op.signature))
    print("Перевірка підпису:", Signature.verifySignature(op.signature, op.publicKey, op.message))

    title("4. Коректні блоки")
    t0 = time.perf_counter()
    submit(chain, "Student -> Canteen 45, Student2 -> Library 20",
           [op, student2.createPaymentOp(library, 20)])
    student.addKeyPairToWallet()
    submit(chain, "Student -> Student2 30 (другий ключ гаманця)",
           [student.createPaymentOp(student2, 30, key_index=1)])
    print(f"Середній час формування блоку з PoW (difficulty=3): {(time.perf_counter() - t0) / 2:.2f} c")
    print("Баланси:", balances(chain))

    title("5. Спроби атак")
    submit(chain, "Витрата більше, ніж є на балансі", [student2.createPaymentOp(canteen, 1000)])
    submit(chain, "Конфліктні операції у блоці (2 x 150 при балансі 225)",
           [student.createPaymentOp(canteen, 150), student.createPaymentOp(library, 150)])
    msg = Operation.payload(student.accountID, student2.accountID, 50, 7)
    forged = Operation(student, student2, 50, student2.signData(msg), student2.wallet[0].publicKeyHex, 7)
    submit(chain, "Student2 підписує витрату з рахунку Student своїм ключем", [forged])
    fake = Account.genAccount("Fake")
    fake.accountID = student.accountID
    submit(chain, "Підроблений об'єкт облікового запису з чужим accountID",
           [fake.createPaymentOp(student2, 10)])
    tampered = student.createPaymentOp(student2, 5)
    tampered.amount = 200
    submit(chain, "Зміна суми після підпису", [tampered])
    submit(chain, "Повтор вже підтвердженої операції в новій транзакції", [op])
    old_tx = chain.blockHistory[1].setOfTransactions[0]
    submit(chain, "Повторне додавання існуючої транзакції", block=chain.createBlock([old_tx]))
    wrong = Block.createBlock([Transaction.createTransaction([student.createPaymentOp(library, 1)])],
                              chain.blockHistory[0].blockID, 1)
    wrong.mine(3)
    submit(chain, "Блок посилається не на останній блок", block=wrong)
    no_pow = Block.createBlock([Transaction.createTransaction([student.createPaymentOp(library, 1)])],
                               chain.lastBlock.blockID, len(chain.blockHistory))
    submit(chain, "Блок без Proof-of-Work", block=no_pow)
    print("Баланси після атак:", balances(chain))

    title("6. Аудит історії")
    print("verifyChain():", chain.verifyChain())
    chain.blockHistory[1].setOfTransactions[0].setOfOperations[0].amount = 1
    print("Після зміни суми в блоці #1:", chain.verifyChain())
    chain.blockHistory[1].setOfTransactions[0].setOfOperations[0].amount = 45
    print("Після відновлення:", chain.verifyChain())
    # Зловмисник перераховує ID транзакції, корінь Меркла та blockID блоку #1
    b1 = chain.blockHistory[1]
    saved = (b1.setOfTransactions[0].nonce, b1.setOfTransactions[0].transactionID,
             b1.merkleRoot, b1.powNonce, b1.blockID)
    tx = b1.setOfTransactions[0]
    tx.nonce += 1
    tx.transactionID = tx.computeID()
    from minichain import merkle_root
    b1.merkleRoot = merkle_root([t.transactionID for t in b1.setOfTransactions])
    b1.powNonce = 0
    b1.mine(3)
    print("Блок #1 переписано з перерахунком гешів і PoW:", chain.verifyChain())
    tx.nonce, tx.transactionID, b1.merkleRoot, b1.powNonce, b1.blockID = saved

    title("7. Стан блокчейну")
    chain.printBlockchain()


if __name__ == "__main__":
    main()
