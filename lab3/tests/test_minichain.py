import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from minichain import Account, Block, Blockchain, KeyPair, Operation, Signature, Transaction  # noqa: E402
from minichain.signature import G, N, is_on_curve, scalar_mult  # noqa: E402


# ------------------------------------------------------------------ ECDSA

def test_generator_on_curve_and_order():
    assert is_on_curve(G)
    assert scalar_mult(N) is None          # n*G = O


def test_known_public_key():
    # відомий вектор: d = 1 -> Q = G; d = 2 -> 2G
    assert KeyPair(1).publicKey == G
    assert KeyPair(2).publicKey[0] == 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5


def test_sign_verify_and_tamper():
    kp = KeyPair.genKeyPair()
    sig = kp.sign("hello")
    assert Signature.verifySignature(sig, kp.publicKeyHex, "hello")
    assert not Signature.verifySignature(sig, kp.publicKeyHex, "hello!")
    other = KeyPair.genKeyPair()
    assert not Signature.verifySignature(sig, other.publicKeyHex, "hello")


def test_signature_compatible_with_cryptography_library():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    for _ in range(5):
        kp = KeyPair.genKeyPair()
        x, y = kp.publicKey
        pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1()).public_key()
        sig = kp.sign("message for lab 3")
        der = encode_dss_signature(int(sig[:64], 16), int(sig[64:], 16))
        pub.verify(der, b"message for lab 3", ec.ECDSA(hashes.SHA256()))  # кидає виняток при помилці


def test_private_key_is_hidden():
    kp = KeyPair.genKeyPair()
    assert not hasattr(kp, "privateKey")


# ------------------------------------------------------------------ сценарії блокчейну

@pytest.fixture
def setup():
    chain = Blockchain.initBlockchain(faucet_coins=1000, faucet_limit=500)
    alice, bob, shop = Account.genAccount("Alice"), Account.genAccount("Bob"), Account.genAccount("Shop")
    chain.getTokenFromFaucet(alice, 100)
    chain.getTokenFromFaucet(bob, 50)
    chain.registerAccount(shop)
    return chain, alice, bob, shop


def add(chain, *ops):
    return chain.validateBlock(chain.createBlock([Transaction.createTransaction(list(ops))]))


def test_genesis_and_faucet(setup):
    chain, alice, bob, _ = setup
    assert len(chain.blockHistory) == 1
    assert chain.faucetCoins == 850
    assert alice.getBalance() == 100 and bob.getBalance() == 50
    with pytest.raises(ValueError):
        chain.getTokenFromFaucet(alice, 501)


def test_valid_payment(setup):
    chain, alice, bob, shop = setup
    ok, _ = add(chain, alice.createPaymentOp(shop, 30), bob.createPaymentOp(shop, 20))
    assert ok
    assert chain.coinDatabase[alice.accountID] == 70
    assert chain.coinDatabase[shop.accountID] == 50
    assert shop.getBalance() == 50
    assert chain.verifyChain()[0]


def test_overspend_rejected(setup):
    chain, alice, _, shop = setup
    ok, reason = add(chain, alice.createPaymentOp(shop, 101))
    assert not ok and "недостатньо" in reason


def test_conflicting_ops_in_block_rejected(setup):
    chain, alice, bob, shop = setup
    ok, reason = add(chain, alice.createPaymentOp(shop, 60), alice.createPaymentOp(bob, 60))
    assert not ok and "недостатньо" in reason
    assert chain.coinDatabase[alice.accountID] == 100      # стан не змінився


def test_forged_signature_rejected(setup):
    chain, alice, bob, _ = setup
    # Боб намагається витратити монети Аліси, підписавши своїм ключем
    msg = Operation.payload(alice.accountID, bob.accountID, 10, 1)
    forged = Operation(alice, bob, 10, bob.signData(msg), bob.wallet[0].publicKeyHex, 1)
    ok, reason = add(chain, forged)
    assert not ok and "ключ" in reason


def test_fake_account_object_rejected(setup):
    chain, alice, bob, _ = setup
    fake = Account.genAccount("Fake")
    fake.accountID = alice.accountID                 # підміна ідентифікатора
    ok, reason = add(chain, fake.createPaymentOp(bob, 10))
    assert not ok and "ключ" in reason


def test_tampered_amount_rejected(setup):
    chain, alice, bob, _ = setup
    op = alice.createPaymentOp(bob, 5)
    op.amount = 50                                   # зміна суми після підпису
    ok, reason = add(chain, op)
    assert not ok and "підпис" in reason


def test_second_key_in_wallet(setup):
    chain, alice, bob, _ = setup
    alice.addKeyPairToWallet()
    ok, _ = add(chain, alice.createPaymentOp(bob, 10, key_index=1))
    assert ok


def test_replay_operation_rejected(setup):
    chain, alice, bob, _ = setup
    op = alice.createPaymentOp(bob, 10)
    assert add(chain, op)[0]
    ok, reason = add(chain, op)                       # та сама операція в новій транзакції
    assert not ok and "повтор" in reason


def test_duplicate_transaction_rejected(setup):
    chain, alice, bob, _ = setup
    tx = Transaction.createTransaction([alice.createPaymentOp(bob, 10)])
    assert chain.validateBlock(chain.createBlock([tx]))[0]
    ok, reason = chain.validateBlock(chain.createBlock([tx]))
    assert not ok and "вже додано" in reason


def test_wrong_prev_hash_rejected(setup):
    chain, alice, bob, _ = setup
    tx = Transaction.createTransaction([alice.createPaymentOp(bob, 10)])
    block = Block.createBlock([tx], "f" * 64, 1)
    ok, reason = chain.validateBlock(block)
    assert not ok and "останній блок" in reason


def test_history_tampering_detected(setup):
    chain, alice, bob, shop = setup
    assert add(chain, alice.createPaymentOp(bob, 10))[0]
    assert add(chain, bob.createPaymentOp(shop, 5))[0]
    assert chain.verifyChain()[0]
    chain.blockHistory[1].setOfTransactions[0].setOfOperations[0].amount = 1
    ok, reason = chain.verifyChain()
    assert not ok and "#1" in reason


def test_pow_difficulty():
    chain = Blockchain.initBlockchain(difficulty=3)
    a, b = Account.genAccount("A"), Account.genAccount("B")
    chain.getTokenFromFaucet(a, 10)
    chain.registerAccount(b)
    block = chain.createBlock([Transaction.createTransaction([a.createPaymentOp(b, 1)])])
    assert block.blockID.startswith("000")
    assert chain.validateBlock(block)[0]
