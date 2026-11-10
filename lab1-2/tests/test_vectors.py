"""Перевірка реалізацій на офіційних тестових векторах та на еталонних бібліотеках."""

import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto_lab import AES, SHA1, sha1, sha3_224, sha3_256, sha3_384, sha3_512  # noqa: E402
from crypto_lab import shake128, shake256, keccak256, vigenere  # noqa: E402
from crypto_lab.aes import key_expansion  # noqa: E402

H = bytes.fromhex

# ------------------------------------------------------------------ AES, FIPS-197

FIPS197_APPENDIX_C = [
    ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "8ea2b7ca516745bfeafc49904b496089"),
]


@pytest.mark.parametrize("key,ct", FIPS197_APPENDIX_C, ids=["AES-128", "AES-192", "AES-256"])
def test_aes_fips197_appendix_c(key, ct):
    pt = H("00112233445566778899aabbccddeeff")
    cipher = AES(H(key))
    assert cipher.encrypt_block(pt).hex() == ct
    assert cipher.decrypt_block(H(ct)) == pt


def test_aes_fips197_appendix_b():
    cipher = AES(H("2b7e151628aed2a6abf7158809cf4f3c"))
    assert cipher.encrypt_block(H("3243f6a8885a308d313198a2e0370734")).hex() == \
        "3925841d02dc09fbdc118597196a0b32"


def test_aes_key_expansion_last_word():
    # FIPS-197, Appendix A.1: w[43] = b6630ca6
    w = key_expansion(H("2b7e151628aed2a6abf7158809cf4f3c"))
    assert len(w) == 44
    assert bytes(w[43]).hex() == "b6630ca6"


def test_aes_cbc_sp800_38a():
    # NIST SP 800-38A, F.2.1 CBC-AES128.Encrypt
    key = H("2b7e151628aed2a6abf7158809cf4f3c")
    iv = H("000102030405060708090a0b0c0d0e0f")
    pt = H("6bc1bee22e409f96e93d7e117393172a"
           "ae2d8a571e03ac9c9eb76fac45af8e51"
           "30c81c46a35ce411e5fbc1191a0a52ef"
           "f69f2445df4f9b17ad2b417be66c3710")
    ct = ("7649abac8119b246cee98e9b12e9197d"
          "5086cb9b507219ee95db113a917678b2"
          "73bed6b8e3c1743b7116e69e22229516"
          "3ff1caa1681fac09120eca307586e1a7")
    cipher = AES(key)
    assert cipher.encrypt_cbc(pt, iv, pad=False).hex() == ct
    assert cipher.decrypt_cbc(H(ct), iv, pad=False) == pt


@pytest.mark.parametrize("bits", [128, 192, 256])
def test_aes_against_cryptography_library(bits):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    for _ in range(20):
        key, iv = os.urandom(bits // 8), os.urandom(16)
        data = os.urandom(16 * 5)
        ref = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        expected = ref.update(data) + ref.finalize()
        assert AES(key).encrypt_cbc(data, iv, pad=False) == expected


def test_aes_roundtrip_with_padding():
    cipher = AES(os.urandom(16))
    iv = os.urandom(16)
    for n in range(0, 50):
        msg = os.urandom(n)
        assert cipher.decrypt_cbc(cipher.encrypt_cbc(msg, iv), iv) == msg
        assert cipher.decrypt_ecb(cipher.encrypt_ecb(msg)) == msg


def test_aes_wrong_key_fails():
    msg = b"Secret message for lab 1-2"
    iv = os.urandom(16)
    ct = AES(b"K" * 16).encrypt_cbc(msg, iv)
    with pytest.raises(ValueError):
        assert AES(b"Z" * 16).decrypt_cbc(ct, iv) != msg


# ------------------------------------------------------------------ SHA-1

SHA1_VECTORS = [
    (b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
    (b"The quick brown fox jumps over the lazy dog",
     "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
]


@pytest.mark.parametrize("msg,digest", SHA1_VECTORS, ids=["empty", "abc", "448bit", "fox"])
def test_sha1_vectors(msg, digest):
    assert sha1(msg) == digest


def test_sha1_million_a():
    h = SHA1()
    for _ in range(1000):
        h.update(b"a" * 1000)
    assert h.hexdigest() == "34aa973cd4c4daa4f61eeb2bdbad27316534016f"


def test_sha1_against_hashlib():
    for n in list(range(0, 130)) + [1000, 4096]:
        data = os.urandom(n)
        assert sha1(data) == hashlib.sha1(data).hexdigest()


# ------------------------------------------------------------------ SHA-3 / Keccak

def test_sha3_256_vectors():
    assert sha3_256(b"") == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    assert sha3_256(b"abc") == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"


def test_keccak256_original():
    assert keccak256(b"") == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


@pytest.mark.parametrize("ours,ref", [
    (sha3_224, hashlib.sha3_224), (sha3_256, hashlib.sha3_256),
    (sha3_384, hashlib.sha3_384), (sha3_512, hashlib.sha3_512),
], ids=["SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"])
def test_sha3_against_hashlib(ours, ref):
    for n in [0, 1, 71, 72, 135, 136, 137, 200, 1000]:
        data = os.urandom(n)
        assert ours(data) == ref(data).hexdigest()


def test_shake_against_hashlib():
    for n in [0, 5, 168, 300]:
        data = os.urandom(n)
        assert shake128(data, 200) == hashlib.shake_128(data).hexdigest(200)
        assert shake256(data, 64) == hashlib.shake_256(data).hexdigest(64)


# ------------------------------------------------------------------ Vigenere

def test_vigenere_classic():
    assert vigenere.encrypt("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"
    assert vigenere.decrypt("LXFOPVEFRNHR", "LEMON") == "ATTACKATDAWN"


def test_vigenere_keeps_case_and_symbols():
    text = "Hello, World!"
    enc = vigenere.encrypt(text, "key")
    assert enc == "Rijvs, Uyvjn!"
    assert vigenere.decrypt(enc, "key") == text
