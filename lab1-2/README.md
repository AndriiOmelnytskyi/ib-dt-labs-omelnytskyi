# Лабораторна робота № 1-2. Реалізація криптографічного алгоритму і алгоритму геш-функції

Дисципліна: Інформаційна безпека та децентралізовані технології (ХНУРЕ).

Рівень виконання: Advanced level.

| Варіант | Алгоритм | Файл |
|---|---|---|
| 1. Алгоритм шифрування | AES-128/192/256 (FIPS-197), режими ECB і CBC, PKCS#7 | `crypto_lab/aes.py` |
| 2. Геш-функція | Keccak / SHA-3 (FIPS 202): SHA3-224/256/384/512, SHAKE128/256, Keccak-256 | `crypto_lab/keccak.py` |
| 2. Геш-функція (basic) | SHA-1 (FIPS 180-4) | `crypto_lab/sha1.py` |
| 1. Алгоритм шифрування (basic) | Шифр Віженера | `crypto_lab/vigenere.py` |

Усі алгоритми реалізовано з нуля на Python 3 без сторонніх криптографічних бібліотек.
Бібліотеки `hashlib` та `cryptography` використовуються лише в тестах як еталон.

## Запуск

```bash
pip install pytest cryptography   # лише для тестів і порівняння швидкодії
python -m pytest -v               # перевірка на тестових векторах
python demo.py all                # демонстрація (aes | hash | avalanche | bench | vigenere)
```

## Приклад використання

```python
from crypto_lab import AES, sha1, sha3_256

key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
iv = bytes(16)
c = AES(key)
ct = c.encrypt_cbc(b"hello", iv)
assert c.decrypt_cbc(ct, iv) == b"hello"

print(sha1(b"abc"))      # a9993e364706816aba3e25717850c26c9cd0d89d
print(sha3_256(b"abc"))  # 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
```

## Тестові вектори

* AES: FIPS-197 Appendix A.1, B, C.1-C.3; NIST SP 800-38A F.2.1 (CBC); 60 випадкових порівнянь з бібліотекою `cryptography`.
* SHA-1: FIPS 180 ("", "abc", 448-бітне повідомлення, мільйон літер "a"); порівняння з `hashlib`.
* SHA-3: FIPS 202 ("", "abc"), Keccak-256(""); порівняння всіх варіантів з `hashlib`.
* Віженер: класичний приклад ATTACKATDAWN / LEMON.
