"""Бібліотека перетворення hex-значень у цілі беззнакові числа і назад
з урахуванням порядку байтів (little-endian / big-endian).

Перетворення виконуються вручну, побайтово, без int.from_bytes / int.to_bytes,
щоб явно показати, як формується число з послідовності байтів.
"""

from __future__ import annotations

HEX_DIGITS = "0123456789abcdef"


def _normalize_hex(value: str) -> str:
    s = value.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if not s:
        raise ValueError("Порожнє hex-значення")
    if any(ch not in HEX_DIGITS for ch in s):
        raise ValueError(f"Некоректний символ у hex-рядку: {value!r}")
    if len(s) % 2:
        s = "0" + s          # доповнюємо до цілої кількості байтів
    return s


def hex_to_bytes(value: str) -> list[int]:
    """Розбиває hex-рядок на байти (кожні 2 символи = 1 байт)."""
    s = _normalize_hex(value)
    return [HEX_DIGITS.index(s[i]) * 16 + HEX_DIGITS.index(s[i + 1]) for i in range(0, len(s), 2)]


def bytes_to_hex(data: list[int]) -> str:
    return "".join(HEX_DIGITS[b >> 4] + HEX_DIGITS[b & 0x0F] for b in data)


def hex_to_big_endian(value: str) -> int:
    """a. HEX -> ціле число, перший байт найстарший (big-endian)."""
    result = 0
    for b in hex_to_bytes(value):
        result = (result << 8) | b
    return result


def hex_to_little_endian(value: str) -> int:
    """b. HEX -> ціле число, перший байт наймолодший (little-endian)."""
    result = 0
    for i, b in enumerate(hex_to_bytes(value)):
        result |= b << (8 * i)
    return result


def _int_to_bytes_be(number: int, num_bytes: int | None) -> list[int]:
    if number < 0:
        raise ValueError("Підтримуються лише беззнакові числа")
    out = []
    n = number
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if not out:
        out = [0]
    if num_bytes is not None:
        if len(out) > num_bytes:
            raise OverflowError(f"Число не вміщується у {num_bytes} байт")
        out += [0] * (num_bytes - len(out))
    return out[::-1]          # від старшого байта до молодшого


def big_endian_to_hex(number: int, num_bytes: int | None = None) -> str:
    """d. Ціле число -> HEX у порядку big-endian."""
    return bytes_to_hex(_int_to_bytes_be(number, num_bytes))


def little_endian_to_hex(number: int, num_bytes: int | None = None) -> str:
    """c. Ціле число -> HEX у порядку little-endian."""
    return bytes_to_hex(_int_to_bytes_be(number, num_bytes)[::-1])


def describe(value: str) -> dict:
    """Повна інформація про hex-значення, як у тестових векторах методички."""
    return {
        "value": value,
        "bytes": len(hex_to_bytes(value)),
        "little_endian": hex_to_little_endian(value),
        "big_endian": hex_to_big_endian(value),
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Використання: python endian.py <hex>")
        sys.exit(1)
    info = describe(sys.argv[1])
    print(f"Value:           {info['value']}")
    print(f"Number of bytes: {info['bytes']}")
    print(f"Little-endian:   {info['little_endian']}")
    print(f"Big-endian:      {info['big_endian']}")
