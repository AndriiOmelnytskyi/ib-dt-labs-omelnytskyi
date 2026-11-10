"""Демонстрація бібліотеки endian на тестових векторах методичних вказівок."""

from endian import big_endian_to_hex, describe, hex_to_bytes, little_endian_to_hex

VECTORS = [
    "ff00000000000000000000000000000000000000000000000000000000000000",
    "aaaa000000000000000000000000000000000000000000000000000000000000",
    "FFFFFFFF",
    "F0" + "00" * 511,
]


def short(s, n=60):
    s = str(s)
    return s if len(s) <= n else f"{s[:28]}...{s[-28:]} ({len(s)} знаків)"


def main():
    for i, v in enumerate(VECTORS, 1):
        info = describe(v)
        print(f"Vector {i}:")
        print(f"  Value:           {short(v)}")
        print(f"  Number of bytes: {info['bytes']}")
        print(f"  Little-endian:   {short(info['little_endian'])}")
        print(f"  Big-endian:      {short(info['big_endian'])}")
        back_le = little_endian_to_hex(info["little_endian"], info["bytes"])
        back_be = big_endian_to_hex(info["big_endian"], info["bytes"])
        print(f"  Зворотне перетворення: LE->HEX {'OK' if back_le == v.lower() else 'FAIL'}, "
              f"BE->HEX {'OK' if back_be == v.lower() else 'FAIL'}")
        print()

    print("Розміщення числа 0x01020304 у пам'яті (4 байти):")
    print("  big-endian   :", " ".join(f"{b:02x}" for b in hex_to_bytes(big_endian_to_hex(0x01020304, 4))))
    print("  little-endian:", " ".join(f"{b:02x}" for b in hex_to_bytes(little_endian_to_hex(0x01020304, 4))))
    print()
    print("Приклад з Bitcoin: поле nonce генезис-блоку зберігається як 1dac2b7c (little-endian)")
    print("  little-endian значення:", describe("1dac2b7c")["little_endian"])


if __name__ == "__main__":
    main()
