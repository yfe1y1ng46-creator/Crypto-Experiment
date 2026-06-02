from __future__ import annotations

import base64
import hashlib

from Crypto.Cipher import AES


MRZ_WITH_MISSING_DIGIT = "12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4"
CIPHERTEXT_B64 = (
    "9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTM"
    "azJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI"
)


def mrz_value(char: str) -> int:
    if char == "<":
        return 0
    if char.isdigit():
        return int(char)
    return ord(char) - ord("A") + 10


def mrz_check_digit(chars: str) -> str:
    weights = [7, 3, 1]
    total = sum(mrz_value(char) * weights[i % 3] for i, char in enumerate(chars))
    return str(total % 10)


def odd_parity_byte(byte: int) -> int:
    high_seven_bits = byte & 0xFE
    ones = bin(high_seven_bits).count("1")
    return high_seven_bits | (0 if ones % 2 else 1)


def derive_aes_key_from_mrz(mrz: str) -> bytes:
    mrz_information = (mrz[0:10] + mrz[13:20] + mrz[21:28]).encode("ascii")
    k_seed = hashlib.sha1(mrz_information).digest()[:16]
    digest = hashlib.sha1(k_seed + bytes.fromhex("00000001")).digest()
    return bytes(odd_parity_byte(byte) for byte in digest[:16])


def remove_01_00_padding(data: bytes) -> bytes:
    marker = data.rfind(b"\x01")
    if marker != -1 and data[marker + 1 :] == b"\x00" * (len(data) - marker - 1):
        return data[:marker]
    return data.rstrip(b"\x00")


def solve() -> tuple[str, str, str, str]:
    expiry_check = mrz_check_digit("111116")
    completed_mrz = MRZ_WITH_MISSING_DIGIT.replace("?", expiry_check)
    key = derive_aes_key_from_mrz(completed_mrz)
    ciphertext = base64.b64decode(CIPHERTEXT_B64)
    plaintext = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(ciphertext)
    plaintext = remove_01_00_padding(plaintext).decode("utf-8")
    codeword = plaintext.split("Codewort lautet: ", 1)[1].rstrip("!")
    return completed_mrz, key.hex(), codeword, plaintext


def main() -> None:
    completed_mrz, key_hex, codeword, plaintext = solve()
    print("completed_mrz:", completed_mrz)
    print("aes_key:", key_hex)
    print("codeword:", codeword)
    print("plaintext:", plaintext)


if __name__ == "__main__":
    main()
