from __future__ import annotations

import hashlib
import random
from collections import Counter

from Crypto.Cipher import AES


BLOCK_SIZE = 16
YELLOW_SUBMARINE = b"YELLOW SUBMARINE"


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    remainder = len(data) % block_size
    pad_len = block_size if remainder == 0 else block_size - remainder
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid PKCS#7 length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("invalid PKCS#7 padding byte")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS#7 padding content")
    return data[:-pad_len]


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def aes_ecb_encrypt_raw(data: bytes, key: bytes) -> bytes:
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("ECB input must be block aligned")
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def aes_ecb_decrypt_raw(data: bytes, key: bytes) -> bytes:
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("ECB input must be block aligned")
    return AES.new(key, AES.MODE_ECB).decrypt(data)


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    previous = iv
    blocks = []
    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset : offset + BLOCK_SIZE]
        encrypted = aes_ecb_encrypt_raw(xor_bytes(block, previous), key)
        blocks.append(encrypted)
        previous = encrypted
    return b"".join(blocks)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes, unpad: bool = True) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("CBC ciphertext must be block aligned")
    previous = iv
    blocks = []
    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset : offset + BLOCK_SIZE]
        decrypted = xor_bytes(aes_ecb_decrypt_raw(block, key), previous)
        blocks.append(decrypted)
        previous = block
    plaintext = b"".join(blocks)
    return pkcs7_unpad(plaintext, BLOCK_SIZE) if unpad else plaintext


def repeated_block_count(data: bytes, block_size: int = BLOCK_SIZE) -> int:
    blocks = [data[i : i + block_size] for i in range(0, len(data), block_size)]
    counts = Counter(blocks)
    return sum(count - 1 for count in counts.values() if count > 1)


def detect_ecb(ciphertext: bytes, block_size: int = BLOCK_SIZE) -> bool:
    return repeated_block_count(ciphertext, block_size) > 0


def random_bytes(rng: random.Random, length: int) -> bytes:
    return bytes(rng.randrange(0, 256) for _ in range(length))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
