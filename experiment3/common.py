from __future__ import annotations

import math
import random


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def invmod(a: int, modulus: int) -> int:
    g, x, _ = egcd(a, modulus)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % modulus


def is_probable_prime(n: int, rounds: int = 8) -> bool:
    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(n):
            return n


def rsa_keygen(bits: int = 256, e: int = 3):
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            return (e, n), (invmod(e, phi), n), (p, q)


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def int_to_bytes(number: int) -> bytes:
    length = max(1, (number.bit_length() + 7) // 8)
    return number.to_bytes(length, "big")


def rsa_encrypt(message_int: int, public_key: tuple[int, int]) -> int:
    e, n = public_key
    return pow(message_int, e, n)


def rsa_decrypt(cipher_int: int, private_key: tuple[int, int]) -> int:
    d, n = private_key
    return pow(cipher_int, d, n)
