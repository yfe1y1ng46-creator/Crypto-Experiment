from __future__ import annotations

import random

from common import bytes_to_int, int_to_bytes, rsa_decrypt, rsa_encrypt, rsa_keygen


def main() -> None:
    random.seed(2026)
    public_key, private_key, primes = rsa_keygen(bits=256, e=3)

    message = b"RSA experiment 3"
    message_int = bytes_to_int(message)
    ciphertext = rsa_encrypt(message_int, public_key)
    recovered_int = rsa_decrypt(ciphertext, private_key)
    recovered = int_to_bytes(recovered_int)

    print("public_e:", public_key[0])
    print("modulus_bits:", public_key[1].bit_length())
    print("prime_bits:", primes[0].bit_length(), primes[1].bit_length())
    print("ciphertext:", ciphertext)
    print("decrypted:", recovered.decode())
    print("roundtrip_ok:", recovered == message)


if __name__ == "__main__":
    main()
