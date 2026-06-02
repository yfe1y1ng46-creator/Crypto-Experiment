import random

from common import (
    BLOCK_SIZE,
    aes_cbc_encrypt,
    aes_ecb_encrypt_raw,
    detect_ecb,
    pkcs7_pad,
    random_bytes,
)


def encryption_oracle(data: bytes, rng: random.Random) -> tuple[str, bytes]:
    key = random_bytes(rng, 16)
    prefix = random_bytes(rng, rng.randint(5, 10))
    suffix = random_bytes(rng, rng.randint(5, 10))
    plaintext = prefix + data + suffix
    if rng.choice([True, False]):
        return "ECB", aes_ecb_encrypt_raw(pkcs7_pad(plaintext), key)
    return "CBC", aes_cbc_encrypt(plaintext, key, random_bytes(rng, 16))


def main() -> None:
    rng = random.Random(2026)
    trials = 20
    correct = 0
    for _ in range(trials):
        actual, ciphertext = encryption_oracle(b"A" * (BLOCK_SIZE * 4), rng)
        guessed = "ECB" if detect_ecb(ciphertext) else "CBC"
        correct += guessed == actual
    print("trials:", trials)
    print("correct:", correct)
    print("accuracy:", f"{correct}/{trials}")


if __name__ == "__main__":
    main()
