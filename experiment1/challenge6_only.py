import base64
import itertools
from pathlib import Path


DATA_FILE = Path(__file__).with_name("cryptopals_6.txt")


def repeating_key_xor(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("inputs must have the same length")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def english_score(data: bytes) -> float:
    score = 0.0
    common = b" etaoinshrdlucmfwypvbgkqjxzETAOINSHRDLUCMFWYPVBGKQJXZ"

    for byte in data:
        if byte in common:
            score += 2.0
        elif 32 <= byte <= 126:
            score += 0.2
        elif byte in (9, 10, 13):
            score += 0.0
        else:
            score -= 5.0

    lower = data.lower()
    for word in (b" the ", b" and ", b" to ", b" of ", b"ing", b"you", b"that"):
        score += lower.count(word) * 4.0

    return score


def crack_single_byte_xor(ciphertext: bytes) -> tuple[float, int, bytes]:
    best = None
    for key in range(256):
        plaintext = bytes(byte ^ key for byte in ciphertext)
        candidate = (english_score(plaintext), key, plaintext)
        if best is None or candidate[0] > best[0]:
            best = candidate
    return best


def normalized_keysize_score(ciphertext: bytes, keysize: int, block_count: int = 8) -> float:
    blocks = [
        ciphertext[i * keysize : (i + 1) * keysize]
        for i in range(block_count)
    ]
    blocks = [block for block in blocks if len(block) == keysize]

    distances = [
        hamming_distance(a, b) / keysize
        for a, b in itertools.combinations(blocks, 2)
    ]
    return sum(distances) / len(distances)


def guess_keysizes(ciphertext: bytes, min_size: int = 2, max_size: int = 40) -> list[int]:
    scored = [
        (normalized_keysize_score(ciphertext, keysize), keysize)
        for keysize in range(min_size, max_size + 1)
    ]
    return [keysize for _, keysize in sorted(scored)[:5]]


def break_repeating_key_xor(ciphertext: bytes) -> tuple[int, bytes, bytes]:
    best = None

    for keysize in guess_keysizes(ciphertext):
        key = bytearray()

        for offset in range(keysize):
            transposed_block = ciphertext[offset::keysize]
            _, key_byte, _ = crack_single_byte_xor(transposed_block)
            key.append(key_byte)

        plaintext = repeating_key_xor(ciphertext, bytes(key))
        candidate = (english_score(plaintext), keysize, bytes(key), plaintext)
        if best is None or candidate[0] > best[0]:
            best = candidate

    _, keysize, key, plaintext = best
    return keysize, key, plaintext


def main() -> None:
    ciphertext = base64.b64decode(DATA_FILE.read_text())

    print("Hamming distance test:", hamming_distance(b"this is a test", b"wokka wokka!!!"))

    keysize, key, plaintext = break_repeating_key_xor(ciphertext)
    print("keysize:", keysize)
    print("key:", key.decode("utf-8"))
    print("plaintext:")
    print(plaintext.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
