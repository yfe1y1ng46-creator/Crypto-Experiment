import base64
import hashlib
import itertools
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def fixed_xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("buffers must have the same length")
    return bytes(x ^ y for x, y in zip(a, b))


def repeating_key_xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


COMMON_CHARS = " etaoinshrdlucmfwypvbgkqjxzETAOINSHRDLUCMFWYPVBGKQJXZ0123456789',.!?-;:\n"
MAX_PREVIEW_WORDS = 8


def english_score(data: bytes) -> float:
    score = 0.0
    for b in data:
        c = chr(b)
        if c in COMMON_CHARS:
            score += 2.0
        elif 32 <= b <= 126:
            score += 0.2
        elif c in "\t\r\n":
            score += 0.0
        else:
            score -= 5.0

    lower = data.lower()
    for word in [b" the ", b" and ", b"ing", b" to ", b" of ", b"you", b"that"]:
        score += lower.count(word) * 4
    return score


def crack_single_byte_xor(ciphertext: bytes):
    candidates = []
    for key in range(256):
        plaintext = bytes(b ^ key for b in ciphertext)
        candidates.append((english_score(plaintext), key, plaintext))
    return max(candidates, key=lambda item: item[0])


def hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("buffers must have the same length")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def normalized_keysize_score(data: bytes, keysize: int, blocks: int = 8) -> float:
    chunks = [data[i * keysize : (i + 1) * keysize] for i in range(blocks)]
    chunks = [c for c in chunks if len(c) == keysize]
    distances = []
    for a, b in itertools.combinations(chunks, 2):
        distances.append(hamming_distance(a, b) / keysize)
    return sum(distances) / len(distances)


def crack_repeating_key_xor(ciphertext: bytes):
    keysizes = sorted(
        ((normalized_keysize_score(ciphertext, keysize), keysize) for keysize in range(2, 41)),
        key=lambda item: item[0],
    )[:5]

    best = None
    for _, keysize in keysizes:
        key = bytearray()
        for i in range(keysize):
            block = ciphertext[i::keysize]
            _, key_byte, _ = crack_single_byte_xor(block)
            key.append(key_byte)
        plaintext = repeating_key_xor(ciphertext, bytes(key))
        score = english_score(plaintext)
        candidate = (score, bytes(key), plaintext)
        if best is None or candidate[0] > best[0]:
            best = candidate
    return best


def plaintext_preview(data: bytes, max_words: int = MAX_PREVIEW_WORDS) -> str:
    return " ".join(data.decode("utf-8", errors="replace").split()[:max_words])


def solve_mtc3_sha1():
    target = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"
    key_pairs = [
        ("Q", "q"),
        ("W", "w"),
        ("%", "5"),
        ("8", "("),
        ("=", "0"),
        ("I", "i"),
        ("*", "+"),
        ("n", "N"),
    ]

    for choices in itertools.product(*key_pairs):
        for perm in itertools.permutations(choices):
            password = "".join(perm)
            if hashlib.sha1(password.encode("utf-8")).hexdigest() == target:
                return password
    raise RuntimeError("password not found")


def main():
    results = {}

    hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    results["challenge_1"] = base64.b64encode(bytes.fromhex(hex_input)).decode()

    a = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    b = bytes.fromhex("686974207468652062756c6c277320657965")
    results["challenge_2"] = fixed_xor(a, b).hex()

    challenge_3_cipher = bytes.fromhex(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )
    _, key3, plain3 = crack_single_byte_xor(challenge_3_cipher)
    results["challenge_3_key"] = repr(chr(key3))
    results["challenge_3_plaintext_preview"] = plaintext_preview(plain3)
    results["challenge_3_plaintext_sha256"] = hashlib.sha256(plain3).hexdigest()
    results["challenge_3_plaintext_length"] = str(len(plain3))
    results["challenge_3_plaintext_line_count"] = str(len(plain3.splitlines()))

    best4 = None
    for line_no, line in enumerate((ROOT / "cryptopals_4.txt").read_text().splitlines(), start=1):
        score, key, plaintext = crack_single_byte_xor(bytes.fromhex(line.strip()))
        candidate = (score, line_no, key, plaintext)
        if best4 is None or score > best4[0]:
            best4 = candidate
    _, line_no4, key4, plain4 = best4
    results["challenge_4_line"] = str(line_no4)
    results["challenge_4_key"] = repr(chr(key4))
    results["challenge_4_plaintext_preview"] = plaintext_preview(plain4)
    results["challenge_4_plaintext_sha256"] = hashlib.sha256(plain4).hexdigest()
    results["challenge_4_plaintext_length"] = str(len(plain4))
    results["challenge_4_plaintext_line_count"] = str(len(plain4.splitlines()))

    stanza = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    results["challenge_5"] = repeating_key_xor(stanza, b"ICE").hex()

    challenge_6_data = base64.b64decode((ROOT / "cryptopals_6.txt").read_text())
    results["challenge_6_hamming_test"] = str(hamming_distance(b"this is a test", b"wokka wokka!!!"))
    _, key6, plain6 = crack_repeating_key_xor(challenge_6_data)
    results["challenge_6_key"] = key6.decode("utf-8")
    results["challenge_6_plaintext_preview"] = plaintext_preview(plain6)
    results["challenge_6_plaintext_sha256"] = hashlib.sha256(plain6).hexdigest()
    results["challenge_6_plaintext_length"] = str(len(plain6))
    results["challenge_6_plaintext_line_count"] = str(len(plain6.splitlines()))
    results["challenge_6_reencrypt_matches_ciphertext"] = str(
        repeating_key_xor(plain6, key6) == challenge_6_data
    )
    results["challenge_6_note"] = "Full plaintext is recovered in memory as plain6; console output is a short preview plus checks."

    results["mtc3_password"] = solve_mtc3_sha1()
    results["mtc3_sha1"] = hashlib.sha1(results["mtc3_password"].encode("utf-8")).hexdigest()

    for name, value in results.items():
        print(f"[{name}]")
        print(value)
        print()


if __name__ == "__main__":
    main()
