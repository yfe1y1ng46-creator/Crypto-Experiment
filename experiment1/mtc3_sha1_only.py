import hashlib
import itertools
import time


TARGET_SHA1 = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"

# Each tuple contains two possible characters for one fingerprinted key.
# The challenge uses a German keyboard layout, so some shifted characters
# differ from a US keyboard layout.
FINGERPRINT_KEY_PAIRS = [
    ("Q", "q"),
    ("W", "w"),
    ("%", "5"),
    ("8", "("),
    ("=", "0"),
    ("I", "i"),
    ("*", "+"),
    ("n", "N"),
]


def sha1_hex(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def generate_candidates():
    for selected_chars in itertools.product(*FINGERPRINT_KEY_PAIRS):
        for permutation in itertools.permutations(selected_chars):
            yield "".join(permutation)


def crack_sha1_password(target_sha1: str) -> tuple[str, int]:
    tried = 0
    seen = set()

    for password in generate_candidates():
        if password in seen:
            continue
        seen.add(password)
        tried += 1

        if sha1_hex(password) == target_sha1:
            return password, tried

    raise ValueError("Password not found")


def main() -> None:
    start_time = time.perf_counter()
    password, tried = crack_sha1_password(TARGET_SHA1)
    elapsed = time.perf_counter() - start_time

    print("target_sha1:", TARGET_SHA1)
    print("password:", password)
    print("password_sha1:", sha1_hex(password))
    print("tried_candidates:", tried)
    print("elapsed_seconds:", f"{elapsed:.6f}")


if __name__ == "__main__":
    main()
