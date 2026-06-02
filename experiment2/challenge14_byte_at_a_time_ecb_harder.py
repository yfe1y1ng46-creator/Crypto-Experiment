from challenge12_byte_at_a_time_ecb_simple import UNKNOWN
from common import BLOCK_SIZE, YELLOW_SUBMARINE, aes_ecb_encrypt_raw, pkcs7_pad, sha256_hex


RANDOM_PREFIX = b"fixed-random-prefix"


def oracle(data: bytes) -> bytes:
    return aes_ecb_encrypt_raw(pkcs7_pad(RANDOM_PREFIX + data + UNKNOWN), YELLOW_SUBMARINE)


def find_prefix_alignment() -> tuple[int, int]:
    for pad_len in range(BLOCK_SIZE):
        probe = b"A" * pad_len + b"B" * (BLOCK_SIZE * 2)
        ciphertext = oracle(probe)
        for block_index in range(len(ciphertext) // BLOCK_SIZE - 1):
            left = ciphertext[block_index * BLOCK_SIZE : (block_index + 1) * BLOCK_SIZE]
            right = ciphertext[(block_index + 1) * BLOCK_SIZE : (block_index + 2) * BLOCK_SIZE]
            if left == right:
                return pad_len, block_index
    raise RuntimeError("prefix alignment not found")


def recover_unknown() -> bytes:
    align_pad_len, prefix_blocks = find_prefix_alignment()
    alignment = b"A" * align_pad_len
    recovered = bytearray()

    for i in range(len(UNKNOWN)):
        short_pad_len = BLOCK_SIZE - 1 - (i % BLOCK_SIZE)
        prefix = alignment + b"A" * short_pad_len
        target_block_index = prefix_blocks + i // BLOCK_SIZE
        target = oracle(prefix)[
            target_block_index * BLOCK_SIZE : (target_block_index + 1) * BLOCK_SIZE
        ]
        dictionary = {}
        for candidate in range(256):
            probe = prefix + bytes(recovered) + bytes([candidate])
            block = oracle(probe)[
                target_block_index * BLOCK_SIZE : (target_block_index + 1) * BLOCK_SIZE
            ]
            dictionary[block] = candidate
        recovered.append(dictionary[target])
    return bytes(recovered)


def main() -> None:
    align_pad_len, prefix_blocks = find_prefix_alignment()
    recovered = recover_unknown()
    print("random_prefix_len:", len(RANDOM_PREFIX))
    print("alignment_pad_len:", align_pad_len)
    print("prefix_blocks:", prefix_blocks)
    print("recovered_len:", len(recovered))
    print("recovered_sha256:", sha256_hex(recovered))
    print("preview:", " ".join(recovered.decode("utf-8", errors="replace").split()[:8]))


if __name__ == "__main__":
    main()
