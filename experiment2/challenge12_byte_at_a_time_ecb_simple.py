import base64

from common import BLOCK_SIZE, YELLOW_SUBMARINE, aes_ecb_encrypt_raw, detect_ecb, pkcs7_pad, sha256_hex


UNKNOWN_B64 = (
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
)
UNKNOWN = base64.b64decode(UNKNOWN_B64)


def oracle(data: bytes) -> bytes:
    return aes_ecb_encrypt_raw(pkcs7_pad(data + UNKNOWN), YELLOW_SUBMARINE)


def discover_block_size() -> int:
    base_len = len(oracle(b""))
    for n in range(1, 65):
        new_len = len(oracle(b"A" * n))
        if new_len > base_len:
            return new_len - base_len
    raise RuntimeError("block size not found")


def recover_unknown() -> bytes:
    block_size = discover_block_size()
    if not detect_ecb(oracle(b"A" * (block_size * 4))):
        raise RuntimeError("oracle is not ECB")

    recovered = bytearray()
    for i in range(len(UNKNOWN)):
        pad_len = block_size - 1 - (i % block_size)
        prefix = b"A" * pad_len
        block_index = i // block_size
        target = oracle(prefix)[block_index * block_size : (block_index + 1) * block_size]
        dictionary = {}
        for candidate in range(256):
            probe = prefix + bytes(recovered) + bytes([candidate])
            block = oracle(probe)[block_index * block_size : (block_index + 1) * block_size]
            dictionary[block] = candidate
        recovered.append(dictionary[target])
    return bytes(recovered)


def main() -> None:
    recovered = recover_unknown()
    print("block_size:", discover_block_size())
    print("detected_mode:", "ECB")
    print("recovered_len:", len(recovered))
    print("recovered_sha256:", sha256_hex(recovered))
    print("preview:", " ".join(recovered.decode("utf-8", errors="replace").split()[:8]))


if __name__ == "__main__":
    main()
