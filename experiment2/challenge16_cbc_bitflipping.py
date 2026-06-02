from common import BLOCK_SIZE, aes_cbc_decrypt, aes_cbc_encrypt


KEY = b"fedcba9876543210"
IV = b"\x00" * 16
PREFIX = b"comment1=cooking%20MCs;userdata="
SUFFIX = b";comment2=%20like%20a%20pound%20of%20bacon"


def encrypt_userdata(userdata: str) -> bytes:
    clean = userdata.replace(";", "").replace("=", "")
    return aes_cbc_encrypt(PREFIX + clean.encode() + SUFFIX, KEY, IV)


def is_admin(ciphertext: bytes) -> bool:
    plaintext = aes_cbc_decrypt(ciphertext, KEY, IV, unpad=False)
    return b";admin=true;" in plaintext


def forge_admin_ciphertext() -> bytes:
    injected = b"XadminXtrueX"
    userdata = "A" * BLOCK_SIZE + injected.decode()
    ciphertext = bytearray(encrypt_userdata(userdata))
    target = b";admin=true;"
    target_offset = len(PREFIX) + BLOCK_SIZE
    for i, target_byte in enumerate(target):
        ciphertext[target_offset - BLOCK_SIZE + i] ^= injected[i] ^ target_byte
    return bytes(ciphertext)


def main() -> None:
    forged = forge_admin_ciphertext()
    print("forged_ciphertext_hex:", forged.hex())
    print("is_admin:", is_admin(forged))


if __name__ == "__main__":
    main()
