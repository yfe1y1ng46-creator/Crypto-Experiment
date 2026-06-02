from common import YELLOW_SUBMARINE, aes_cbc_decrypt, aes_cbc_encrypt


def main() -> None:
    key = YELLOW_SUBMARINE
    iv = b"\x00" * 16
    plaintext = b"CBC mode test"
    ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    recovered = aes_cbc_decrypt(ciphertext, key, iv)
    print("key:", key.decode())
    print("iv_hex:", iv.hex())
    print("ciphertext_hex:", ciphertext.hex())
    print("recovered:", recovered.decode())
    print("roundtrip_ok:", recovered == plaintext)


if __name__ == "__main__":
    main()
