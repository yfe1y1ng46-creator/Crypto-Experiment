from common import pkcs7_pad


def main() -> None:
    padded = pkcs7_pad(b"YELLOW SUBMARINE", 20)
    print("input:", "YELLOW SUBMARINE")
    print("block_size:", 20)
    print("padded_repr:", repr(padded))
    print("padded_hex:", padded.hex())


if __name__ == "__main__":
    main()
