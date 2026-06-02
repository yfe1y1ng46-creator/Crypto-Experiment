from common import pkcs7_unpad


def check(data: bytes) -> str:
    try:
        return pkcs7_unpad(data).decode()
    except ValueError as exc:
        return f"invalid: {exc}"


def main() -> None:
    samples = [
        b"ICE ICE BABY\x04\x04\x04\x04",
        b"ICE ICE BABY\x05\x05\x05\x05",
        b"ICE ICE BABY\x01\x02\x03\x04",
    ]
    for sample in samples:
        print(repr(sample), "=>", check(sample))


if __name__ == "__main__":
    main()
