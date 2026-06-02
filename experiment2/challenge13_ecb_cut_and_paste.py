from common import YELLOW_SUBMARINE, aes_ecb_decrypt_raw, aes_ecb_encrypt_raw, pkcs7_pad, pkcs7_unpad


def profile_for(email: str) -> str:
    clean_email = email.replace("&", "").replace("=", "")
    return f"email={clean_email}&uid=10&role=user"


def encrypt_profile(email: str) -> bytes:
    return aes_ecb_encrypt_raw(pkcs7_pad(profile_for(email).encode()), YELLOW_SUBMARINE)


def decrypt_profile(ciphertext: bytes) -> str:
    return pkcs7_unpad(aes_ecb_decrypt_raw(ciphertext, YELLOW_SUBMARINE)).decode()


def forge_admin_profile() -> str:
    admin_block_email = "A" * 10 + "admin" + chr(11) * 11
    admin_block = encrypt_profile(admin_block_email)[16:32]
    normal_profile = encrypt_profile("foo@bar12.com")
    forged = normal_profile[:32] + admin_block
    return decrypt_profile(forged)


def main() -> None:
    print("normal_profile:", profile_for("foo@bar12.com"))
    print("forged_profile:", forge_admin_profile())
    print("is_admin:", "role=admin" in forge_admin_profile())


if __name__ == "__main__":
    main()
