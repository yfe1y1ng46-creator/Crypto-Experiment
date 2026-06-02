import math
import random


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def invmod(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m


def is_probable_prime(n, rounds=8):
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(n):
            return n


def rsa_keygen(bits=256, e=3):
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            return (e, n), (invmod(e, phi), n), (p, q)


def bytes_to_int(data):
    return int.from_bytes(data, "big")


def int_to_bytes(number):
    length = max(1, (number.bit_length() + 7) // 8)
    return number.to_bytes(length, "big")


def rsa_encrypt(message_int, public_key):
    e, n = public_key
    return pow(message_int, e, n)


def rsa_decrypt(cipher_int, private_key):
    d, n = private_key
    return pow(cipher_int, d, n)


def unconcealed_count(e, p, q):
    return (math.gcd(e - 1, p - 1) + 1) * (math.gcd(e - 1, q - 1) + 1)


def project_euler_182():
    p, q = 1009, 3643
    phi = (p - 1) * (q - 1)
    best_count = None
    answer_sum = 0
    answer_count = 0
    for e in range(2, phi):
        if math.gcd(e, phi) != 1:
            continue
        count = unconcealed_count(e, p, q)
        if best_count is None or count < best_count:
            best_count = count
            answer_sum = e
            answer_count = 1
        elif count == best_count:
            answer_sum += e
            answer_count += 1
    return best_count, answer_count, answer_sum


def main():
    random.seed(2026)
    best_count, e_count, e_sum = project_euler_182()
    public_key, private_key, primes = rsa_keygen(bits=256, e=3)
    message = b"RSA experiment 3"
    message_int = bytes_to_int(message)
    cipher_int = rsa_encrypt(message_int, public_key)
    plain_int = rsa_decrypt(cipher_int, private_key)
    recovered = int_to_bytes(plain_int)

    print("Euler 182 min unconcealed messages:", best_count)
    print("Euler 182 number of best e:", e_count)
    print("Euler 182 sum of e:", e_sum)
    print("RSA public e:", public_key[0])
    print("RSA modulus bits:", public_key[1].bit_length())
    print("RSA primes bits:", primes[0].bit_length(), primes[1].bit_length())
    print("RSA ciphertext:", cipher_int)
    print("RSA decrypted:", recovered.decode())
    print("RSA roundtrip ok:", recovered == message)


if __name__ == "__main__":
    main()
