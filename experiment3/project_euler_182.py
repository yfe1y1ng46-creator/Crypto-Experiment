from __future__ import annotations

import math


P = 1009
Q = 3643


def unconcealed_count(e: int, p: int = P, q: int = Q) -> int:
    return (math.gcd(e - 1, p - 1) + 1) * (math.gcd(e - 1, q - 1) + 1)


def solve_project_euler_182() -> tuple[int, int, int]:
    phi = (P - 1) * (Q - 1)
    best_count = None
    best_e_count = 0
    best_e_sum = 0

    for e in range(2, phi):
        if math.gcd(e, phi) != 1:
            continue

        count = unconcealed_count(e)
        if best_count is None or count < best_count:
            best_count = count
            best_e_count = 1
            best_e_sum = e
        elif count == best_count:
            best_e_count += 1
            best_e_sum += e

    return best_count, best_e_count, best_e_sum


def main() -> None:
    best_count, best_e_count, best_e_sum = solve_project_euler_182()
    print("p:", P)
    print("q:", Q)
    print("min_unconcealed_messages:", best_count)
    print("number_of_best_e:", best_e_count)
    print("sum_of_best_e:", best_e_sum)


if __name__ == "__main__":
    main()
