"""
Standalone math functions used in ECC
"""


def legendre_symbol(a: int, p: int) -> int:
    """Calculates the Legendre symbol (a | p) according to Euler's criterion. Returns -1, 0 or 1"""
    ec = pow(a, (p - 1) // 2, p)
    return ec - p if ec > 1 else ec


def tonelli_shanks(n: int, p: int):
    """
    Computes the square root of n modulo p using the Tonelli-Shanks algorithm.
    If n is a quadratic residue mod p, returns an integer r such that r^2 ≡ n (mod p).
    Returns None if no solution exists or if p | n.
    """

    # Verify n is a quadratic residue and coprime to n
    if legendre_symbol(n, p) != 1:
        return None

    # p = 3 (mod 4) case
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    # Step 1: Decompose p-1 as q * 2^s, where q is odd
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1

    # Step 2: Find a quadratic non-residue z (legendre_symbol(z, p) == -1)
    z = next(x for x in range(2, p) if legendre_symbol(x, p) == p - 1)

    # 3) Configure initial variables: m = s, c = z^q (mod p), t = n^q (mod p), r = n^(q+1)/2 (mod p)
    m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q + 1) // 2, p)

    # 4) Repeat until t == 1
    while t != 1:

        # First find the least integer i such that t^(2^i) = 1 (mod p)
        i, factor = 0, t
        while factor != 1:
            factor = pow(factor, 2, p)
            i += 1

        # Update variables
        b = pow(c, 2 ** (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p

    return r
