"""
Elliptic Curve Class
"""
# --- IMPORTS --- #
import json
import secrets

from src.library.ecc_math import legendre_symbol, tonelli_shanks

MAX_PRIME = pow(2, 19) - 1  # 7th Mersenne Prime


class EllipticCurve:

    def __init__(self, a: int, b: int, p: int, order: int, generator: tuple):
        """
        We instantiate an elliptic curve E of the form

            y^2 = x^3 + ax + b (mod p).

        We let E(F_p) denote the corresponding cyclic abelian group, comprised of the rational points of E and the
        point at infinity. The order variable refers to the order of this group. As the group is cyclic,
        it will contain a generator point, which can be specified during instantiation.

        """
        # Get curve values
        self.a = a
        self.b = b
        self.p = p

        # Get group values
        self.order = order
        self.generator = generator

    def __repr__(self):
        gx, gy = self.generator
        hex_dict = {
            'a': hex(self.a),
            'b': hex(self.b),
            'p': hex(self.p),
            'order': hex(self.order),
            'generator': (hex(gx), hex(gy))
        }
        return json.dumps(hex_dict)

    # --- Right Hand Side --- #

    def x_terms(self, x: int) -> int:
        """Compute x^3 + ax + b mod p."""
        return (pow(x, 3, self.p) + self.a * x + self.b) % self.p

    # --- Points on curve --- #

    def random_point(self) -> tuple:
        """
        Returns a cryptographically secure random point on the curve.
        """
        # Find a random x-coordinate that is on the curve
        x = next(
            x for x in (secrets.randbelow(self.p - 1) for _ in iter(int, 1))
            if self.is_x_on_curve(x)
        )
        # Compute corresponding y-coordinate
        return x, self.find_y_from_x(x)

    def is_point_on_curve(self, point: tuple) -> bool:
        """
        Returns true if the given point is on the curve, false otherwise
        """
        # Point at infinity case first
        if point is None:
            return True

        # Return True if y^2 = x^3 + ax +b (mod p) and False otherwise
        x, y = point
        return (self.x_terms(x) - pow(y, 2)) % self.p == 0

    def is_x_on_curve(self, x: int) -> bool:
        """
        A residue x is on the curve E iff x^3 + ax + b is a quadratic residue modulo p.
        This includes the trivial case x^3 + ax + b = 0 (mod p). Hence, by Euler's criterion, if
            ((x^3+ax+b) | p) != 1 (mod p),
        then x is a point on the curve.
        """
        return legendre_symbol(self.x_terms(x), self.p) != -1

    def find_y_from_x(self, x: int):
        """
        Using Tonelli-Shanks, return the smaller y such that E(x, y) = 0 if x is on the curve.
        Note that if (x, y) is a point, then (x, p-y) is also a point.
        """

        # Verify x is on curve
        if not self.is_x_on_curve(x):
            return None

        # Find the two possible y values
        y = tonelli_shanks(self.x_terms(x), self.p)
        neg_y = -y % self.p

        # Check y values
        try:
            assert self.is_point_on_curve((x, y))
            assert self.is_point_on_curve((x, neg_y))
            assert self.add_points((x, y), (x, neg_y)) is None
        except AssertionError:
            return None

        # Return y
        return y

    # --- Group operations --- #

    def add_points(self, point1: tuple, point2: tuple):
        """
        Adding points using the elliptic curve addition rules.
        """

        # Verify points exist
        try:
            assert self.is_point_on_curve(point1)
            assert self.is_point_on_curve(point2)
        except AssertionError:
            return None

        # Point at infinity cases
        if point1 is None:
            return point2
        if point2 is None:
            return point1

        # Get coordinates
        x1, y1 = point1
        x2, y2 = point2

        # Get slope if it exists
        if x1 == x2:
            if y1 != y2:  # Points are inverses
                return None
            elif y1 == 0:  # Point is its own inverse when lying on the x-axis
                return None
            else:  # Points are the same
                m = ((3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p)) % self.p
        else:  # Points are distinct
            m = ((y2 - y1) * pow(x2 - x1, -1, self.p)) % self.p

        # Use the addition formulas
        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        point = (x3, y3)

        # Verify result
        try:
            assert self.is_point_on_curve(point)
        except AssertionError:
            return None

        # Return sum of points
        return point

    def scalar_multiplication(self, n: int, point: tuple):
        """
        We use the double-and-add algorithm to add a point P with itself n times.

        Algorithm:
        ---------
        Break n into a binary representation (big-endian).
        Then iterate over each bit in the representation as follows:
            1) If it's the first bit, ignore;
            2) double the previous result (starting with P)
            3) if the bit = 1, add a copy of P to the result.

        Ex: n = 26. Binary representation = 11010
            bit     | action        | result
            --------------------------------
            1       | ignore        | P
            1       | double/add    | 2P + P = 3P
            0       | double        | 6P
            1       | double/add    | 12P + P = 13P
            0       | double        | 26P
        """
        # Point at infinity case
        if point is None:
            return None

        # Take residue of n modulo the group order
        n = n % self.order

        # Handle zero residue case
        if n == 0:
            return None

        # Initialize result to point at infinity and temp_point to the given point
        result = None
        temp_point = point
        # Iterate over the bits of n, from least significant to most significant
        while n > 0:
            # If the least significant bit is 1, add temp_point to result
            if n & 1:
                result = self.add_points(result, temp_point)

            # Double temp_point
            temp_point = self.add_points(temp_point, temp_point)

            # Right-shift n to process the next bit
            n >>= 1

        # Verify results
        if not self.is_point_on_curve(result):
            return None

        return result

        # # Proceed with algorithm
        # bitstring = bin(n)[2:]
        # temp_point = point
        # for x in range(1, len(bitstring)):
        #     temp_point = self.add_points(temp_point, temp_point)  # Double regardless of bit
        #     bit = int(bitstring[x:x + 1], 2)
        #     if bit == 1:
        #         temp_point = self.add_points(temp_point, point)  # Add to the doubling if bit == 1
        #
        # # Verify results
        # try:
        #     assert self.is_point_on_curve(temp_point)
        # except AssertionError:
        #     return None
        #
        # # Return point
        # return temp_point

    def multiply_generator(self, n: int):
        return self.scalar_multiplication(n, self.generator)

    # # --- Point compression/decompression --- #
    # def compress_point(self, point: tuple):
    #     """
    #     Will return x point as hex string with 0x02 or 0x03 prefix depending on parity of y
    #     """
    #     # Verify point is on the curve
    #     try:
    #         assert self.is_point_on_curve(point)
    #     except AssertionError:
    #         return None
    #
    #     # Point at infinity can't be compressed
    #     if not point:
    #         return point
    #
    #     x, y = point
    #     if y % 2 == 0:
    #         compressed_point = '0x02' + hex(x)[2:]
    #     else:
    #         compressed_point = '0x03' + hex(x)[2:]
    #     return compressed_point
    #
    # def decompress_point(self, hex_string: str):
    #     """
    #     We return a point on the curve according to the leading parity bit. We account for the hex string starting with '0x' or not.
    #     """
    #     # Get x val and y parity
    #     if hex_string[:2] == '0x':
    #         parity = int(hex_string[2:4], 16)
    #         x = int(hex_string[4:], 16)
    #     else:
    #         parity = int(hex_string[:2], 16)
    #         x = int(hex_string[2:], 16)
    #
    #     # Find candidate y from x
    #     temp_y = self.find_y_from_x(x)
    #
    #     # Choose correct y based on parity
    #     if temp_y % 2 == parity % 2:
    #         y = temp_y
    #     else:
    #         y = self.p - temp_y
    #
    #     # Verify point
    #     try:
    #         assert self.is_point_on_curve((x, y))
    #     except AssertionError:
    #         return None
    #
    #     return x, y
