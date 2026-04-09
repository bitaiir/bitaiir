from typing import NamedTuple


class PrivateKeyError(Exception):
    """Exception raised when the private key is out of the allowed range."""


class PointError(Exception):
    """Exception raised when the point is not on the elliptic curve."""


class Point(NamedTuple):
    """
    Represents a point on an elliptic curve.

    Attributes:
        x (int): The x-coordinate of the point.
        y (int): The y-coordinate of the point.
    """
    x: int
    y: int


class EllipticCurve(NamedTuple):
    """
    Represents an elliptic curve with complete parameters.

    Attributes:
        p_curve (int): The prime number defining the finite field.
        n_curve (int): The order of the curve.
        a_curve (int): The 'a' coefficient of the curve equation.
        b_curve (int): The 'b' coefficient of the curve equation.
        gen_point (Point): The generator point (base point) of the curve.
    """
    p_curve: int
    n_curve: int
    a_curve: int
    b_curve: int
    gen_point: Point


class EllipticCurveCryptography:
    """
    Implements cryptographic operations over an elliptic curve.

    Attributes:
        curve (EllipticCurve): The elliptic curve used for cryptographic operations.
    """
    def __init__(self, curve: EllipticCurve):
        """
        Initialize the cryptographic system with a specific elliptic curve.

        Args:
            curve (EllipticCurve): The elliptic curve parameters.
        """
        self.curve = curve
        self.pointNULL = Point(0, 0)  # Represents the point at infinity.

    def modp(self, n: int, p1: int) -> int:
        """
        Compute n modulo p1.

        Args:
            n (int): The dividend.
            p1 (int): The divisor (modulus).

        Returns:
            int: The result of n % p1.
        """
        return n % p1

    def inverse(self, r: int, p: int) -> int:
        """
        Calculate the modular multiplicative inverse of r modulo p.

        Args:
            r (int): The number to invert.
            p (int): The modulus.

        Returns:
            int: The modular inverse of r modulo p.
        """
        t, newt = 1, 0
        r, newr = r, p
        while newr != 0:
            quotient = r // newr
            t, newt = newt, t - quotient * newt
            r, newr = newr, r - quotient * newr
        return t % p

    def doublep(self, x: int, y: int) -> Point:
        """
        Double a point on the elliptic curve.

        Args:
            x (int): The x-coordinate of the point.
            y (int): The y-coordinate of the point.

        Returns:
            Point: The resulting point after doubling.
        """
        m = self.modp((3 * x**2 + self.curve.a_curve) * self.inverse(2 * y, self.curve.p_curve), self.curve.p_curve)
        x_r = self.modp(m**2 - 2 * x, self.curve.p_curve)
        y_r = self.modp(m * (x - x_r) - y, self.curve.p_curve)
        return Point(x_r, y_r)

    def addp(self, p1: Point, p2: Point) -> Point:
        """
        Add two points on the elliptic curve.

        Args:
            p1 (Point): The first point.
            p2 (Point): The second point.

        Returns:
            Point: The resulting point after addition.
        """
        if p1.x == p2.x and p1.y == p2.y:
            return self.doublep(p1.x, p1.y)
        m = self.modp((p2.y - p1.y) * self.inverse(p2.x - p1.x, self.curve.p_curve), self.curve.p_curve)
        x_r = self.modp(m**2 - p1.x - p2.x, self.curve.p_curve)
        y_r = self.modp(m * (p1.x - x_r) - p1.y, self.curve.p_curve)
        return Point(x_r, y_r)

    def eccnP(self, n: int, point: Point = None) -> Point:
        """
        Multiply a point on the elliptic curve by a scalar (n).

        Args:
            n (int): The scalar value.
            point (Point, optional): The point to multiply. Defaults to the curve's generator point.

        Returns:
            Point: The resulting point after multiplication.
        """
        point = self.curve.gen_point if point is None else point
        res = self.pointNULL
        while n:
            if n & 1:
                res = self.addp(res, point) if res != self.pointNULL else point
            point = self.doublep(point.x, point.y)
            n >>= 1
        return res

    def in_curve(self, x: int, y: int) -> bool:
        """
        Check if a point is on the elliptic curve.

        Args:
            x (int): The x-coordinate of the point.
            y (int): The y-coordinate of the point.

        Returns:
            bool: True if the point is on the curve, False otherwise.
        """
        return (y * y) % self.curve.p_curve == (x**3 + self.curve.a_curve * x + self.curve.b_curve) % self.curve.p_curve

    def is_valid_key(self, scalar: int, /) -> bool:
        """
        Check if a scalar (e.g., private key) is valid.

        Args:
            scalar (int): The scalar value to validate.

        Returns:
            bool: True if the scalar is valid, False otherwise.
        """
        return isinstance(scalar, int) and 1 <= scalar < self.curve.n_curve
    

if __name__ == "__main__":
    # Define the secp256k1 curve
    secp256k1 = EllipticCurve(
        p_curve=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        n_curve=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        a_curve=0,
        b_curve=7,
        gen_point=Point(
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        )
    )

    # Instantiate the ECC system
    ecc = EllipticCurveCryptography(secp256k1)

    # Test a private key and compute its public key
    private_key = 1
    public_key = ecc.eccnP(private_key)

    # Debug
    print(f"Public Key X:       {public_key.x}")
    print(f"Public Key Y:       {public_key.y}")
    print(f"Public Key X (Hex): {hex(public_key.x)}")
    print(f"Public Key Y (Hex): {hex(public_key.y)}")
    print(f"On curve?           {ecc.in_curve(public_key.x, public_key.y)}")
    print(f"Valid private key?  {ecc.is_valid_key(private_key)}")
