from bitaiir.core.ecc.elliptic_curve_cryptography import EllipticCurveCryptography, EllipticCurve, Point


class Secp256k1:
    """
    Class representing the secp256k1 elliptic curve.
    """

    def __init__(self):
        """
        Initializes the secp256k1 curve with the appropriate parameters.
        """
        # Define the parameters for the secp256k1 curve
        self.curve = EllipticCurve(
            p_curve=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
            n_curve=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
            a_curve=0,
            b_curve=7,
            gen_point=Point(
                0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
            )
        )
        # Instantiate the cryptography system with the curve
        self.ecc = EllipticCurveCryptography(self.curve)

    def get_point(self, x, y) -> Point:
        """
        Returns the secp256k1 curve parameters.

        Returns:
            EllipticCurve: Object representing the elliptic curve.
        """
        return Point(x, y)

    def get_curve(self) -> EllipticCurve:
        """
        Returns the secp256k1 curve parameters.

        Returns:
            EllipticCurve: Object representing the elliptic curve.
        """
        return self.curve

    def get_ecc_instance(self) -> EllipticCurveCryptography:
        """
        Returns the EllipticCurveCryptography instance configured with secp256k1.

        Returns:
            EllipticCurveCryptography: Instance configured for the secp256k1 curve.
        """
        return self.ecc


if __name__ == "__main__":
    # Instantiate the secp256k1 curve
    secp256k1 = Secp256k1()

    # Retrieve the curve parameters
    curve = secp256k1.get_curve()

    # Retrieve the EllipticCurveCryptography instance
    ecc = secp256k1.get_ecc_instance()

    # Test a private key and compute the public key
    private_key = 1
    public_key = ecc.eccnP(private_key)

    # Debug
    print(f"Public Key X:       {public_key.x}")
    print(f"Public Key Y:       {public_key.y}")
    print(f"Public Key X (Hex): {hex(public_key.x)}")
    print(f"Public Key Y (Hex): {hex(public_key.y)}")
    print(f"On curve?           {ecc.in_curve(public_key.x, public_key.y)}")
    print(f"Valid private key?  {ecc.is_valid_key(private_key)}")
