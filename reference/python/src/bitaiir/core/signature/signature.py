from bitaiir.core.crypto.secp256k1 import Secp256k1
from bitaiir.core.crypto.hmac256 import HMACSHA256
from bitaiir.core.address.address import Address
from bitaiir.core.crypto.sha256 import SHA256
from bitaiir.core.base.base58 import Base58
from bitaiir.core.base.base64 import Base64
from typing import NamedTuple


class SignatureError(Exception):
    """
    Raised when there are invalid ECDSA signature parameters.
    """
    pass


class Signature(NamedTuple):
    """
    Represents an elliptic curve digital signature with components r and s.

    References:
        - https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    """
    r: int  # Signature component r
    s: int  # Signature component s


class SignatureAlgorithm:
    """
    Implements the ECDSA (Elliptic Curve Digital Signature Algorithm) for signing and verification.
    """

    def __init__(self):
        """
        Initialize the cryptographic components required for ECDSA.
        """
        self.secp256k1 = Secp256k1()
        self.address = Address()
        self.sha256 = SHA256()
        self.base58 = Base58()
        self.base64 = Base64()

    def varint(self, length: int) -> bytes:
        """
        Encode an integer into a variable-length format according to the Bitcoin protocol.

        Args:
            length (int): The integer to encode.

        Returns:
            bytes: The variable-length encoded representation of the integer.

        Raises:
            SignatureError: If the length exceeds the maximum allowable value.

        References:
            - https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
        """
        # If the length is less than 0xFD, encode it directly as 1 byte
        if length < 0xFD:
            return length.to_bytes(1, 'little')
        # If the length is within the range for a 2-byte encoding
        elif length <= 0xFFFF:
            return b'\xFD' + length.to_bytes(2, 'little')
        # If the length is within the range for a 4-byte encoding
        elif length <= 0xFFFFFFFF:
            return b'\xFE' + length.to_bytes(4, 'little')
        # If the length is within the range for an 8-byte encoding
        elif length <= 0xFFFFFFFFFFFFFFFF:
            return b'\xFF' + length.to_bytes(8, 'little')
        else:
            # Raise an error if the length is too large to encode
            raise SignatureError(f'Message is too lengthy: {length}')
    
    def msg_magic(self, msg: str) -> bytes:
        """
        Add a BitAiir message magic prefix to the given message.

        Args:
            msg (str): The message to be encoded with magic.

        Returns:
            bytes: The encoded message prefixed with magic.
        """
        # Convert the input message string to bytes using UTF-8 encoding
        message = msg.encode('utf-8')

        # Return the message with magic prefix, length encoded as varint, and the original message
        return b'\x18BitAiir Signed Message:\n' + self.varint(len(message)) + message

    def signed(self, privkey: int, msg: int, k: int) -> Signature | None:
        """
        Calculate the r and s values for an ECDSA signature.

        This is a helper function that performs the core signature calculation. It is not intended to be used directly.

        Args:
            privkey (int): The private key as a random integer.
            msg (int): The hash of the message (typically the double SHA256 of a message with 'msg magic' applied).
            k (int): The nonce used for signing, sourced from a random or pseudorandom generator (e.g., RFC 6979).

        Returns:
            Signature | None: The calculated ECDSA signature containing r and s, or None if the signature is invalid.
        """
        # Validate that the nonce (k) is a valid private key on the curve
        if not self.secp256k1.ecc.is_valid_key(k):
            return None

        # Compute the elliptic curve point k * G (standard multiplication using the generator G)
        point = self.secp256k1.ecc.eccnP(k)

        # Calculate the r value as the x-coordinate of the point modulo the curve order (n)
        r = point.x % self.secp256k1.curve.n_curve

        # If r is zero, the signature is invalid
        if r == 0:
            return None

        # Calculate the modular inverse of k modulo the curve order (n)
        k_inv = self.secp256k1.ecc.inverse(k, self.secp256k1.curve.n_curve)

        # Compute the s value using the signature equation: s = k^(-1) * (msg + privkey * r) mod n
        s = (k_inv * (msg + privkey * r)) % self.secp256k1.curve.n_curve

        # If s is zero, the signature is invalid
        if s == 0:
            return None

        # Ensure s is in the lower half of the curve order (BIP 62 requirement for deterministic signatures)
        if s > self.secp256k1.curve.n_curve >> 1:  # Curve order divided by 2
            s = self.secp256k1.curve.n_curve - s

        # Return the signature as a tuple containing r and s
        return Signature(r, s)

    def sign(self, privkey: int, msg: int, /) -> Signature:
        """
        Sign a message hash using a private key to generate an ECDSA signature.

        Args:
            privkey (int): The private key used for signing.
            msg (int): The hash of the message to be signed (typically double SHA256 of the message).

        Returns:
            Signature: The ECDSA signature containing r and s values.

        References:
            https://learnmeabitcoin.com/technical/ecdsa#sign
        """
        while True:
            # Generate a random integer (nonce) for signing
            k = self.address.wallet.generate_integer()

            # Attempt to calculate the signature using the random nonce
            if (sig := self.signed(privkey, msg, k)) is not None:
                return sig

    def rfc_sign(self, x: int, msg: int, q: int) -> Signature:
        """
        Generate an ECDSA signature deterministically using RFC 6979.

        Args:
            x (int): The private key.
            msg (int): The message hash to be signed.
            q (int): The order of the base point in the elliptic curve group.

        Returns:
            Signature: The ECDSA signature containing r and s values.

        References:
            https://www.rfc-editor.org/rfc/rfc6979 section 3.2
        """
        # Calculate bit lengths for the elliptic curve order
        qlen = q.bit_length()
        qolen = qlen >> 3  # Byte length of q
        rolen = (qlen + 7) >> 3  # Byte length for octet encoding

        # Convert the message hash to bytes (step a is omitted, as we already have the hash)
        h1 = msg.to_bytes(32, 'big')

        # Step b: Initialize V to all ones
        V = b'\x01' * 32

        # Step c: Initialize K to all zeros
        K = b'\x00' * 32

        # Step d: Construct the HMAC inputs m1 and m2
        m1 = b'\x00' + self.address.int_to_oct(x, rolen) + self.address.bits_to_oct(h1, q, qlen, rolen)
        m2 = b'\x01' + self.address.int_to_oct(x, rolen) + self.address.bits_to_oct(h1, q, qlen, rolen)

        # Update K with HMAC(K, V || m1) (step d)
        hmac1 = HMACSHA256(K)
        K = hmac1.compute(V + m1)

        # Update V with HMAC(K, V) (step e)
        hmac2 = HMACSHA256(K)
        V = hmac2.compute(V)

        # Update K with HMAC(K, V || m2) (step f)
        hmac3 = HMACSHA256(K)
        K = hmac3.compute(V + m2)

        # Update V with HMAC(K, V) (step g)
        hmac4 = HMACSHA256(K)
        V = hmac4.compute(V)

        # Step h: Generate candidate k values until a valid signature is produced
        while True:
            T = b''
            while len(T) < qolen:
                # Generate pseudorandom T with HMAC(K, V)
                hmac5 = HMACSHA256(K)
                V = hmac5.compute(V)
                T += V

            # Convert T to an integer k within the range [1, q-1]
            k = self.address.bits_to_int(T, qlen)

            # Attempt to sign the message with k
            if (sig := self.signed(x, msg, k)) is not None:
                return sig

            # If k was invalid, update K and V and retry
            hmac6 = HMACSHA256(K)
            K = hmac6.compute(V + b'\x00')
            hmac7 = HMACSHA256(K)
            V = hmac7.compute(V)

    def sign_message(
        self,
        wif: str,
        message: str,
        deterministic: bool = False
    ) -> tuple[str, ...]:
        """
        Sign a message using a private key in Wallet Import Format (WIF).

        Args:
            wif (str): The private key in WIF format (compressed or uncompressed).
            message (str): The message to be signed.
            deterministic (bool): If True, produces deterministic signatures (RFC 6979). Defaults to False.

        Returns:
            tuple[str, ...]: A tuple containing:
                - The generated address associated with the public key.
                - The original message.
                - The Base64-encoded signature.

        Raises:
            SignatureError: If the signature parameters are invalid.

        References:
            https://en.bitcoin.it/wiki/Protocol_documentation#Signatures
            https://www.rfc-editor.org/rfc/rfc6979
        """
        # Add message magic and compute its double SHA256 hash
        m_bytes = self.msg_magic(message)
        msg = int.from_bytes(self.sha256.double_sha256(m_bytes), 'big')

        # Extract the private key and compression flag from the WIF
        privkey, compressed = self.address.wif_to_int(wif)

        # Derive the public key from the private key
        publickey = self.address.private_to_public(privkey, compressed)

        # Generate the associated address from the public key
        address = self.address.public_to_address(publickey)

        # Determine whether to use deterministic or random signature generation
        if not deterministic:
            # Generate a random signature
            sig = self.sign(privkey, msg)
        else:
            # Generate a deterministic signature based on RFC 6979
            sig = self.rfc_sign(privkey, msg, self.secp256k1.curve.n_curve)

        # Determine the version (compressed or uncompressed)
        ver = 1 if compressed else 0

        # Convert the signature components (r and s) to 32-byte big-endian values
        r = sig.r.to_bytes(32, 'big')
        s = sig.s.to_bytes(32, 'big')

        # Define headers for P2PKH signatures
        headers = [
            [b'\x1b', b'\x1c', b'\x1d', b'\x1e'],  # 27 - 30 P2PKH uncompressed
            [b'\x1f', b'\x20', b'\x21', b'\x22'],  # 31 - 34 P2PKH compressed
        ]

        # Attempt to construct and verify the signature
        for header in headers[ver]:
            # Encode the signature as Base64
            signature = self.base64.encode(header + r + s)

            # Verify the signature for the generated address and message
            verified, _, _ = self.verify_message(address, message, signature)
            if verified:
                return address, message, signature

        # Raise an error if signature parameters are invalid
        raise SignatureError("Invalid signature parameters")
    
    def verify_message(
        self, address: str, message: str, signature: str
    ) -> tuple[bool, str, str]:
        """
        Verify a signed message using the provided address, message, and signature.

        Args:
            address (str): The address used to sign the message.
            message (str): The original message that was signed.
            signature (str): The Base64-encoded signature to verify.

        Returns:
            tuple[bool, str, str]:
                - A boolean indicating whether the verification succeeded.
                - The public key in hexadecimal format.
                - A status message describing the result.

        Raises:
            SignatureError: If the signature is malformed or invalid.

        References:
            https://en.bitcoin.it/wiki/Protocol_documentation#Signatures
            https://learnmeabitcoin.com/technical/ecdsa#verify
        """
        try:
            # Decode the Base64 signature
            dsig = self.base64.decode(signature)
        except Exception as error:
            raise SignatureError(f'Failed to decode signature: {error.args[0].capitalize()}')

        # Ensure the decoded signature is 65 bytes long
        if len(dsig) != 65:
            raise SignatureError(f'Signature must be 65 bytes long: Got {len(dsig)}')

        # Extract the header, r, and s values from the signature
        header, r, s = dsig[0], int.from_bytes(dsig[1:33], 'big'), int.from_bytes(dsig[33:], 'big')

        # Validate the header byte
        if header < 27 or header > 46:
            raise SignatureError(f'Header byte out of range: {header}')

        # Ensure r and s are within valid ranges
        if r >= self.secp256k1.curve.n_curve or r == 0:
            raise SignatureError(f'r-value out of range: {r}')
        if s >= self.secp256k1.curve.n_curve or s == 0:
            raise SignatureError(f's-value out of range: {s}')

        # Determine if the signature is compressed or uncompressed
        if header >= 27 and header <= 30:
            compressed = False
        else:
            header -= 4
            compressed = True

        # Reconstruct the elliptic curve point from the signature components
        recid = header - 27
        x = r + self.secp256k1.curve.n_curve * (recid >> 1)
        alpha = pow(x, 3, self.secp256k1.curve.p_curve) + self.secp256k1.curve.b_curve % self.secp256k1.curve.p_curve
        beta = pow(alpha, (self.secp256k1.curve.p_curve + 1) >> 2, self.secp256k1.curve.p_curve)
        y = beta if (beta - recid) % 2 == 0 else self.secp256k1.curve.p_curve - beta

        # Get the elliptic curve point R
        R = self.secp256k1.get_point(x, y)

        # Add message magic and compute its double SHA256 hash
        m_bytes = self.msg_magic(message)
        z = int.from_bytes(self.sha256.double_sha256(m_bytes), 'big')

        # Calculate the public key point Q
        e = (-z) % self.secp256k1.curve.n_curve
        inv_r = self.secp256k1.ecc.inverse(r, self.secp256k1.curve.n_curve)
        p = self.secp256k1.ecc.eccnP(s, R)
        q = self.secp256k1.ecc.eccnP(e, self.secp256k1.curve.gen_point)
        Q = self.secp256k1.ecc.addp(p, q)

        # Scale the public key point by the modular inverse of r
        point = self.secp256k1.ecc.eccnP(inv_r, Q)

        # Format the public key as compressed or uncompressed
        if compressed:
            prefix = b'\x02' if point.y % 2 == 0 else b'\x03'
            public_key = prefix + point.x.to_bytes(32, byteorder='big')
        else:
            public_key = (
                b'\x04'
                + point.x.to_bytes(32, byteorder='big')
                + point.y.to_bytes(32, byteorder='big')
            )

        # Convert the public key to an address
        addr = self.address.public_to_address(public_key.hex())

        # Verify if the reconstructed address matches the provided address
        if addr == address:
            return True, public_key.hex(), f"Message verified to be from {address}"
        return False, public_key.hex(), "Message failed to verify"


if __name__ == "__main__":
    # Initialize the signature algorithm object
    signature = SignatureAlgorithm()

    # Define test cases for signature verification
    test_cases = [
        # Compressed public key signature verification
        {
            "address": "aiir1JzjaNRfrBVh6abfGzM8H7WSJmxvhoNhGR",
            "message": "ECDSA is the most fun I have ever experienced",
            "signature": "HxS3ZviRS/zIa26ohjnHnQ8MnUTBZ3PAQcQj0j5zFflzDpJ4/4tR21sX+sMFLB23qlU6NwOrD04NQqDvdvG35G0="
        },
        # Uncompressed public key signature verification
        {
            "address": "aiir1KBoKn8xzGgFnirpmqtfPRbeoE7WmGW1Wf",
            "message": "ECDSA is the most fun I have ever experienced",
            "signature": "GxS3ZviRS/zIa26ohjnHnQ8MnUTBZ3PAQcQj0j5zFflzDpJ4/4tR21sX+sMFLB23qlU6NwOrD04NQqDvdvG35G0="
        },
        # Invalid signature test case
        {
            "address": "aiir175A5YsPUdM71mnNCC3i8faxxYJgBonjWL",
            "message": "ECDSA is the most fun I have ever experienced",
            "signature": "IBuc5GXSJCr6m7KevsBAoCiX8ToOjW2CDZMr6PCEbiHwQJ237LZTj/REbDHI1/yelY6uBWEWXiOWoGnajlgvO/A="
        },
        # Invalid signature error test case
        {
            "address": "aiir175A5YsPUdM71mnNCC3i8faxxYJgBonjWL",
            "message": "ECDSA is the most fun I have ever experienced",
            "signature": "HyiLDcQQ1p2bKmyqM0e5oIBQtKSZds4kJQ+VbZWpr0kYA6Qkam2MlUeTr+lm1teUGHuLapfa43Jj="
        }
    ]

    # Iterate through each test case
    for idx, case in enumerate(test_cases, 1):
        try:
            # Attempt to verify the message signature
            is_verified, public_key, status = signature.verify_message(
                case["address"], case["message"], case["signature"]
            )

            # Print detailed information for the test case
            print(f"Test Case {idx}:")
            print(f"    Address: {case['address']}")
            print(f"    Message: {case['message']}")
            print(f"    Signature: {case['signature']}")
            print(f"    Verified: {is_verified}")
            print(f"    Public Key: {public_key}")
            print(f"    Status: {status}\n")
        except SignatureError as e:
            # Handle and print errors for failed verifications
            print(f"Test Case {idx} Failed: {str(e)}\n")
