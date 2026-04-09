from bitaiir.core.crypto.secp256k1 import Secp256k1
from bitaiir.core.crypto.ripemd160 import Ripemd160
from bitaiir.core.crypto.sha256 import SHA256
from bitaiir.core.base.base58 import Base58


class PrivateKeyError(Exception):
    """Private key is out of allowed range"""


class Address:
    def __init__(self):
        """Initialize required cryptographic components."""
        self.secp256k1 = Secp256k1()
        self.base58 = Base58()
        self.sha256 = SHA256()
        self.ripemd160 = Ripemd160()

    def is_odd(self, n: int) -> int:
        """
        Determine if a given integer is odd.

        Args:
            n (int): The integer to be checked.

        Returns:
            int: 1 if the integer is odd, 0 if the integer is even.
        """
        # Use bitwise AND to check the least significant bit (LSB)
        # If LSB is 1, the number is odd; if 0, the number is even
        return n & 1

    def int_to_oct(self, x: int, rolen: int) -> bytes:
        """
        Convert an integer to an octet string of a specified length.

        Args:
            x (int): The integer to be converted.
            rolen (int): The required length of the resulting octet string in bytes.

        Returns:
            bytes: The octet string resulting from the conversion.

        References:
            https://www.rfc-editor.org/rfc/rfc6979 section 2.3.3.
        """
        # Calculate the actual byte length of the integer
        xolen = x.bit_length() >> 3

        # Convert the integer to a hexadecimal string
        x_hex = f'{x:x}'

        # Adjust the hexadecimal string to match the required octet length
        if xolen < rolen:
            # Pad with leading zeros if the octet length is greater
            x_hex = f'{x:0>{rolen << 1}x}'
        elif xolen > rolen:
            # Truncate to the required octet length if the integer is too large
            x_hex = x_hex[xolen - rolen << 1 :]

        # Convert the hexadecimal string to bytes and return
        return bytes.fromhex(x_hex)

    def bits_to_int(self, b: bytes, qlen: int) -> int:
        """
        Convert the given bits in bytes to an integer value.

        Args:
            b (bytes): The input bytes containing the bits to be converted.
            qlen (int): The bit length of the field for which the bits are being converted.

        Returns:
            int: The integer value converted from the input bits.

        References:
            https://www.rfc-editor.org/rfc/rfc6979 section 2.3.2.
        """
        # Determine the bit length of the input byte array
        blen = len(b) << 3  # Multiply byte length by 8 to get bit length

        # Convert the byte array to an integer
        b_int = int.from_bytes(b, 'big')

        # If the input bit length exceeds qlen, truncate the integer
        if blen > qlen:
            b_int = b_int >> (blen - qlen)

        # Return the resulting integer
        return b_int

    def bits_to_oct(self, b: bytes, q: int, qlen: int, rolen: int) -> bytes:
        """
        Convert a byte string to an octet string using the specified parameters.

        Args:
            b (bytes): The input byte string.
            q (int): The modulus parameter (q) for the curve.
            qlen (int): The bit length of q.
            rolen (int): The required length of the resulting octet string in bytes.

        Returns:
            bytes: The resulting octet string.

        References:
            https://www.rfc-editor.org/rfc/rfc6979 section 2.3.4.
        """
        # Convert the input bytes to an integer using the specified bit length (qlen)
        z1 = self.bits_to_int(b, qlen)

        # Subtract q from the integer value (modular reduction step)
        z2 = z1 - q

        # If the result is negative, retain the original value (as per RFC 6979)
        if z2 < 0:
            z2 = z1

        # Convert the resulting integer to an octet string of the specified length
        return self.int_to_oct(z2, rolen)

    def valid_checksum(self, version: bytes, privkey: bytes, checksum: bytes, /) -> bool:
        """
        Validate the checksum for the provided version, private key, and checksum bytes.

        Args:
            version (bytes): The version byte(s).
            privkey (bytes): The private key byte(s).
            checksum (bytes): The checksum byte(s).

        Returns:
            bool: True if the checksum is valid, False otherwise.
        """
        # Concatenate the version and private key bytes
        data = version + privkey

        # Compute the double SHA-256 hash of the concatenated data
        computed_checksum = self.sha256.double_sha256(data)[:4]

        # Compare the computed checksum with the provided checksum
        return computed_checksum == checksum

    def wif_to_int(self, wif: str, /) -> tuple[int, bool]:
        """
        Convert a WIF (Wallet Import Format) private key to an integer.

        Args:
            wif (str): The WIF private key as a string.

        Returns:
            tuple[int, bool]: A tuple containing:
                - The private key as an integer.
                - A boolean indicating whether the key is compressed.

        Raises:
            PrivateKeyError: If the WIF format is invalid, the checksum is incorrect, or the private key is invalid.
        """
        # Validate that the input is a string
        if not isinstance(wif, str):
            raise PrivateKeyError('Input must be a WIF format string')

        # Decode the WIF to its components
        try:
            version, privkey, checksum = self.wif_to_bytes(wif)
        except ValueError:
            raise PrivateKeyError('Invalid WIF format: Unable to extract components')

        # Validate the checksum
        if not self.valid_checksum(version, privkey, checksum):
            raise PrivateKeyError('Invalid WIF checksum')

        # Determine if the key is compressed and convert the private key to an integer
        if len(privkey) == 33:
            privkey_int = int.from_bytes(privkey[:-1], 'big')  # Remove the compression flag byte
            compressed = True
        else:
            privkey_int = int.from_bytes(privkey, 'big')
            compressed = False

        # Validate the private key
        if self.secp256k1.ecc.is_valid_key(privkey_int):
            return privkey_int, compressed

        raise PrivateKeyError('Invalid scalar/private key')

    def wif_to_bytes(self, wif: str, /) -> tuple[bytes, bytes, bytes]:
        """
        Convert a WIF (Wallet Import Format) private key to its components in bytes.

        Args:
            wif (str): The WIF private key as a string.

        Returns:
            tuple[bytes, bytes, bytes]: A tuple containing:
                - The version byte.
                - The private key bytes.
                - The checksum bytes.

        Raises:
            PrivateKeyError: If the WIF format is invalid or the input is not a string.
        """
        # Ensure the input is a string
        if not isinstance(wif, str):
            raise PrivateKeyError('Input must be a WIF format string')

        # Decode the Base58-encoded WIF key
        try:
            privkey = self.base58.decode(wif)
        except ValueError:
            raise PrivateKeyError('Invalid WIF format: Base58 decoding failed')
        
        # Extract the version byte, private key bytes, and checksum bytes
        version, privkey, checksum = privkey[:1], privkey[1:-4], privkey[-4:]

        return version, privkey, checksum

    def private_key_to_public_key_points(self, private_key: int, /) -> tuple[int, int]:
        """
        Derive the public key points (x, y) from a private key.

        Args:
            private_key (int): The private key as an integer.

        Returns:
            tuple[int, int]: A tuple containing the public key points (x, y) as integers.

        Raises:
            ValueError: If the provided private key is invalid.
        """
        # Validate the private key to ensure it's within the valid range of the curve
        if not self.secp256k1.ecc.is_valid_key(private_key):
            raise ValueError("The provided private key is not valid. Ensure it is within the curve's valid range.")

        # Derive the public key points using the elliptic curve multiplication
        public_key_points = self.secp256k1.ecc.eccnP(private_key)

        return public_key_points

    def private_to_public(self, private_key: int | str | bytes, compressed: bool = True) -> str:
        """
        Convert a private key to its corresponding public key.

        Args:
            private_key (int | str | bytes): The private key, which can be an integer, a hexadecimal string, or bytes.
            compressed (bool): Whether to return the public key in compressed format. Defaults to True.

        Returns:
            str: The public key in hexadecimal format.

        Raises:
            TypeError: If the private key is not an integer, bytes, or a valid hexadecimal string.
            ValueError: If the generated public key is not on the elliptic curve.
        """
        # Convert private key to an integer based on its type
        if isinstance(private_key, bytes):
            private_key_int = int.from_bytes(private_key, byteorder='big')
        elif isinstance(private_key, int):
            private_key_int = private_key
        elif isinstance(private_key, str):
            try:
                private_key_int = int(private_key, 16)
            except ValueError:
                raise TypeError("Private_key must be a valid hex string.")
        else:
            raise TypeError("Private_key must be an integer, bytes, or hex string.")

        # Derive public key points (x, y) from the private key
        public_key_x, public_key_y = self.private_key_to_public_key_points(private_key_int)

        # Ensure the public key is on the elliptic curve
        if not self.secp256k1.ecc.in_curve(public_key_x, public_key_y):
            raise ValueError("The generated public key is not on the curve.")

        # Generate the public key in compressed or uncompressed format
        if compressed:
            prefix = b'\x02' if public_key_y % 2 == 0 else b'\x03'
            public_key = prefix + public_key_x.to_bytes(32, byteorder='big')
        else:
            public_key = (
                b'\x04'
                + public_key_x.to_bytes(32, byteorder='big')
                + public_key_y.to_bytes(32, byteorder='big')
            )

        return public_key.hex()

    def public_to_address(self, public_key: str) -> str:
        """
        Convert a public key to a BitAiir-compatible address.

        Args:
            public_key (str): The public key in hexadecimal format.

        Returns:
            str: The generated address in BitAiir-compatible format.
        """
        # Convert the public key from hex to bytes
        public_key_bytes = bytes.fromhex(public_key)

        # Perform SHA-256 hashing on the public key bytes
        sha256_hashed = self.sha256.sha256(public_key_bytes)

        # Perform RIPEMD-160 hashing on the result of SHA-256
        ripemd160_hashed = self.ripemd160.digest(sha256_hashed)

        # Add a network prefix to the RIPEMD-160 hash (0x00 for mainnet)
        prefixed_key = b'\x00' + ripemd160_hashed

        # Calculate the checksum by double SHA-256 hashing the prefixed key
        checksum = self.sha256.sha256(self.sha256.sha256(prefixed_key))[:4]

        # Concatenate the prefixed key and checksum
        final_key = prefixed_key + checksum

        # Encode the concatenated key in Base58
        base58_encoded = self.base58.encode(final_key)

        # Prepend the custom "aiir" prefix to the encoded address
        return f"aiir{base58_encoded}"

    def private_key_to_WIF(self, private_key: str, compressed: bool = False) -> str:
        """
        Convert a private key to WIF (Wallet Import Format).

        Args:
            private_key (str): The private key in hexadecimal format.
            compressed (bool): Whether to generate a compressed WIF. Defaults to False.

        Returns:
            str: The WIF format private key.
        """
        # Add the version prefix (0xfe for BitAiir mainnet private keys)
        version_prefix = b"\xfe"
        extended_key = version_prefix + bytes.fromhex(private_key)

        # Append the compression flag if the key should be compressed
        if compressed:
            extended_key += b'\x01'

        # Calculate the checksum by double hashing the extended key
        first_sha256 = self.sha256.sha256(extended_key)
        second_sha256 = self.sha256.sha256(first_sha256)
        checksum = second_sha256[:4]

        # Append the checksum to the extended key
        final_key = extended_key + checksum

        # Encode the resulting key in Base58
        return self.base58.encode(final_key)


if __name__ == "__main__":
    # Initialize the Address class to provide cryptographic functionality for testing
    address = Address()

    # Test 1: Check if a number is odd
    print("Testing is_odd:")
    # Testing with odd and even numbers
    print(f"5 is odd: {address.is_odd(5)}")  # Expected: 1 (True for odd)
    print(f"4 is odd: {address.is_odd(4)}\n")  # Expected: 0 (False for even)

    # Test 2: Convert integer to octet string
    print("Testing int_to_oct:")
    # Convert integer 255 to an octet string of 4 bytes
    oct_result = address.int_to_oct(255, 4)
    print(f"Integer 255 to octet (4 bytes): {oct_result.hex()}\n")  # Expected: 000000ff

    # Test 3: Convert bits to integer
    print("Testing bits_to_int:")
    # Convert the byte string to an integer, with a specified bit length (qlen)
    bits = b"\xff\x00"
    qlen = 16
    bits_result = address.bits_to_int(bits, qlen)
    print(f"Bits {bits.hex()} to int (qlen=16): {bits_result}\n")  # Expected: 65280 (0xff00)

    # Test 4: Convert bits to octet string
    print("Testing bits_to_oct:")
    # Convert byte string to an octet string with parameters
    bits_oct_result = address.bits_to_oct(bits, 256, 16, 2)
    print(f"Bits {bits.hex()} to octet: {bits_oct_result.hex()}\n")  # Expected: Correct octet string based on parameters

    # Test 5: Validate checksum
    print("Testing valid_checksum:")
    # Create a checksum using SHA-256 hashing
    version = b"\x00"
    privkey = b"\x01\x02\x03\x04"
    checksum = address.sha256.double_sha256(version + privkey)[:4]
    print(f"Checksum valid: {address.valid_checksum(version, privkey, checksum)}\n")  # Expected: True

    # Test 6: WIF to integer
    print("Testing wif_to_int:")
    # Convert a private key to WIF and back to integer
    wif = address.private_key_to_WIF("403b3d4fcff56a92f335a0cf570e47bcb17b2a6b867b86a84704863d3a3c7437", compressed=False)
    privkey_int, compressed = address.wif_to_int(wif)
    print(f"WIF: {wif}")  # Wallet Import Format of the private key
    print(f"Private key integer: {privkey_int}")  # Integer representation of the private key
    print(f"Compressed: {compressed}\n")  # Whether the key is compressed

    # Test 7: Private key to public key points
    print("Testing private_key_to_public_key_points:")
    # Derive public key points from a private key
    private_key = 1
    public_key_x, public_key_y = address.private_key_to_public_key_points(private_key)
    print(f"Public Key X: {public_key_x}")
    print(f"Public Key Y: {public_key_y}")
    print(f"Public Key X (Hex): {hex(public_key_x)}")
    print(f"Public Key Y (Hex): {hex(public_key_y)}")
    print(f"On Curve?           {address.secp256k1.ecc.in_curve(public_key_x, public_key_y)}")
    print(f"Valid Private Key?  {address.secp256k1.ecc.is_valid_key(private_key)}\n")

    # Test 8: Private key to public key (compressed and uncompressed)
    print("Testing private_to_public:")
    # Convert private key to compressed and uncompressed public keys
    private_key_hex = "1"
    compressed_pubkey = address.private_to_public(private_key_hex, compressed=True)
    uncompressed_pubkey = address.private_to_public(private_key_hex, compressed=False)
    print(f"Compressed Public Key: {compressed_pubkey}")
    print(f"Uncompressed Public Key: {uncompressed_pubkey}\n")

    # Test 9: Public key to address
    print("Testing public_to_address:")
    # Generate an address from the compressed public key
    pubkey = compressed_pubkey
    generated_address = address.public_to_address(pubkey)
    print(f"Generated Address (Compressed): {generated_address}\n")

    # Test 10: Private key to WIF
    print("Testing private_key_to_WIF:")
    # Convert a private key to Wallet Import Format
    private_key_wif = address.private_key_to_WIF("798e2a22999e8b1ab02c2940eb72fdd048fabacfe78081caf902fca84d82e24c", compressed=True)
    print(f"WIF (Compressed): {private_key_wif}\n")
