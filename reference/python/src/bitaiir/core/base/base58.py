class Base58:
    """
    A class for encoding and decoding data using the Base58 encoding scheme.
    """

    def __init__(self):
        """
        Initialize the Base58 alphabet used for encoding and decoding.
        """
        self.ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    def encode(self, input_bytes: bytes) -> str:
        """
        Encode a sequence of bytes into a Base58 string.

        Args:
            input_bytes (bytes): The input data as bytes.

        Returns:
            str: The Base58 encoded string.
        """
        # Count the number of leading zero bytes
        leading_zeros = len(input_bytes) - len(input_bytes.lstrip(b'\x00'))

        # Convert the remaining bytes to an integer
        n = int.from_bytes(input_bytes, 'big')
        encoded = []

        # Perform Base58 encoding
        while n > 0:
            n, rem = divmod(n, 58)
            encoded.append(self.ALPHABET[rem])

        # Add leading zeros as '1'. The empty input encodes to the empty
        # string, matching the canonical Bitcoin Base58 behavior. Returning
        # '1' for an empty input would collide with the encoding of a single
        # zero byte and break round-tripping.
        return '1' * leading_zeros + ''.join(reversed(encoded))

    def decode(self, base58_str: str) -> bytes:
        """
        Decode a Base58 string back into bytes.

        Args:
            base58_str (str): The Base58 encoded string.

        Returns:
            bytes: The decoded byte sequence.
        """
        # Map each Base58 character to its index
        base58_map = {char: index for index, char in enumerate(self.ALPHABET)}

        # Convert the Base58 string to an integer
        n = 0
        for char in base58_str:
            n *= 58
            n += base58_map[char]

        # Calculate the number of bytes needed to represent the integer
        byte_length = (n.bit_length() + 7) // 8

        # Convert the integer back to bytes
        decoded_bytes = n.to_bytes(byte_length, 'big')

        # Count the number of leading '1' characters in the Base58 string
        leading_zeros = len(base58_str) - len(base58_str.lstrip('1'))

        # Add leading zero bytes to match the original data
        return b'\x00' * leading_zeros + decoded_bytes


if __name__ == "__main__":
    # Initialize the Base58 class for encoding and decoding operations
    base58 = Base58()

    # Example Base58 wallet address
    wallet = "1Mg4MNgCZ2LFH8GBfjYNpKyGWwVxA43eUR"

    # Decode the Base58 wallet address to its raw byte format
    wallet_decode = base58.decode(wallet)

    # Re-encode the decoded bytes back to Base58 to verify consistency
    wallet_encode = base58.encode(wallet_decode)

    # Output the results with clear explanations
    print(f"Original Wallet Address (Base58): {wallet}")  # The initial wallet address in Base58
    print(f"Decoded Bytes (Hex):              {wallet_decode.hex()}")  # The raw byte representation of the address
    print(f"Re-encoded Wallet Address:        {wallet_encode}")  # The re-encoded Base58 wallet address

    # Verify if the re-encoded address matches the original address
    if wallet == wallet_encode:
        print("Success: Re-encoded address matches the original wallet address.")
    else:
        print("Error: Re-encoded address does not match the original wallet address.")
