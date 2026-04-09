from bitaiir.core.crypto.sha256 import SHA256


class HMACSHA256:
    """
    Implements HMAC-SHA256, a keyed-hash message authentication code using SHA-256.
    """

    def __init__(self, key: bytes):
        """
        Initialize the HMAC-SHA256 instance with a given key.

        Args:
            key (bytes): The secret key used for HMAC computation.
        """
        self.block_size = 64  # Block size for SHA-256
        self.hash_func = SHA256  # Hash function used
        self.key = self._prepare_key(key)

    def _prepare_key(self, key: bytes) -> bytes:
        """
        Prepares the key by adjusting its size to match the block size.

        Args:
            key (bytes): The input key.

        Returns:
            bytes: The prepared key, either truncated or padded to match the block size.
        """
        if len(key) > self.block_size:
            # Reduce the size of keys longer than the block size
            key = self.hash_func(key).digest()
        if len(key) < self.block_size:
            # Pad keys shorter than the block size with zero bytes
            key = key + b'\x00' * (self.block_size - len(key))
        return key

    def compute(self, message: bytes) -> bytes:
        """
        Computes the HMAC-SHA256 for the given message.

        Args:
            message (bytes): The input message to authenticate.

        Returns:
            bytes: The HMAC-SHA256 digest of the message.
        """
        # Initialize inner and outer pad constants
        ipad = bytes([0x36] * self.block_size)  # Inner padding (0x36)
        opad = bytes([0x5C] * self.block_size)  # Outer padding (0x5C)

        # XOR the key with the inner and outer pads
        key_ipad = bytes([k ^ i for k, i in zip(self.key, ipad)])
        key_opad = bytes([k ^ o for k, o in zip(self.key, opad)])

        # Perform the inner hash: H(key_ipad || message)
        inner_hash = self.hash_func(key_ipad + message).digest()

        # Perform the outer hash: H(key_opad || inner_hash)
        outer_hash = self.hash_func(key_opad + inner_hash).digest()

        return outer_hash


# Example usage
if __name__ == "__main__":
    # Secret key for HMAC
    key = 'shared_secret'.encode("utf-8")

    # Message to authenticate
    message = 'This is an important message.'.encode("utf-8")

    # Create HMAC-SHA256 instance
    hmac = HMACSHA256(key)

    # Compute HMAC
    hmac_result = hmac.compute(message)

    # Print the result in hexadecimal format
    print("HMAC (hex):", hmac_result.hex())
