import struct


class SHA256:
    """
    A Python implementation of the SHA-256 hashing algorithm
    """

    # Constants for SHA-256
    _k = (
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    )
    _h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    def __init__(self, message: bytes = None):
        """
        Initializes the SHA-256 hashing context.

        Args:
            message (bytes, optional): The initial message to hash. Defaults to None.
        """
        self._buffer = b""
        self._counter = 0
        self._digest = list(self._h)
        if message:
            self.update(message)

    def _rotr(self, x: int, n: int) -> int:
        """
        Rotate a 32-bit integer x to the right by n bits.

        Args:
            x (int): The integer to rotate.
            n (int): The number of bits to rotate.

        Returns:
            int: The rotated integer.
        """
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def _process_block(self, chunk: bytes):
        """
        Process a 64-byte block of data.

        Args:
            chunk (bytes): The block of data to process.
        """
        w = list(struct.unpack("!16L", chunk)) + [0] * 48
        for i in range(16, 64):
            s0 = self._rotr(w[i - 15], 7) ^ self._rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = self._rotr(w[i - 2], 17) ^ self._rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = self._digest
        for i in range(64):
            s1 = self._rotr(e, 6) ^ self._rotr(e, 11) ^ self._rotr(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + s1 + ch + self._k[i] + w[i]) & 0xFFFFFFFF
            s0 = self._rotr(a, 2) ^ self._rotr(a, 13) ^ self._rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        self._digest = [(x + y) & 0xFFFFFFFF for x, y in zip(self._digest, [a, b, c, d, e, f, g, h])]

    def update(self, message: bytes):
        """
        Updates the hash object with new data.

        Args:
            message (bytes): The data to update the hash with.
        """
        if isinstance(message, str):
            message = message.encode("utf-8")
        self._buffer += message
        self._counter += len(message)
        while len(self._buffer) >= 64:
            self._process_block(self._buffer[:64])
            self._buffer = self._buffer[64:]

    def digest(self) -> bytes:
        """
        Returns the binary (raw) digest of the hashed data.

        Returns:
            bytes: The binary digest.
        """
        padding = b"\x80" + b"\x00" * ((55 - self._counter % 64) % 64)
        bit_length = struct.pack("!Q", self._counter * 8)
        self.update(padding + bit_length)
        return b"".join(struct.pack("!L", h) for h in self._digest)

    def hexdigest(self) -> str:
        """
        Returns the hexadecimal representation of the digest.

        Returns:
            str: The hexadecimal digest.
        """
        return self.digest().hex()

    @staticmethod
    def sha256(data: bytes) -> bytes:
        """
        Computes the SHA-256 hash of the given data.

        Args:
            data (bytes): The data to hash.

        Returns:
            bytes: The SHA-256 hash of the data.
        """
        return SHA256(data).digest()

    @staticmethod
    def double_sha256(data: bytes) -> bytes:
        """
        Computes the double SHA-256 hash of the given data.

        Args:
            data (bytes): The data to hash.

        Returns:
            bytes: The double SHA-256 hash of the data.
        """
        return SHA256(SHA256(data).digest()).digest()


if __name__ == "__main__":
    # Example data to hash
    data = b"example data to hash"

    # Single SHA-256 hash
    hash1 = SHA256.sha256(data)
    
    # Double SHA-256 hash (commonly used in Bitcoin and other blockchain technologies)
    hash2 = SHA256.double_sha256(data)

    # Print the results in a formatted way
    print("SHA-256 Example")
    print("================")
    print(f"Input Data:        {data.decode('utf-8')}")
    print(f"SHA-256 Hash:      {hash1.hex()}")
    print(f"Double SHA-256:    {hash2.hex()}")
    print()

    # Test with an empty input
    empty_data = b""
    empty_hash = SHA256.sha256(empty_data)

    print("SHA-256 Empty Input Example")
    print("===========================")
    print(f"Input Data:        <empty>")
    print(f"SHA-256 Hash:      {empty_hash.hex()}")
    print()

    # Test with a longer input
    long_data = b"a" * 1000
    long_hash = SHA256.sha256(long_data)

    print("SHA-256 Long Input Example")
    print("==========================")
    print(f"Input Data:        {'a' * 20}... (1000 characters)")
    print(f"SHA-256 Hash:      {long_hash.hex()}")
