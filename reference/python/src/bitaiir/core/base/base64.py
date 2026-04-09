class Base64:
    """
    A class for encoding and decoding data using the Base64 encoding scheme.
    """

    def __init__(self):
        """
        Initialize the Base64 character set.
        """
        self.base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    def encode(self, data: bytes | str) -> str:
        """
        Encode data into a Base64 string.

        Args:
            data (bytes | str): The data to be encoded. Can be bytes or a string.

        Returns:
            str: The Base64 encoded string.
        """
        # Ensure the input data is in bytes
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Convert data to binary format
        binary_data = ''.join(f'{byte:08b}' for byte in data)

        # Add padding to make the binary data a multiple of 6 bits
        padding = len(binary_data) % 6
        if padding:
            binary_data += '0' * (6 - padding)

        # Encode binary data into Base64 format
        encoded_data = ''.join(self.base64_chars[int(binary_data[i:i+6], 2)] for i in range(0, len(binary_data), 6))

        # Add padding '=' characters based on the length of the input data
        if len(data) % 3 == 1:
            encoded_data += "=="
        elif len(data) % 3 == 2:
            encoded_data += "="

        return encoded_data

    def decode(self, encoded_data: str) -> bytes:
        """
        Decode a Base64 string back into bytes.

        Args:
            encoded_data (str): The Base64 encoded string.

        Returns:
            bytes: The decoded byte sequence.
        """
        # Count and remove padding '=' characters
        padding = encoded_data.count('=')
        encoded_data = encoded_data.rstrip('=')

        # Convert Base64 characters back into binary format
        binary_data = ''.join(f'{self.base64_chars.index(c):06b}' for c in encoded_data)

        # Remove extra padding bits if they exist
        binary_data = binary_data[:-padding * 2] if padding else binary_data

        # Convert binary data back to bytes
        decoded_data = bytes(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8))

        return decoded_data


if __name__ == "__main__":
    # Initialize the Base64 class for encoding and decoding operations
    base64 = Base64()

    # Example data for encoding and decoding
    data = b"Hello, World!"  # Data as bytes

    # Encode the data to Base64
    encoded = base64.encode(data)

    # Decode the Base64 string back to bytes
    decoded = base64.decode(encoded)

    # Output the results with clear explanations
    print(f"Original Data (Bytes): {data}")  # The original data in byte format
    print(f"Encoded Data (Base64): {encoded}")  # The Base64 encoded representation of the data
    print(f"Decoded Data (Bytes):  {decoded}")  # The decoded data back to its original byte form

    # Verify if the decoded data matches the original data
    if data == decoded:
        print("Success: Decoded data matches the original data.")
    else:
        print("Error: Decoded data does not match the original data.")
