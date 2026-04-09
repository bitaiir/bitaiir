from bitaiir.core.signature.signature import SignatureAlgorithm
from bitaiir.core.crypto.secp256k1 import Secp256k1
from bitaiir.core.address.address import Address
import secrets


class Wallet:
    """
    Class to manage wallets for the BitAiir blockchain, including the 
    generation of private keys, public keys, and addresses in both 
    compressed and uncompressed formats. Provides signing and 
    verification of messages.
    """

    def __init__(self):
        """
        Initializes the required cryptographic components for key generation,
        address conversion, and signing.
        """
        self.KEY_BYTES = 32  # Private key size: 256 bits (32 bytes)
        self.signatureAlgorithm = SignatureAlgorithm()  # Signing algorithm
        self.address = Address()  # Address conversion utilities
        self.secp256k1 = Secp256k1()  # Secp256k1 elliptic curve implementation

    def generate_integer(self) -> int:
        """
        Generates a cryptographically secure random integer within the 
        range of the Secp256k1 curve.

        Returns:
            int: A secure random integer less than the curve's prime order.
        """
        return secrets.randbelow(self.secp256k1.curve.n_curve)

    def generate_private_key(self) -> str:
        """
        Generates a secure 256-bit (32-byte) private key.

        Returns:
            str: The generated private key in hexadecimal format.
        """
        private_key = secrets.token_bytes(self.KEY_BYTES)  # Generate secure bytes
        return private_key.hex()

    def sign(self, wif: str, message: str, deterministic: bool = True) -> str:
        """
        Signs a message using the private key in WIF format.

        Args:
            wif (str): The private key in Wallet Import Format (WIF).
            message (str): The message to be signed.
            deterministic (bool, optional): Determines if the signature is 
                deterministic. Defaults to True.

        Returns:
            str: The signature of the message in hexadecimal format.
        """
        return self.signatureAlgorithm.sign_message(wif, message, deterministic)

    def verify_signature(self, address: str, message: str, signature: str) -> bool:
        """
        Verifies the signature of a message.

        Args:
            address (str): The public address used to verify the signature.
            message (str): The original message that was signed.
            signature (str): The message signature in hexadecimal format.

        Returns:
            bool: True if the signature is valid, otherwise False.
        """
        return self.signatureAlgorithm.verify_message(address, message, signature)

    def generate_wallet(self) -> dict:
        """
        Generates a wallet containing:
        - Private key
        - Public keys (compressed and uncompressed)
        - Addresses (compressed and uncompressed)
        - WIF formats for both types of keys

        Returns:
            dict: A dictionary containing the wallet's private key, 
                  public keys, addresses, and WIFs in both compressed 
                  and uncompressed formats.
        """
        private_key = self.generate_private_key()
        
        # Uncompressed public key and address
        public_key_uncompressed = self.address.private_to_public(private_key, compressed=False)
        address_uncompressed = self.address.public_to_address(public_key_uncompressed)
        wif_uncompressed = self.address.private_key_to_WIF(private_key, compressed=False)
        
        # Compressed public key and address
        public_key_compressed = self.address.private_to_public(private_key, compressed=True)
        address_compressed = self.address.public_to_address(public_key_compressed)
        wif_compressed = self.address.private_key_to_WIF(private_key, compressed=True)
        
        return {
            "private_key": private_key,
            "public_key_uncompressed": public_key_uncompressed,
            "public_key_compressed": public_key_compressed,
            "address_uncompressed": address_uncompressed,
            "address_compressed": address_compressed,
            "wif_uncompressed": wif_uncompressed,
            "wif_compressed": wif_compressed
        }


if __name__ == "__main__":
    # Initialize the Wallet class for generating and handling wallet data
    wallet = Wallet()

    # Generate a new wallet and retrieve its details
    generated_wallet = wallet.generate_wallet()

    # Extract wallet data
    private_key = generated_wallet["private_key"]
    public_key_uncompressed = generated_wallet["public_key_uncompressed"]
    public_key_compressed = generated_wallet["public_key_compressed"]
    address_uncompressed = generated_wallet["address_uncompressed"]
    address_compressed = generated_wallet["address_compressed"]
    wif_uncompressed = generated_wallet["wif_uncompressed"]
    wif_compressed = generated_wallet["wif_compressed"]

    # Output the generated wallet details
    print(f"Private Key:                {private_key}")
    print(f"Public Key (Uncompressed):  {public_key_uncompressed}")
    print(f"Public Key (Compressed):    {public_key_compressed}")
    print(f"Address (Uncompressed):     {address_uncompressed}")
    print(f"Address (Compressed):       {address_compressed}")
    print(f"WIF (Uncompressed):         {wif_uncompressed}")
    print(f"WIF (Compressed):           {wif_compressed}\n")

    # Test signature and verification with uncompressed key
    print("Testing signature with uncompressed key:")
    deterministic = True
    message = "ECDSA is the most fun I have ever experienced"
    address, message_signed, signature = wallet.sign(wif_uncompressed, message, deterministic)
    is_valid, public_key, verify_message = wallet.verify_signature(address_uncompressed, message, signature)

    # Output results of signature and verification
    print(f"Signature:                  {signature}")
    print(f"Signature Valid:            {is_valid}\n")

    # Test signature and verification with compressed key
    print("Testing signature with compressed key:")
    deterministic = True
    address, message_signed, signature = wallet.sign(wif_compressed, message, deterministic)
    is_valid, public_key, verify_message = wallet.verify_signature(address_compressed, message, signature)

    # Output results of signature and verification
    print(f"Signature:                  {signature}")
    print(f"Signature Valid:            {is_valid}")
