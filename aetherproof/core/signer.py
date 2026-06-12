"""Ed25519 signing and key management."""

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from typing import Tuple, Optional
import os
import json


class Signer:
    """Ed25519 signer for receipts. R0 root depth (software key)."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey):
        """Initialize with an Ed25519 private key.

        Args:
            private_key: cryptography Ed25519PrivateKey instance
        """
        self.private_key = private_key
        self.public_key = private_key.public_key()

    @classmethod
    def generate(cls) -> "Signer":
        """Generate a new random Ed25519 keypair.

        Returns:
            New Signer instance
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        return cls(private_key)

    @classmethod
    def from_private_pem(cls, pem_bytes: bytes, password: Optional[bytes] = None) -> "Signer":
        """Load from PEM-encoded private key.

        Args:
            pem_bytes: PEM data
            password: encryption password if key is encrypted

        Returns:
            Signer instance
        """
        private_key = serialization.load_pem_private_key(
            pem_bytes, password=password, backend=default_backend()
        )
        return cls(private_key)

    @classmethod
    def from_private_file(cls, file_path: str, password: Optional[bytes] = None) -> "Signer":
        """Load from a PEM file.

        Args:
            file_path: path to private key file
            password: encryption password if key is encrypted

        Returns:
            Signer instance
        """
        with open(file_path, "rb") as f:
            pem_bytes = f.read()
        return cls.from_private_pem(pem_bytes, password)

    def sign(self, message: bytes) -> str:
        """Sign a message with the private key.

        Args:
            message: bytes to sign (typically receipt fields in order)

        Returns:
            Hex-encoded Ed25519 signature
        """
        signature = self.private_key.sign(message)
        return signature.hex()

    def sign_message(self, message: str) -> str:
        """Sign a string message.

        Args:
            message: string to sign

        Returns:
            Hex-encoded Ed25519 signature
        """
        return self.sign(message.encode("utf-8"))

    def export_private_pem(self, password: Optional[bytes] = None) -> bytes:
        """Export private key as PEM.

        Args:
            password: optional encryption password

        Returns:
            PEM-encoded bytes
        """
        if password:
            encryption = serialization.BestAvailableEncryption(password)
        else:
            encryption = serialization.NoEncryption()

        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

    def export_public_pem(self) -> bytes:
        """Export public key as PEM.

        Returns:
            PEM-encoded bytes
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def export_private_file(self, file_path: str, password: Optional[bytes] = None) -> None:
        """Save private key to PEM file.

        Args:
            file_path: where to save
            password: optional encryption password
        """
        with open(file_path, "wb") as f:
            f.write(self.export_private_pem(password))

    def export_public_file(self, file_path: str) -> None:
        """Save public key to PEM file.

        Args:
            file_path: where to save
        """
        with open(file_path, "wb") as f:
            f.write(self.export_public_pem())

    def get_public_key(self) -> "Verifier":
        """Get the corresponding Verifier (public key).

        Returns:
            Verifier instance
        """
        return Verifier(self.public_key)

    def __repr__(self) -> str:
        pub_hex = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()[:16]
        return f"Signer(public_key={pub_hex}...)"


class Verifier:
    """Ed25519 verifier for receipts (public key only)."""

    def __init__(self, public_key: ed25519.Ed25519PublicKey):
        """Initialize with an Ed25519 public key.

        Args:
            public_key: cryptography Ed25519PublicKey instance
        """
        self.public_key = public_key

    @classmethod
    def from_public_pem(cls, pem_bytes: bytes) -> "Verifier":
        """Load from PEM-encoded public key.

        Args:
            pem_bytes: PEM data

        Returns:
            Verifier instance
        """
        public_key = serialization.load_pem_public_key(pem_bytes, backend=default_backend())
        return cls(public_key)

    @classmethod
    def from_public_file(cls, file_path: str) -> "Verifier":
        """Load from a PEM file.

        Args:
            file_path: path to public key file

        Returns:
            Verifier instance
        """
        with open(file_path, "rb") as f:
            pem_bytes = f.read()
        return cls.from_public_pem(pem_bytes)

    def verify(self, message: bytes, signature_hex: str) -> bool:
        """Verify a signature.

        Args:
            message: original bytes
            signature_hex: hex-encoded Ed25519 signature

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            signature = bytes.fromhex(signature_hex)
            self.public_key.verify(signature, message)
            return True
        except Exception:
            return False

    def verify_message(self, message: str, signature_hex: str) -> bool:
        """Verify a string message signature.

        Args:
            message: original string
            signature_hex: hex-encoded signature

        Returns:
            True if signature is valid
        """
        return self.verify(message.encode("utf-8"), signature_hex)

    def export_public_pem(self) -> bytes:
        """Export public key as PEM.

        Returns:
            PEM-encoded bytes
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def export_public_file(self, file_path: str) -> None:
        """Save public key to PEM file.

        Args:
            file_path: where to save
        """
        with open(file_path, "wb") as f:
            f.write(self.export_public_pem())

    def __repr__(self) -> str:
        pub_hex = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()[:16]
        return f"Verifier(public_key={pub_hex}...)"
