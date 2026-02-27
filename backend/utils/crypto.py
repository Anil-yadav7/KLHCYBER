"""Cryptographic utilities for the BreachShield platform.

Provides encryption, decryption, and hashing functions to ensure sensitive
personal data, such as email addresses, are never stored in plaintext within
the database.
"""

import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken

from ..config.settings import settings

logger = logging.getLogger(__name__)

# Initialize the Fernet symmetric encryption module using the configured secret key.
# The key must be a URL-safe base64-encoded 32-byte key.
_fernet = Fernet(settings.ENCRYPTION_KEY.encode())


def encrypt_email(email: str) -> str:
    """Encrypt a normalized email address using symmetric cryptography.
    
    Args:
        email: The plaintext email address.
        
    Returns:
        The URL-safe base64-encoded encrypted payload as a string.
    """
    normalized: str = email.lower().strip()
    encrypted_bytes: bytes = _fernet.encrypt(normalized.encode("utf-8"))
    
    logger.debug("Email encrypted successfully")
    return encrypted_bytes.decode("utf-8")


def decrypt_email(encrypted_email: str) -> str:
    """Decrypt an encrypted email string back to its normalized plaintext form.
    
    Args:
        encrypted_email: The base64-encoded encrypted payload.
        
    Returns:
        The decoded plaintext email address.
        
    Raises:
        ValueError: If decryption fails due to an invalid or tampered token.
    """
    try:
        decrypted_bytes: bytes = _fernet.decrypt(encrypted_email.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except InvalidToken:
        logger.error("Failed to decrypt email record. Token is invalid or tampered.")
        raise ValueError("Decryption failed — invalid token")


def hash_email(email: str) -> str:
    """Generate a deterministic SHA-256 hash of a normalized email address.
    
    This hash operates as a secure, fast lookup mechanism in the database
    to prevent duplicate entries or query encrypted blobs directly.
    
    Args:
        email: The plaintext email address.
        
    Returns:
        The standard hexadecimal string representation of the hash.
    """
    normalized: str = email.lower().strip()
    hash_obj = hashlib.sha256(normalized.encode("utf-8"))
    return hash_obj.hexdigest()


def generate_email_preview(email: str) -> str:
    """Construct an obfuscated preview of an email address for safe UI display.
    
    Args:
        email: The plaintext email address.
        
    Returns:
        The partially masked email address (e.g., 'joh***@gmail.com').
    """
    local_part, domain = email.split("@", 1)
    
    if len(local_part) <= 3:
        preview: str = local_part[:1] + "***"
    else:
        preview: str = local_part[:3] + "***"
        
    return f"{preview}@{domain}"


def generate_fernet_key() -> str:
    """Utility to generate a pristine, valid Fernet key for environment setup.
    
    Returns:
        A randomly generated, valid URL-safe base64-encoded 32-byte key.
    """
    return Fernet.generate_key().decode("utf-8")
