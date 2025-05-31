#!/usr/bin/env python3
"""
RSA Key Management Module
Handles RSA key generation, serialization, and loading operations
"""

import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

class RSAKeyManager:
    """Handles RSA key generation, serialization, and validation"""
    
    @staticmethod
    def generate_key_pair(key_size=2048):
        """
        Generate RSA key pair
        
        Args:
            key_size (int): Size of the RSA key in bits (default: 2048)
            
        Returns:
            tuple: (private_key, public_key)
            
        Raises:
            Exception: If key generation fails
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            public_key = private_key.public_key()
            return private_key, public_key
        except Exception as e:
            logger.error(f"Failed to generate RSA key pair: {e}")
            raise

    @staticmethod
    def serialize_private_key(private_key, password=None):
        """
        Serialize private key to PEM format
        
        Args:
            private_key: RSA private key object
            password (str, optional): Password to encrypt the private key
            
        Returns:
            bytes: Serialized private key in PEM format
            
        Raises:
            Exception: If serialization fails
        """
        try:
            encryption = serialization.NoEncryption()
            if password:
                encryption = serialization.BestAvailableEncryption(password.encode())
            
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            )
        except Exception as e:
            logger.error(f"Failed to serialize private key: {e}")
            raise

    @staticmethod
    def serialize_public_key(public_key):
        """
        Serialize public key to PEM format
        
        Args:
            public_key: RSA public key object
            
        Returns:
            bytes: Serialized public key in PEM format
            
        Raises:
            Exception: If serialization fails
        """
        try:
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except Exception as e:
            logger.error(f"Failed to serialize public key: {e}")
            raise

    @staticmethod
    def load_private_key(pem_data, password=None):
        """
        Load private key from PEM data
        
        Args:
            pem_data (bytes): PEM-encoded private key data
            password (str, optional): Password for encrypted private key
            
        Returns:
            RSA private key object
            
        Raises:
            Exception: If loading fails
        """
        try:
            return serialization.load_pem_private_key(
                pem_data,
                password=password.encode() if password else None
            )
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            raise

    @staticmethod
    def load_public_key(pem_data):
        """
        Load public key from PEM data
        
        Args:
            pem_data (bytes): PEM-encoded public key data
            
        Returns:
            RSA public key object
            
        Raises:
            Exception: If loading fails
        """
        try:
            return serialization.load_pem_public_key(pem_data)
        except Exception as e:
            logger.error(f"Failed to load public key: {e}")
            raise