#!/usr/bin/env python3
"""
User Model Module
Defines the User class and related data structures
"""

import logging
from datetime import datetime
from password_manager import PasswordManager
from rsa_key_manager import RSAKeyManager

logger = logging.getLogger(__name__)

class User:
    """Represents a user in the messaging system"""
    
    def __init__(self, username, password_hash, email=None):
        """
        Initialize a new user
        
        Args:
            username (str): Unique username
            password_hash (bytes): Hashed password
            email (str, optional): User's email address
        """
        self.username = username
        self.password_hash = password_hash
        self.email = email
        self.private_key = None
        self.public_key = None
        self.registration_time = datetime.now()
        self.last_key_update = None
        self.last_login = None
        
    def generate_keys(self, key_size=2048):
        """
        Generate RSA key pair for the user
        
        Args:
            key_size (int): Size of the RSA key in bits (default: 2048)
            
        Raises:
            Exception: If key generation fails
        """
        try:
            logger.info(f"Generating RSA key pair for user: {self.username}")
            self.private_key, self.public_key = RSAKeyManager.generate_key_pair(key_size)
            self.last_key_update = datetime.now()
            logger.info(f"Successfully generated {key_size}-bit RSA keys for {self.username}")
        except Exception as e:
            logger.error(f"Key generation failed for {self.username}: {e}")
            raise

    def verify_password(self, password):
        """
        Verify user password
        
        Args:
            password (str): Password to verify
            
        Returns:
            bool: True if password is correct, False otherwise
        """
        return PasswordManager.verify_password(password, self.password_hash)

    def update_last_login(self):
        """Update last login time to current time"""
        self.last_login = datetime.now()

    def get_public_key_pem(self):
        """
        Get public key in PEM format
        
        Returns:
            bytes: Public key in PEM format
            
        Raises:
            ValueError: If no public key is available
        """
        if not self.public_key:
            raise ValueError("No public key available")
        return RSAKeyManager.serialize_public_key(self.public_key)

    def get_private_key_pem(self, password=None):
        """
        Get private key in PEM format
        
        Args:
            password (str, optional): Password to encrypt the private key
            
        Returns:
            bytes: Private key in PEM format
            
        Raises:
            ValueError: If no private key is available
        """
        if not self.private_key:
            raise ValueError("No private key available")
        return RSAKeyManager.serialize_private_key(self.private_key, password)

    def to_dict(self):
        """
        Convert user to dictionary (excluding private key for security)
        
        Returns:
            dict: User data as dictionary
        """
        return {
            'username': self.username,
            'password_hash': self.password_hash.hex(),  # Store as hex string
            'email': self.email,
            'public_key_pem': self.get_public_key_pem().decode('utf-8') if self.public_key else None,
            'registration_time': self.registration_time.isoformat(),
            'last_key_update': self.last_key_update.isoformat() if self.last_key_update else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

    @classmethod
    def from_dict(cls, data):
        """
        Create User instance from dictionary data
        
        Args:
            data (dict): User data dictionary
            
        Returns:
            User: New User instance
        """
        # Convert hex string back to bytes
        password_hash = bytes.fromhex(data['password_hash'])
        user = cls(data['username'], password_hash, data.get('email'))
        
        # Set timestamps
        user.registration_time = datetime.fromisoformat(data['registration_time'])
        
        if data.get('last_key_update'):
            user.last_key_update = datetime.fromisoformat(data['last_key_update'])
        
        if data.get('last_login'):
            user.last_login = datetime.fromisoformat(data['last_login'])
        
        # Load public key if available
        if data.get('public_key_pem'):
            user.public_key = RSAKeyManager.load_public_key(
                data['public_key_pem'].encode('utf-8')
            )
        
        return user