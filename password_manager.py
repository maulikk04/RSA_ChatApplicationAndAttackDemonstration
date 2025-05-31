#!/usr/bin/env python3
"""
Password Management Module
Handles password hashing and verification using PBKDF2 with SHA-256
"""

import os
import hashlib
import logging

logger = logging.getLogger(__name__)

class PasswordManager:
    """Handles password hashing and verification"""
    
    @staticmethod
    def hash_password(password, salt=None):
        """
        Hash password with salt using SHA-256
        
        Args:
            password (str): Plain text password
            salt (bytes, optional): Salt for hashing. If None, generates new salt
            
        Returns:
            bytes: Salt + hashed password
        """
        if salt is None:
            salt = os.urandom(32)  # 32 bytes = 256 bits
        
        # Hash password with salt using PBKDF2
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode('utf-8'), 
            salt, 
            100000  # 100,000 iterations
        )
        return salt + pwd_hash
    
    @staticmethod
    def verify_password(password, hashed_password):
        """
        Verify password against hash
        
        Args:
            password (str): Plain text password to verify
            hashed_password (bytes): Stored password hash (salt + hash)
            
        Returns:
            bool: True if password matches, False otherwise
        """
        # Extract salt (first 32 bytes)
        salt = hashed_password[:32]
        stored_hash = hashed_password[32:]
        
        # Hash the provided password with the same salt
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        
        # Compare hashes
        return pwd_hash == stored_hash