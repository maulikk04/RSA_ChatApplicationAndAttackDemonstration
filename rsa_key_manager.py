#!/usr/bin/env python3
"""
RSA Key Management Module
Handles RSA key generation, serialization, and loading operations
Supports manual key generation for educational purposes (smaller key sizes)
"""

import logging
import random
import math
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers

logger = logging.getLogger(__name__)

class RSAKeyManager:
    """Handles RSA key generation, serialization, and validation"""
    
    @staticmethod
    def _is_prime(n, k=10):
        """
        Miller-Rabin primality test
        
        Args:
            n (int): Number to test
            k (int): Number of rounds (default: 10)
            
        Returns:
            bool: True if n is probably prime, False if composite
        """
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n-1 as d * 2^r
        r = 0
        d = n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Perform k rounds of testing
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
                
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    @staticmethod
    def _generate_prime(bits):
        """
        Generate a prime number with specified bit length
        
        Args:
            bits (int): Desired bit length
            
        Returns:
            int: A prime number
        """
        while True:
            # Generate a random odd number with the desired bit length
            candidate = random.getrandbits(bits)
            # Ensure it's odd and has the right bit length
            candidate |= (1 << bits - 1) | 1
            
            if RSAKeyManager._is_prime(candidate):
                return candidate
    
    @staticmethod
    def _extended_gcd(a, b):
        """
        Extended Euclidean Algorithm
        
        Args:
            a, b (int): Input integers
            
        Returns:
            tuple: (gcd, x, y) where gcd = ax + by
        """
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = RSAKeyManager._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    
    @staticmethod
    def _mod_inverse(e, phi_n):
        """
        Calculate modular multiplicative inverse
        
        Args:
            e (int): Public exponent
            phi_n (int): Euler's totient function result
            
        Returns:
            int: Modular inverse of e modulo phi_n
            
        Raises:
            ValueError: If inverse doesn't exist
        """
        gcd, x, _ = RSAKeyManager._extended_gcd(e, phi_n)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return x % phi_n
    
    @staticmethod
    def _generate_manual_rsa_keys(key_size, public_exponent=65537):
        """
        Manually generate RSA key pair for educational purposes
        
        Args:
            key_size (int): Size of the RSA key in bits
            public_exponent (int): Public exponent e (default: 65537)
            
        Returns:
            tuple: (private_key_object, public_key_object)
        """
        logger.warning(f"Generating {key_size}-bit RSA keys manually for educational purposes")
        
        while True:  # Keep trying until we find suitable primes
            try:
                # Step 1: Generate two distinct prime numbers
                p_bits = key_size // 2
                q_bits = key_size - p_bits
                
                # Generate primes that satisfy: gcd(e, p-1) = 1 and gcd(e, q-1) = 1
                while True:
                    p = RSAKeyManager._generate_prime(p_bits)
                    if math.gcd(public_exponent, p - 1) == 1:
                        break
                
                while True:
                    q = RSAKeyManager._generate_prime(q_bits)
                    if q != p and math.gcd(public_exponent, q - 1) == 1:
                        break
                
                # Step 2: Compute n = p * q
                n = p * q
                
                # Step 3: Compute Euler's totient function
                phi_n = (p - 1) * (q - 1)
                
                # Step 4: Verify public exponent e is coprime with phi_n
                if math.gcd(public_exponent, phi_n) != 1:
                    continue  # Try again with new primes
                
                # Step 5: Compute private exponent d
                d = RSAKeyManager._mod_inverse(public_exponent, phi_n)
                
                # Step 6: Compute CRT parameters
                dmp1 = d % (p - 1)
                dmq1 = d % (q - 1)
                iqmp = RSAKeyManager._mod_inverse(q, p)
                
                # Create RSA key objects using cryptography library structures
                public_numbers = RSAPublicNumbers(public_exponent, n)
                private_numbers = RSAPrivateNumbers(
                    p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp,
                    public_numbers=public_numbers
                )
                
                private_key = private_numbers.private_key()
                public_key = private_key.public_key()
                
                logger.info(f"Successfully generated {key_size}-bit RSA keys manually")
                logger.info(f"Key parameters: p={p_bits} bits, q={q_bits} bits, n={n.bit_length()} bits, e={public_exponent}")
                
                return private_key, public_key
                
            except Exception as e:
                if "inverse does not exist" in str(e):
                    continue  # Try again with new primes
                raise
    
    @staticmethod
    def generate_key_pair(key_size=2048, public_exponent=65537):
        """
        Generate RSA key pair
        
        Args:
            key_size (int): Size of the RSA key in bits (default: 2048)
            public_exponent (int): Public exponent e (default: 65537)
            
        Returns:
            tuple: (private_key, public_key)
            
        Raises:
            Exception: If key generation fails
        """
        try:
            # For educational purposes, allow smaller key sizes with manual generation
            if key_size < 1024:
                logger.warning(f"Using manual RSA key generation for {key_size}-bit keys")
                logger.warning("Small key sizes are INSECURE and for educational use only!")
                return RSAKeyManager._generate_manual_rsa_keys(key_size, public_exponent)
            
            # Use the standard library for secure key sizes
            private_key = rsa.generate_private_key(
                public_exponent=public_exponent,
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

    @staticmethod
    def get_key_parameters(public_key):
        """
        Extract RSA key parameters for analysis
        
        Args:
            public_key: RSA public key object
            
        Returns:
            dict: Dictionary containing n, e, and key size
        """
        try:
            public_numbers = public_key.public_numbers()
            return {
                'n': public_numbers.n,
                'e': public_numbers.e,
                'key_size': public_numbers.n.bit_length()
            }
        except Exception as e:
            logger.error(f"Failed to extract key parameters: {e}")
            raise
