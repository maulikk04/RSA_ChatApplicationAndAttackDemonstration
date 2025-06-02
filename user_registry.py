#!/usr/bin/env python3
"""
User Registry Module
Manages user registration, authentication, and key sharing
"""

import os
import json
import logging
from user_model import User
from password_manager import PasswordManager

logger = logging.getLogger(__name__)

class UserRegistry:
    """Manages user registration, authentication, and key sharing"""
    
    def __init__(self, data_dir="messaging_data"):
        """
        Initialize UserRegistry
        
        Args:
            data_dir (str): Directory to store user data and keys
        """
        self.data_dir = data_dir
        self.users_file = os.path.join(data_dir, "users.json")
        self.keys_dir = os.path.join(data_dir, "keys")
        self.users = {}
        self.public_keys = {}
        self.current_user = None
        self._last_mtime = 0  # Initialize modification time tracking
        
        # Create directories and load existing users
        self._create_directories()
        self._load_users()

    def _create_directories(self):
        """Create necessary directories for data storage"""
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            os.makedirs(self.keys_dir, exist_ok=True)
            logger.info(f"Created data directories: {self.data_dir}")
        except Exception as e:
            logger.error(f"Failed to create directories: {e}")
            raise

    def _load_users(self):
        """Load existing users from file"""
        try:
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r') as f:
                    data = json.load(f)
                    self.users = {}  # Clear existing users
                    for username, user_data in data.items():
                        user = User.from_dict(user_data)
                        self.users[username] = user
                
                # Rebuild public_keys dictionary from loaded users
                self._rebuild_public_keys()
                
                # Update modification time tracking
                self._last_mtime = os.path.getmtime(self.users_file)
                
                logger.info(f"Loaded {len(self.users)} existing users")
            else:
                logger.info("No existing users file found")
                self._last_mtime = 0
        except Exception as e:
            logger.error(f"Failed to load users: {e}")
            self.users = {}
            self.public_keys = {}
            self._last_mtime = 0

    def _rebuild_public_keys(self):
        """Rebuild the public_keys dictionary from current users"""
        self.public_keys = {}
        for username, user in self.users.items():
            if user.public_key:
                self.public_keys[username] = user.get_public_key_pem()

    def _refresh_users_from_file(self):
        """Refresh users data from file to get latest updates"""
        try:
            if os.path.exists(self.users_file):
                # Get current modification time
                current_mtime = os.path.getmtime(self.users_file)
                
                # If file has been updated since last load
                if current_mtime > self._last_mtime:
                    # Store current user before refresh
                    current_logged_user = self.current_user
                    
                    # Reload all user data
                    self._load_users()
                    
                    # Restore current user after refresh
                    self.current_user = current_logged_user
                    
                    logger.info("Refreshed user data from file")
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to refresh users: {e}")
            return False

    def _save_users(self):
        """Save users to file"""
        try:
            data = {username: user.to_dict() for username, user in self.users.items()}
            with open(self.users_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Update modification time tracking
            self._last_mtime = os.path.getmtime(self.users_file)
            logger.info("Users data saved successfully")
        except Exception as e:
            logger.error(f"Failed to save users: {e}")
            raise

    def register_user(self, username, password, email=None, key_size=2048):
        """
        Register a new user with password and RSA key generation
        
        Args:
            username (str): Unique username
            password (str): User's password
            email (str, optional): User's email address
            key_size (int): RSA key size in bits (default: 2048)
            
        Returns:
            User: The newly registered user
            
        Raises:
            ValueError: If username already exists or invalid input
        """
        try:
            # Validate input
            if not username or not username.strip():
                raise ValueError("Username cannot be empty")
            
            if not password or len(password) < 6:
                raise ValueError("Password must be at least 6 characters long")
            
            username = username.strip()
            
            # Refresh users to check for any new registrations
            self._refresh_users_from_file()
            
            if username in self.users:
                raise ValueError(f"User '{username}' already exists")
            
            # Hash password and create user
            password_hash = PasswordManager.hash_password(password)
            logger.info(f"Registering new user: {username}")
            user = User(username, password_hash, email)
            user.generate_keys(key_size)
            
            # Save user
            self.users[username] = user
            self.public_keys[username] = user.get_public_key_pem()
            
            # Save private key to file (encrypted with user password)
            private_key_file = os.path.join(self.keys_dir, f"{username}_private.pem")
            with open(private_key_file, 'wb') as f:
                f.write(user.get_private_key_pem(password))
            
            # Update users file
            self._save_users()
            
            logger.info(f"Successfully registered user: {username}")
            return user
            
        except Exception as e:
            logger.error(f"User registration failed: {e}")
            raise

    def login(self, username, password):
        """
        Authenticate user login
        
        Args:
            username (str): Username to login
            password (str): User's password
            
        Returns:
            tuple: (bool, str) - (Success status, password if successful)
            
        Raises:
            ValueError: If invalid username or password
        """
        try:
            username = username.strip()
            
            # Refresh users data to get latest registrations
            self._refresh_users_from_file()
            
            if username not in self.users:
                raise ValueError("Invalid username or password")
            
            user = self.users[username]
            
            if not user.verify_password(password):
                raise ValueError("Invalid username or password")
            
            # Update last login time
            user.update_last_login()
            self.current_user = username
            self._save_users()
            
            logger.info(f"User {username} logged in successfully")
            return True, password  # Return password for session key decryption
            
        except Exception as e:
            logger.error(f"Login failed: {e}")
            raise

    def logout(self):
        """
        Logout current user
        
        Returns:
            bool: True if logout successful, False if no user was logged in
        """
        if self.current_user:
            logger.info(f"User {self.current_user} logged out")
            self.current_user = None
            return True
        return False

    def is_logged_in(self):
        """
        Check if a user is currently logged in
        
        Returns:
            bool: True if a user is logged in, False otherwise
        """
        return self.current_user is not None

    def get_current_user(self):
        """
        Get current logged in user
        
        Returns:
            User or None: Current user object or None if not logged in
        """
        if self.current_user:
            # Always refresh before returning current user data
            self._refresh_users_from_file()
            return self.users.get(self.current_user)
        return None

    def get_user(self, username):
        """
        Get user by username
        
        Args:
            username (str): Username to retrieve
            
        Returns:
            User or None: User object or None if not found
        """
        # Refresh to get latest data
        self._refresh_users_from_file()
        return self.users.get(username)

    def get_all_users(self):
        """
        Get all registered users
        
        Returns:
            list: List of all usernames
        """
        # Refresh to get latest data
        self._refresh_users_from_file()
        return list(self.users.keys())

    def get_public_keys(self, exclude_user=None):
        """
        Get all public keys (optionally excluding a specific user)
        
        Args:
            exclude_user (str, optional): Username to exclude from results
            
        Returns:
            dict: Dictionary of username -> public_key_pem mappings
        """
        # Refresh to get latest data
        self._refresh_users_from_file()
        keys = self.public_keys.copy()
        if exclude_user and exclude_user in keys:
            del keys[exclude_user]
        return keys

    def update_public_keys_for_user(self, username):
        """
        Update public keys information for a specific user
        
        Args:
            username (str): Username to update keys for
            
        Returns:
            dict: Dictionary of other users' public keys
            
        Raises:
            ValueError: If user not found
        """
        # Refresh to get latest data
        self._refresh_users_from_file()
        
        if username not in self.users:
            raise ValueError(f"User '{username}' not found")
        
        other_keys = self.get_public_keys(exclude_user=username)
        logger.info(f"Updated public keys for {username}: {len(other_keys)} keys available")
        return other_keys

    def get_users_with_fresh_data(self):
        """
        Get all users with the most up-to-date data from file
        
        Returns:
            dict: Dictionary of username -> User object mappings
        """
        # Force refresh to get latest data
        self._refresh_users_from_file()
        return self.users.copy()
