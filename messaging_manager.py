#!/usr/bin/env python3
"""
Messaging Manager Module
Handles encrypted messaging between users using RSA encryption
"""

import os
import json
import logging
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class MessageManager:
    """Manages encrypted messaging between users"""
    
    def __init__(self, data_dir="messaging_data"):
        """
        Initialize MessageManager
        
        Args:
            data_dir (str): Directory to store message data
        """
        self.data_dir = data_dir
        self.messages_dir = os.path.join(data_dir, "messages")
        self.messages_file = os.path.join(data_dir, "messages.json")
        self.messages = {}
        
        # Create directories and load existing messages
        self._create_directories()
        self._load_messages()
    
    def _create_directories(self):
        """Create necessary directories for message storage"""
        try:
            os.makedirs(self.messages_dir, exist_ok=True)
            logger.info(f"Created messages directory: {self.messages_dir}")
        except Exception as e:
            logger.error(f"Failed to create messages directory: {e}")
            raise
    
    def _load_messages(self):
        """Load existing messages from file"""
        try:
            if os.path.exists(self.messages_file):
                with open(self.messages_file, 'r') as f:
                    self.messages = json.load(f)
                logger.info(f"Loaded existing messages")
            else:
                logger.info("No existing messages file found")
                self.messages = {}
        except Exception as e:
            logger.error(f"Failed to load messages: {e}")
            self.messages = {}
    
    def _reload_messages(self):
        """Reload messages from file to get latest updates"""
        try:
            if os.path.exists(self.messages_file):
                with open(self.messages_file, 'r') as f:
                    self.messages = json.load(f)
                logger.debug("Messages reloaded from file")
            else:
                self.messages = {}
        except Exception as e:
            logger.error(f"Failed to reload messages: {e}")
            # Keep existing messages if reload fails
    
    def _save_messages(self):
        """Save messages to file"""
        try:
            with open(self.messages_file, 'w') as f:
                json.dump(self.messages, f, indent=2)
            logger.info("Messages saved successfully")
        except Exception as e:
            logger.error(f"Failed to save messages: {e}")
            raise
    
    def _get_conversation_key(self, user1, user2):
        """
        Generate a consistent conversation key for two users
        
        Args:
            user1 (str): First username
            user2 (str): Second username
            
        Returns:
            str: Conversation key
        """
        # Sort usernames to ensure consistent key regardless of order
        users = sorted([user1, user2])
        return f"{users[0]}_{users[1]}"
    
    def _encrypt_message(self, message, recipient_public_key_pem, sender_username):
        """
        Encrypt message using recipient's public key
        
        Args:
            message (str): Message to encrypt
            recipient_public_key_pem (bytes): Recipient's public key in PEM format
            sender_username (str): Username of the sender
            
        Returns:
            bytes: Encrypted message
            
        Raises:
            ValueError: If encryption fails
        """
        try:
            print(f"🔐 Encrypting message using {sender_username}'s recipient public key...")
            
            # Load recipient's public key
            public_key = serialization.load_pem_public_key(
                recipient_public_key_pem,
                backend=default_backend()
            )
            
            # Encrypt the message
            encrypted_message = public_key.encrypt(
                message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            print(f"✅ Message encrypted successfully!")
            return encrypted_message
            
        except Exception as e:
            logger.error(f"Message encryption failed: {e}")
            raise ValueError(f"Failed to encrypt message: {e}")
    
    def _decrypt_message(self, encrypted_message, private_key_pem, password, recipient_username):
        """
        Decrypt message using recipient's private key
        
        Args:
            encrypted_message (bytes): Encrypted message
            private_key_pem (bytes): Recipient's private key in PEM format
            password (str): Password to decrypt private key
            recipient_username (str): Username of the recipient
            
        Returns:
            str: Decrypted message
            
        Raises:
            ValueError: If decryption fails
        """
        try:
            print(f"🔓 Decrypting message using {recipient_username}'s private key...")
            
            # Load recipient's private key
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=password.encode('utf-8'),
                backend=default_backend()
            )
            
            # Decrypt the message
            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            print(f"✅ Message decrypted successfully!")
            return decrypted_message.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Message decryption failed: {e}")
            raise ValueError(f"Failed to decrypt message: {e}")
    
    def send_message(self, sender_username, recipient_username, message, recipient_public_key, sender_password=None):
        """
        Send an encrypted message from sender to recipient
        
        Args:
            sender_username (str): Username of the sender
            recipient_username (str): Username of the recipient
            message (str): Message to send
            recipient_public_key (bytes): Recipient's public key in PEM format
            sender_password (str, optional): Sender's password (for future use)
            
        Returns:
            bool: True if message sent successfully
            
        Raises:
            ValueError: If sending fails
        """
        try:
            if not message.strip():
                raise ValueError("Message cannot be empty")
            
            print(f"\n📤 Sending message from {sender_username} to {recipient_username}")
            
            # Reload messages before sending to ensure we have the latest state
            self._reload_messages()
            
            # Encrypt the message using recipient's public key
            encrypted_message = self._encrypt_message(message, recipient_public_key, sender_username)
            
            # Create message data - now storing both encrypted and original message
            message_data = {
                'sender': sender_username,
                'recipient': recipient_username,
                'encrypted_message': encrypted_message.hex(),  # Store as hex string for recipient
                'original_message': message,  # Store original message for sender's reference
                'timestamp': datetime.now().isoformat(),
                'message_id': len(self.messages) + 1
            }
            
            # Get conversation key
            conversation_key = self._get_conversation_key(sender_username, recipient_username)
            
            # Initialize conversation if it doesn't exist
            if conversation_key not in self.messages:
                self.messages[conversation_key] = []
            
            # Add message to conversation
            self.messages[conversation_key].append(message_data)
            
            # Save messages
            self._save_messages()
            
            print(f"✅ Message sent successfully to {recipient_username}!")
            logger.info(f"Message sent from {sender_username} to {recipient_username}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            raise ValueError(f"Failed to send message: {e}")
    
    def get_messages_for_user(self, username):
        """
        Get all messages for a specific user (both sent and received)
        
        Args:
            username (str): Username to get messages for
            
        Returns:
            list: List of message data dictionaries
        """
        # Reload messages to get the latest updates
        self._reload_messages()
        
        user_messages = []
        
        for conversation_key, messages in self.messages.items():
            # Check if user is part of this conversation
            if username in conversation_key.split('_'):
                user_messages.extend(messages)
        
        # Sort messages by timestamp
        user_messages.sort(key=lambda x: x['timestamp'])
        
        return user_messages
    
    def get_conversation(self, user1, user2):
        """
        Get conversation between two users
        
        Args:
            user1 (str): First username
            user2 (str): Second username
            
        Returns:
            list: List of message data dictionaries
        """
        # Reload messages to get the latest updates
        self._reload_messages()
        
        conversation_key = self._get_conversation_key(user1, user2)
        return self.messages.get(conversation_key, [])
    
    def decrypt_message_for_user(self, message_data, username, private_key_pem, password):
        """
        Decrypt a specific message for a user
        
        Args:
            message_data (dict): Message data dictionary
            username (str): Username of the person decrypting
            private_key_pem (bytes): User's private key in PEM format
            password (str): Password to decrypt private key
            
        Returns:
            str: Decrypted message
            
        Raises:
            ValueError: If user is not the recipient or decryption fails
        """
        try:
            # Check if user is the recipient
            if message_data['recipient'] != username:
                raise ValueError("You can only decrypt messages sent to you")
            
            # Get encrypted message from hex
            encrypted_message = bytes.fromhex(message_data['encrypted_message'])
            
            # Decrypt the message
            decrypted_message = self._decrypt_message(
                encrypted_message, 
                private_key_pem, 
                password, 
                username
            )
            
            return decrypted_message
            
        except Exception as e:
            logger.error(f"Failed to decrypt message for user {username}: {e}")
            raise ValueError(f"Failed to decrypt message: {e}")
    
    def get_message_content_for_user(self, message_data, username, private_key_pem=None, password=None):
        """
        Get message content for a user (either original if sender, or decrypt if recipient)
        
        Args:
            message_data (dict): Message data dictionary
            username (str): Username requesting the message
            private_key_pem (bytes, optional): User's private key in PEM format
            password (str, optional): Password to decrypt private key
            
        Returns:
            str: Message content
        """
        try:
            # If user is the sender, return the original message
            if message_data['sender'] == username:
                return message_data.get('original_message', '[Message content not available]')
            
            # If user is the recipient, decrypt the message
            elif message_data['recipient'] == username:
                if private_key_pem and password:
                    return self.decrypt_message_for_user(message_data, username, private_key_pem, password)
                else:
                    return '[Private key or password not provided for decryption]'
            
            # If user is neither sender nor recipient
            else:
                return '[You are not authorized to view this message]'
                
        except Exception as e:
            logger.error(f"Failed to get message content for user {username}: {e}")
            return f'[Failed to retrieve message: {e}]'
    
    def get_user_conversations(self, username):
        """
        Get list of users that have conversations with the specified user
        
        Args:
            username (str): Username to get conversations for
            
        Returns:
            list: List of usernames that have conversations with the user
        """
        # Reload messages to get the latest updates
        self._reload_messages()
        
        conversations = []
        
        for conversation_key in self.messages.keys():
            users = conversation_key.split('_')
            if username in users:
                # Add the other user in the conversation
                other_user = users[0] if users[1] == username else users[1]
                conversations.append(other_user)
        
        return list(set(conversations))  # Remove duplicates