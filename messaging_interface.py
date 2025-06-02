#!/usr/bin/env python3
"""
Messaging Interface Module
Handles CLI interactions for messaging functionality with double encryption
"""

import os
import getpass
import logging
from datetime import datetime
from messaging_manager import MessageManager
from display_utils import print_success, print_error
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class MessagingInterface:
    """Handles CLI interactions for messaging"""
    
    def __init__(self, user_registry, data_dir="messaging_data"):
        """
        Initialize MessagingInterface
        
        Args:
            user_registry (UserRegistry): The user registry instance
            data_dir (str): Directory to store message data
        """
        self.registry = user_registry
        self.message_manager = MessageManager(data_dir)
        # Store both the PEM and decrypted private key
        self._session_private_key = None
        self._session_decrypted_key = None
        self._user_password = None

    def initialize_session(self, username, password):
        """Initialize session with user's login password"""
        try:
            # Load and decrypt private key at login
            private_key_file = os.path.join(self.registry.keys_dir, f"{username}_private.pem")
            if not os.path.exists(private_key_file):
                print_error("Private key file not found")
                return False

            with open(private_key_file, 'rb') as f:
                private_key_pem = f.read()

            # Load and decrypt the private key
            self._session_decrypted_key = serialization.load_pem_private_key(
                private_key_pem,
                password=password.encode('utf-8'),
                backend=default_backend()
            )
            
            # Store both PEM and password
            self._session_private_key = private_key_pem
            self._user_password = password
            return True

        except Exception as e:
            logger.error(f"Failed to initialize session: {e}")
            return False

    def clear_session(self):
        """Clear session data when user logs out"""
        self._session_private_key = None
        self._session_decrypted_key = None
        self._user_password = None

    def get_decrypted_key(self):
        """Get the decrypted private key from session"""
        return self._session_decrypted_key

    def handle_send_message(self):
        """Handle sending a message to another user"""
        try:
            current_user = self.registry.get_current_user()
            if not current_user:
                print_error("You must be logged in to send messages")
                return
            
            # Get recipient username
            recipient_username = input("Enter recipient username: ").strip()
            
            if not recipient_username:
                print_error("Recipient username cannot be empty")
                return
            
            if recipient_username == current_user.username:
                print_error("You cannot send a message to yourself")
                return
            
            # Check if recipient exists
            recipient_user = self.registry.get_user(recipient_username)
            if not recipient_user:
                print_error(f"User '{recipient_username}' not found")
                return
            
            if not recipient_user.public_key:
                print_error(f"User '{recipient_username}' doesn't have a public key")
                return
            
            # Check if sender has public key (required for double encryption)
            if not current_user.public_key:
                print_error("You don't have a public key. Please regenerate your keys.")
                return
            
            # Get message
            print("\nEnter your message (press Enter twice to finish):")
            message_lines = []
            while True:
                line = input()
                if line == "" and message_lines and message_lines[-1] == "":
                    break
                message_lines.append(line)
            
            # Remove the last empty line
            if message_lines and message_lines[-1] == "":
                message_lines.pop()
            
            message = "\n".join(message_lines).strip()
            
            if not message:
                print_error("Message cannot be empty")
                return
            
            # Send the message with double encryption
            self.message_manager.send_message(
                sender_username=current_user.username,
                recipient_username=recipient_username,
                message=message,
                recipient_public_key=recipient_user.get_public_key_pem(),
                sender_public_key=current_user.get_public_key_pem()
            )
            
            print_success(f"Message sent to {recipient_username}!")
            
        except Exception as e:
            print_error(f"Failed to send message: {e}")
            logger.error(f"Send message error: {e}")
    
    def handle_view_messages(self):
        """Handle viewing messages for current user"""
        try:
            current_user = self.registry.get_current_user()
            if not current_user:
                print_error("You must be logged in to view messages")
                return

            # Get private key from session
            private_key = self.get_decrypted_key()
            if not private_key:
                print_error("Private key not available in session")
                return

            # Get messages for user
            messages = self.message_manager.get_messages_for_user(current_user.username)

            if not messages:
                print("📭 No messages found")
                return

            print(f"\n{'='*80}")
            print(f"YOUR MESSAGES ({len(messages)} total)")
            print(f"{'='*80}")

            for i, message_data in enumerate(messages, 1):
                try:
                    timestamp = datetime.fromisoformat(message_data['timestamp'])
                    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')

                    print(f"\n--- Message {i} ---")
                    print(f"From: {message_data['sender']}")
                    print(f"To: {message_data['recipient']}")
                    print(f"Time: {timestamp_str}")

                    # Get message content using double encryption
                    message_content = self.message_manager.get_message_content_for_user(
                        message_data, 
                        current_user.username, 
                        private_key,  # Using decrypted key object
                        ""  # Empty password since we're using the decrypted key
                    )
                    print(f"Message: {message_content}")
                    
                    # Show whether user was sender or recipient
                    if message_data['sender'] == current_user.username:
                        print("📤 (Sent by you)")
                    else:
                        print("📥 (Received)")
                    
                    print("-" * 50)

                except Exception as e:
                    print(f"Error displaying message {i}: {e}")
                    continue

        except Exception as e:
            print_error(f"Failed to view messages: {e}")
            logger.error(f"View messages error: {e}")
    
    def handle_view_conversation(self):
        """Handle viewing conversation with a specific user"""
        try:
            current_user = self.registry.get_current_user()
            if not current_user:
                print_error("You must be logged in to view conversations")
                return

            # Get other username
            other_username = input("Enter username to view conversation with: ").strip()

            if not other_username:
                print_error("Username cannot be empty")
                return

            if other_username == current_user.username:
                print_error("You cannot have a conversation with yourself")
                return

            # Check if other user exists
            other_user = self.registry.get_user(other_username)
            if not other_user:
                print_error(f"User '{other_username}' not found")
                return

            # Get private key from session
            private_key = self.get_decrypted_key()
            if not private_key:
                print_error("Private key not available in session")
                return

            # Get conversation
            conversation = self.message_manager.get_conversation(current_user.username, other_username)

            if not conversation:
                print(f"📭 No conversation found with {other_username}")
                return

            print(f"\n{'='*80}")
            print(f"CONVERSATION WITH {other_username.upper()} ({len(conversation)} messages)")
            print(f"{'='*80}")

            for i, message_data in enumerate(conversation, 1):
                try:
                    timestamp = datetime.fromisoformat(message_data['timestamp'])
                    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')

                    sender = message_data['sender']
                    recipient = message_data['recipient']

                    # Determine message direction
                    if sender == current_user.username:
                        direction = "You → " + recipient
                        message_prefix = "You"
                    else:
                        direction = sender + " → You"
                        message_prefix = sender

                    print(f"\n[{timestamp_str}] {direction}")

                    # Get message content using double encryption
                    message_content = self.message_manager.get_message_content_for_user(
                        message_data, 
                        current_user.username, 
                        private_key,  # Using decrypted key object
                        ""  # Empty password since we're using the decrypted key
                    )
                    print(f"{message_prefix}: {message_content}")

                except Exception as e:
                    print(f"Error displaying message {i}: {e}")
                    continue

            print(f"\n{'='*80}")

        except Exception as e:
            print_error(f"Failed to view conversation: {e}")
            logger.error(f"View conversation error: {e}")
    
    def handle_list_conversations(self):
        """Handle listing all conversations for current user"""
        try:
            current_user = self.registry.get_current_user()
            if not current_user:
                print_error("You must be logged in to list conversations")
                return
            
            conversations = self.message_manager.get_user_conversations(current_user.username)
            
            if not conversations:
                print("📭 No conversations found")
                return
            
            print(f"\n{'='*50}")
            print(f"YOUR CONVERSATIONS ({len(conversations)} total)")
            print(f"{'='*50}")
            
            for i, other_user in enumerate(conversations, 1):
                conversation = self.message_manager.get_conversation(current_user.username, other_user)
                message_count = len(conversation)
                
                # Get latest message timestamp
                if conversation:
                    latest_timestamp = datetime.fromisoformat(conversation[-1]['timestamp'])
                    latest_time_str = latest_timestamp.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    latest_time_str = "N/A"
                
                print(f"{i}. {other_user} ({message_count} messages) - Last: {latest_time_str}")
            
            print(f"{'='*50}")
            
        except Exception as e:
            print_error(f"Failed to list conversations: {e}")
            logger.error(f"List conversations error: {e}")
