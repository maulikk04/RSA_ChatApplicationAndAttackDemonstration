#!/usr/bin/env python3
"""
CLI Interface Module
Handles command-line interface interactions and user input
"""

import getpass
import logging
from user_registry import UserRegistry
from messaging_interface import MessagingInterface
from display_utils import (
    display_user_details, display_all_users, display_login_status,
    display_menu, get_user_choice, print_header, print_success,
    print_error, print_goodbye
)

logger = logging.getLogger(__name__)

class CLIInterface:
    """Handles command-line interface for the messaging application"""
    
    def __init__(self, data_dir="messaging_data"):
        """
        Initialize CLI interface
        
        Args:
            data_dir (str): Directory to store user data
        """
        self.registry = UserRegistry(data_dir)
        self.messaging = MessagingInterface(self.registry, data_dir)
    
    def handle_registration(self):
        """Handle user registration process"""
        try:
            username = input("Enter username: ").strip()
            password = getpass.getpass("Enter password: ")
            confirm_password = getpass.getpass("Confirm password: ")
            
            if password != confirm_password:
                print("Passwords do not match!")
                return
            
            email = input("Enter email (optional): ").strip()
            email = email if email else None
            
            try:
                key_size = int(input("Enter key size (default 2048): ").strip() or "2048")
                if key_size < 1024:
                    print("Warning: Key size less than 1024 is not recommended")
            except ValueError:
                key_size = 2048
            
            user = self.registry.register_user(username, password, email, key_size)
            print_success(f"User '{username}' registered successfully!")
            display_user_details(self.registry, username)
            
        except ValueError as e:
            print_error(f"Registration failed: {e}")
    
    def handle_login(self):
        """Handle user login process"""
        try:
            username = input("Enter username: ").strip()
            password = getpass.getpass("Enter password: ")
            
            success, password = self.registry.login(username, password)
            if success:
                # Initialize messaging session with user's password
                self.messaging.initialize_session(username, password)
                print_success(f"Welcome back, {username}!")
        
        except ValueError as e:
            print_error(f"Login failed: {e}")
    
    def handle_view_user_details(self):
        """Handle viewing specific user details"""
        username = input("Enter username to view: ").strip()
        display_user_details(self.registry, username)
    
    def handle_update_public_keys(self):
        """Handle updating public keys for current user"""
        try:
            other_keys = self.registry.update_public_keys_for_user(self.registry.current_user)
            print_success(f"Updated public keys for '{self.registry.current_user}'")
            print(f"Available public keys from other users: {len(other_keys)}")
            for other_user in other_keys:
                print(f"  - {other_user}")
        except ValueError as e:
            print_error(str(e))
    
    def handle_logout(self):
        """Handle user logout"""
        if self.registry.logout():
            # Clear messaging interface session
            self.messaging.clear_session()
            print_success("Logged out successfully!")
        else:
            print("No user was logged in.")
    
    def run_not_logged_in_menu(self, choice):
        """
        Handle menu choices when user is not logged in
        
        Args:
            choice (str): User's menu choice
            
        Returns:
            bool: False if user wants to exit, True otherwise
        """
        if choice == '1':
            # Register new user
            self.handle_registration()
        elif choice == '2':
            # Login
            self.handle_login()
        elif choice == '3':
            # List all users
            display_all_users(self.registry)
        elif choice == '4':
            # Exit
            return False
        else:
            print("Invalid choice. Please try again.")
        
        return True
    
    def run_logged_in_menu(self, choice):
        """
        Handle menu choices when user is logged in
        
        Args:
            choice (str): User's menu choice
            
        Returns:
            bool: False if user wants to exit, True otherwise
        """
        if choice == '1':
            # View my details
            display_user_details(self.registry, self.registry.current_user)
        elif choice == '2':
            # View user details
            self.handle_view_user_details()
        elif choice == '3':
            # List all users
            display_all_users(self.registry)
        elif choice == '4':
            # Update public keys
            self.handle_update_public_keys()
        elif choice == '5':
            # Send message
            self.messaging.handle_send_message()
        elif choice == '6':
            # View my messages
            self.messaging.handle_view_messages()
        elif choice == '7':
            # View conversation
            self.messaging.handle_view_conversation()
        elif choice == '8':
            # List conversations
            self.messaging.handle_list_conversations()
        elif choice == '9':
            # Logout
            self.handle_logout()
        elif choice == '10':
            # Exit
            return False
        else:
            print("Invalid choice. Please try again.")
        
        return True
    
    def run(self):
        """Main application loop"""
        print_header()
        
        while True:
            try:
                # Show current login status and menu
                display_login_status(self.registry)
                is_logged_in = self.registry.is_logged_in()
                display_menu(is_logged_in)
                
                # Get user choice
                choice = get_user_choice(is_logged_in)
                
                # Handle menu choice based on login status
                if not is_logged_in:
                    if not self.run_not_logged_in_menu(choice):
                        break
                else:
                    if not self.run_logged_in_menu(choice):
                        break
                        
            except KeyboardInterrupt:
                print("\n")
                break
            except Exception as e:
                print_error(str(e))
                logger.error(f"Unexpected error in CLI: {e}")
        
        print_goodbye()
