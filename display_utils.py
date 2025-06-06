#!/usr/bin/env python3
"""
Display Utilities Module
Handles user interface display functions and formatting
"""
import os
def display_user_details(registry, username):
    """
    Display detailed information about a user
    
    Args:
        registry (UserRegistry): The user registry instance
        username (str): Username to display details for
    """
    user = registry.get_user(username)
    if not user:
        print(f"User '{username}' not found")
        return
    
    print(f"\n{'='*50}")
    print(f"USER DETAILS: {username}")
    print(f"{'='*50}")
    print(f"Username: {user.username}")
    print(f"Email: {user.email or 'Not provided'}")
    print(f"Registration Time: {user.registration_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Last Key Update: {user.last_key_update.strftime('%Y-%m-%d %H:%M:%S') if user.last_key_update else 'Never'}")
    print(f"Last Login: {user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'Never'}")
    
    if user.public_key:
        print(f"\nPublic Key (first 100 chars):")
        pub_key_str = user.get_public_key_pem().decode('utf-8')
        print(f"{pub_key_str[:100]}...")
    
    # Show available public keys from other users
    other_keys = registry.get_public_keys(exclude_user=username)
    print(f"\nOther Users' Public Keys Available: {len(other_keys)}")
    for other_user in other_keys:
        print(f"  - {other_user}")

def display_all_users(registry):
    """
    Display summary of all users
    
    Args:
        registry (UserRegistry): The user registry instance
    """
    # Get fresh user data to ensure we have the latest login times
    users = registry.get_users_with_fresh_data()
    
    if not users:
        print("No users registered yet.")
        return
    
    print(f"\n{'='*80}")
    print(f"ALL REGISTERED USERS ({len(users)} total)")
    print(f"{'='*80}")
    print(f"{'Username':<15} {'Email':<20} {'Registered':<20} {'Last Login':<20}")
    print(f"{'-'*75}")
    
    for user in users.values():
        email = user.email or 'N/A'
        reg_time = user.registration_time.strftime('%Y-%m-%d %H:%M')
        last_login = user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else 'Never'
        print(f"{user.username:<15} {email:<20} {reg_time:<20} {last_login:<20}")

def display_login_status(registry):
    """
    Display current login status
    
    Args:
        registry (UserRegistry): The user registry instance
    """
    if registry.is_logged_in():
        current_user = registry.get_current_user()
        print(f"\n[LOGGED IN as: {current_user.username}]")
    else:
        print("\n[NOT LOGGED IN]")

def display_menu(is_logged_in):
    """
    Display appropriate menu based on login status
    
    Args:
        is_logged_in (bool): Whether a user is currently logged in
    """
    print("\nOptions:")
    if not is_logged_in:
        print("1. Register new user")
        print("2. Login")
        print("3. List all users")
        print("4. Exit")
    else:
        print("1. View my details")
        print("2. View user details")
        print("3. List all users")
        print("4. Update public keys")
        print("5. Send message")
        print("6. View my messages")
        print("7. View conversation")
        print("8. List conversations")
        print("9. RSA Attack Demonstration")
        print("10. Logout")
        print("11. Exit")

def get_user_choice(is_logged_in):
    """
    Get user menu choice with appropriate prompt
    
    Args:
        is_logged_in (bool): Whether a user is currently logged in
        
    Returns:
        str: User's choice
    """
    if not is_logged_in:
        return input("\nEnter your choice (1-4): ").strip()
    else:
        return input("\nEnter your choice (1-10): ").strip()

def print_header(heading=None):
    """Print application header"""
    print(f"RSA CLI Messaging System - {heading}")
    print("=" * 60)

def print_success(message):
    """
    Print success message with checkmark
    Args:
        message (str): Success message to display
    """
    print(f"\n✓ {message}")

def print_error(message):
    """
    Print error message
    
    Args:
        message (str): Error message to display
    """
    print(f"Error: {message}")

def print_goodbye():
    """Print goodbye message"""
    print("Goodbye!")

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')
