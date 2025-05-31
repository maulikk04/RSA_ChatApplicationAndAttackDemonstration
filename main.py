#!/usr/bin/env python3
"""
Main Application Entry Point
RSA-based CLI Messaging Application - User Registration & Key Management with Authentication
"""

import logging
from cli_interface import CLIInterface

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('messaging_app.log'),
        logging.StreamHandler()
    ]
)

def main():
    """Main application entry point"""
    try:
        # Initialize and run the CLI interface
        cli = CLIInterface()
        cli.run()
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"A fatal error occurred: {e}")
        print("Please check the log file for more details.")

if __name__ == "__main__":
    main()