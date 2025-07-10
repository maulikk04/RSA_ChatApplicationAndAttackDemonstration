#!/usr/bin/env python3
"""
Attack Interface Module
Provides CLI interface for RSA attack demonstrations
"""

import os
import json
import logging
from datetime import datetime
from rsa_attack import RSAAttacker
from rsa_key_manager import RSAKeyManager
from display_utils import print_header, clear_screen

logger = logging.getLogger(__name__)

class AttackInterface:
    """CLI interface for RSA attack demonstrations"""
    
    def __init__(self):
        """Initialize Attack Interface"""
        self.attacker = RSAAttacker()
        
    def show_attack_menu(self):
        """Display the attack demonstration menu"""
        clear_screen()
        print_header("RSA ATTACK DEMONSTRATION")
        
        menu_options = [
            "1. Small Key Attack",
            "2. Benchmark Different Key Sizes against Small key attacks",
            "3. Hastad's Broadcast Attack", 
            "4. Wiener's Attack", 
            "5. View Previous Results",
            "0. Back to Main Menu"
        ]
        
        for option in menu_options:
            print(f"   {option}")
        print()
    
    def run_attack_interface(self):
        """Main attack interface loop"""
        while True:
            try:
                self.show_attack_menu()
                choice = input("🎯 Select an option: ").strip()
                
                if choice == '1':
                    self.single_key_attack()
                elif choice == '2':
                    self.benchmark_key_sizes()
                elif choice == '3':
                    self.hastad_attack_demo()
                elif choice == '4':
                    self.wiener_attack_demo()
                elif choice == '5':
                    self.view_previous_results()
                elif choice == '0':
                    clear_screen()
                    break
                else:
                    print("❌ Invalid option. Please try again.")
                    input("Press Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\n\n👋 Exiting attack interface...")
                break
            except Exception as e:
                logger.error(f"Error in attack interface: {e}")
                print(f"❌ An error occurred: {e}")
                input("Press Enter to continue...")
    
    def single_key_attack(self):
        """Demonstrate attack on a single key"""
        clear_screen()
        print_header("SINGLE KEY ATTACK DEMONSTRATION")
        
        try:
            # Get key size from user
            print("Enter the RSA key size to attack (e.g., 128, 256, 384, 512):")
            key_size_input = input("Key size (bits): ").strip()
            
            try:
                key_size = int(key_size_input)
            except ValueError:
                print("❌ Invalid key size. Using default 256 bits.")
                key_size = 256
            
            # Ask for attack methods
            print(f"\nAvailable attack methods:")
            print("1. Trial Division")
            print("2. Pollard's Rho")
            print("3. Fermat's Method")
            print("4. All methods")
            
            method_choice = input("Select methods (1-4): ").strip()
            
            if method_choice == '1':
                attack_methods = ['trial_division']
            elif method_choice == '2':
                attack_methods = ['pollard_rho']
            elif method_choice == '3':
                attack_methods = ['fermat']
            else:
                attack_methods = ['trial_division', 'pollard_rho', 'fermat']
            
            print(f"\n🔧 Generating {key_size}-bit RSA key for testing...")
            
            # Generate test key
            private_key, public_key = RSAKeyManager.generate_key_pair(key_size)
            public_key_pem = RSAKeyManager.serialize_public_key(public_key)
            
            print(f"✅ Key generated successfully!")
            
            # Perform attack
            print(f"\n🚀 Starting attack with methods: {', '.join(attack_methods)}")
            print("⚠️  This may take some time depending on key size...")
            
            result = self.attacker.attack_small_key(public_key_pem, key_size, attack_methods)
            
            # Display results
            self.display_single_attack_result(result)
            
            # Ask to save results
            save_choice = input("\n💾 Save results to file? (y/n): ").strip().lower()
            if save_choice == 'y':
                filename = f"attack_result_{key_size}bit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                self.attacker.save_results([result], filename)
            
        except Exception as e:
            logger.error(f"Single key attack failed: {e}")
            print(f"❌ Attack failed: {e}")
        
        input("\nPress Enter to continue...")
    
    def benchmark_key_sizes(self):
        """Benchmark attacks against multiple key sizes"""
        clear_screen()
        print_header("RSA KEY SIZE BENCHMARK")
        
        try:
            print("This will test RSA attacks against different key sizes.")
            print("⚠️  Warning: Larger keys may take considerable time to attack!")
            print()
        
            key_sizes_input = input("Enter key sizes separated by commas (e.g., 128,256,384): ")
            if not key_sizes_input:
                print("❌ No key sizes provided. Using default: 128,256,384")
                key_sizes = [128, 256, 384]    
            try:
                key_sizes = [int(x.strip()) for x in key_sizes_input.split(',')]
            except ValueError:
                    print("❌ Invalid input. Using default test set.")
                    key_sizes = [128, 256, 384]
            
            print(f"\n🎯 Testing key sizes: {key_sizes}")
            print("⏳ This may take several minutes...")
            
            # Run benchmark
            results = self.attacker.benchmark_key_sizes(key_sizes)
            
            # Display results
            self.display_benchmark_results(results)
            
            # Generate analysis
            self.attacker.generate_attack_report(results)
            self.attacker.create_comparison_table(results)
            
            save_choice = input("\n💾 Save benchmark results? (y/n): ").strip().lower()
            if save_choice == 'y':
                filename = f"benchmark_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                self.attacker.save_results(results, filename)
                
        except Exception as e:
            logger.error(f"Benchmark failed: {e}")
            print(f"❌ Benchmark failed: {e}")
        
        input("\nPress Enter to continue...")
    
    def view_previous_results(self):
        """View previously saved attack results"""
        clear_screen()
        print_header("PREVIOUS ATTACK RESULTS")
        
        try:
            # Find result files
            result_files = [f for f in os.listdir('.') if f.startswith(('attack_result_', 'benchmark_results_')) and f.endswith('.json')]
            
            if not result_files:
                print("📂 No previous results found.")
                input("Press Enter to continue...")
                return
            
            print("Available result files:")
            for i, filename in enumerate(result_files, 1):
                print(f"   {i}. {filename}")
            
            choice = input(f"\nSelect file to view (1-{len(result_files)}): ").strip()
            
            try:
                file_index = int(choice) - 1
                if 0 <= file_index < len(result_files):
                    selected_file = result_files[file_index]
                    
                    with open(selected_file, 'r') as f:
                        results = json.load(f)
                    
                    print(f"\n📊 Results from {selected_file}:")
                    print("=" * 60)
                    
                    if isinstance(results, list):
                        # Multiple results (benchmark)
                        self.display_benchmark_results(results)
                        self.attacker.create_comparison_table(results)
                    else:
                        # Single result
                        self.display_single_attack_result(results)
                else:
                    print("❌ Invalid selection")
            except ValueError:
                print("❌ Invalid input")
                
        except Exception as e:
            logger.error(f"Failed to view results: {e}")
            print(f"❌ Failed to load results: {e}")
        
        input("\nPress Enter to continue...")
    
    def hastad_attack_demo(self):
        """Demonstrate Hastad's broadcast attack"""
        clear_screen()
        print_header("HASTAD'S BROADCAST ATTACK DEMONSTRATION")
        
        try:
            print("\nHastad's broadcast attack exploits RSA when:")
            print("1. The same message is encrypted multiple times")
            print("2. A small public exponent (e=3) is used")
            print("3. Different public keys are used for each encryption")
            
            # Choose attack variant
            print("\nChoose attack demonstration type:")
            print("1. Basic Hastad Attack (non-padded)")
            print("2. Padded vs Non-padded Messages (OAEP)")
            
            choice = input("\nSelect option (1-2): ").strip()
            
            if choice == "1":
                self._basic_hastad_attack()
            elif choice == "2":
                self._hastad_attack_padding_comparison()
            else:
                print("❌ Invalid choice")
                
        except Exception as e:
            logger.error(f"Hastad attack demonstration failed: {e}")
            print(f"❌ Attack failed: {e}")
    
        input("\nPress Enter to continue...")

    def _get_hastad_inputs(self):
        """Get common inputs for all Hastad attack demonstrations"""
        print("\nEnter a message to encrypt (will be converted to integer):")
        message = input("Message: ").strip()
        if not message:
            message = "attack at dawn"
            print(f"Using default message: '{message}'")
        
        # Validate message size
        message_bytes = message.encode('utf-8')
        if len(message_bytes) > 128:
            print("\n❌ Error: Message is too long!")
            print("Maximum message length is 128 bytes (1024 bits)")
            print(f"Your message is {len(message_bytes)} bytes ({len(message_bytes) * 8} bits)")
            return None, None, None
        
        # Get number of recipients
        while True:
            try:
                num_recipients = input("\nEnter number of recipients/keys (minimum 3): ").strip()
                num_recipients = int(num_recipients) if num_recipients else 3
                if num_recipients < 3:
                    print("⚠️ Minimum 3 recipients required for the attack. Using 3.")
                    num_recipients = 3
                break
            except ValueError:
                print("❌ Invalid input. Please enter a number.")
        
        message_int = int.from_bytes(message_bytes, 'big')
        return message, message_int, num_recipients

    def _basic_hastad_attack(self):
        """Basic Hastad attack implementation"""
        message, message_int, num_recipients = self._get_hastad_inputs()
        if not message:
            return
            
        print(f"\n🎯 Running Hastad attack with:")
        print(f"   Message: '{message}'")
        print(f"   Recipients: {num_recipients}")
        
        result = self.attacker.demonstrate_hastad_attack(
            message_int=message_int,
            e=3,
            num_keys=num_recipients
        )
        self._display_hastad_result(result, message)

    def _hastad_attack_different_exponents(self):
        """Compare Hastad attack with different exponents"""
        message, message_int, num_recipients = self._get_hastad_inputs()
        if not message:
            return
            
        exponents = [3, 5,7] 
        results = []
        
        print(f"\n🎯 Testing with message: '{message}'")
        print(f"   Base number of recipients: {num_recipients}")
        print("\nRunning attacks with different exponents:")
        
        for e in exponents:
            required_recipients = max(num_recipients, e)
            print(f"\n🔍 Testing with e = {e} (using {required_recipients} recipients)")
            
            result = self.attacker.demonstrate_hastad_attack(
                message_int=message_int,
                e=e,
                num_keys=required_recipients
            )
            results.append((e, result))
        
        # Display comparison results
        print("\n📊 EXPONENT COMPARISON RESULTS")
        print("=" * 60)
        print(f"{'Exponent (e)':<12} {'Success':<10} {'Time (s)':<12} {'Recipients':<12} {'Notes'}")
        print("-" * 60)
        
        for e, result in results:
            success = "✅" if result['successful'] else "❌"
            time = f"{result.get('attack_time', 'N/A'):.4f}" if 'attack_time' in result else "N/A"
            recipients = max(num_recipients, e)
            notes = "Recovered" if result['successful'] else "Failed"
            print(f"{e:<12} {success:<10} {time:<12} {recipients:<12} {notes}")
        
        print("\n📝 Analysis:")
        print("• Smaller exponents generally make the attack easier")
        print("• Each exponent requires at least e different ciphertexts")
        print("• Larger exponents increase computational complexity")

    def _hastad_attack_padding_comparison(self):
        """Compare Hastad attack on padded (OAEP) vs non-padded messages"""
        from rsa_key_manager import RSAKeyManager
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        import time
        import logging
        
        logger = logging.getLogger(__name__)
        
        message, message_int, num_recipients = self._get_hastad_inputs()
        if not message:
            return
            
        print(f"\n🎯 Testing with message: '{message}'")
        print(f"   Recipients: {num_recipients}")
        print(f"   Message as integer: {message_int}")
        
        # Configuration
        key_size = 2048
        public_exponent = 3
        
        try:
            # Generate keys for all recipients (same keys used for both tests)
            print(f"\n🔑 Generating {num_recipients} RSA key pairs...")
            key_pairs = []
            moduli = []
            
            for i in range(num_recipients):
                private_key, public_key = RSAKeyManager.generate_key_pair(
                    key_size, public_exponent=public_exponent
                )
                key_pairs.append((private_key, public_key))
                moduli.append(public_key.public_numbers().n)
                print(f"   ✓ Key pair {i+1} generated (n = {moduli[-1] % 10000}...)")
            
            print("\n" + "="*80)
            print("🔍 TESTING NON-PADDED RSA ENCRYPTION")
            print("="*80)
            
            # Test 1: Non-padded (raw) RSA encryption
            raw_ciphertexts = []
            raw_start_time = time.time()
            
            for i, (_, public_key) in enumerate(key_pairs):
                # Raw RSA encryption: c = m^e mod n
                n = public_key.public_numbers().n
                e = public_key.public_numbers().e
                
                # Ensure message is smaller than modulus
                if message_int >= n:
                    print(f"❌ Message too large for key {i+1} (message: {message_int}, n: {n})")
                    return
                
                ciphertext = pow(message_int, e, n)
                raw_ciphertexts.append(ciphertext)
                print(f"   Recipient {i+1}: c = {ciphertext % 10000}... (mod {n % 10000}...)")
            
            raw_encrypt_time = time.time() - raw_start_time
            
            # Attempt Hastad attack on raw ciphertexts
            print(f"\n🚀 Launching Hastad attack on non-padded ciphertexts...")
            raw_attack_result = self.attacker.hastad_broadcast_attack(
                ciphertexts=raw_ciphertexts,
                moduli=moduli,
                e=public_exponent
            )
            
            raw_result = {
                'successful': raw_attack_result[0] is not None,
                'recovered_message': raw_attack_result[0],
                'attack_time': raw_attack_result[1],
                'encrypt_time': raw_encrypt_time,
                'error': None if raw_attack_result[0] is not None else "Attack failed"
            }
            
            if raw_result['successful']:
                recovered_text = None
                try:
                    # Try to convert back to text
                    recovered_bytes = raw_result['recovered_message'].to_bytes(
                        (raw_result['recovered_message'].bit_length() + 7) // 8, 'big'
                    )
                    recovered_text = recovered_bytes.decode('utf-8', errors='ignore')
                except:
                    pass
                
                print(f"   ✅ Attack successful!")
                print(f"   📝 Recovered integer: {raw_result['recovered_message']}")
                if recovered_text:
                    print(f"   📝 Recovered text: '{recovered_text}'")
                print(f"   ⏱️  Attack time: {raw_result['attack_time']:.4f}s")
            else:
                print(f"   ❌ Attack failed: {raw_result['error']}")
            
            print("\n" + "="*80)
            print("🔍 TESTING OAEP-PADDED RSA ENCRYPTION")
            print("="*80)
            
            # Test 2: OAEP-padded RSA encryption
            padded_ciphertexts = []
            padded_start_time = time.time()
            
            message_bytes = message.encode('utf-8')
            
            for i, (_, public_key) in enumerate(key_pairs):
                try:
                    # OAEP padded encryption
                    ciphertext_bytes = public_key.encrypt(
                        message_bytes,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    ciphertext_int = int.from_bytes(ciphertext_bytes, 'big')
                    padded_ciphertexts.append(ciphertext_int)
                    print(f"   Recipient {i+1}: c = {ciphertext_int % 10000}... (OAEP padded)")
                    
                except Exception as e:
                    logger.error(f"OAEP encryption failed for recipient {i+1}: {e}")
                    print(f"   ❌ OAEP encryption failed for recipient {i+1}: {e}")
                    return
            
            padded_encrypt_time = time.time() - padded_start_time
            
            print(f"\n🚀 Launching Hastad attack on OAEP-padded ciphertexts...")
            padded_attack_result = self.attacker.hastad_broadcast_attack(
                ciphertexts=padded_ciphertexts,
                moduli=moduli,
                e=public_exponent
            )
            
            padded_result = {
                'successful': False, 
                'recovered_message': padded_attack_result[0],
                'attack_time': padded_attack_result[1],
                'encrypt_time': padded_encrypt_time,
                'error': 'OAEP padding prevents attack through randomization'
            }
            
            if padded_attack_result[0] is not None:
                print(f"   ⚠️  Unexpected: Attack returned a result!")
                print(f"   📝 Result: {padded_attack_result[0]}")
                print(f"   🔍 This likely means the attack found a mathematical solution")
                print(f"      but it's not the original message due to OAEP padding.")
                padded_result['error'] = 'Attack found mathematical solution, but not original message'
            else:
                print(f"   ✅ Attack correctly failed (as expected with OAEP)")
                print(f"   📝 OAEP padding successfully prevented the attack")
            
            print(f"   ⏱️  Attack attempt time: {padded_result['attack_time']:.4f}s")
            
        except Exception as e:
            logger.error(f"Error during padding comparison: {e}")
            print(f"❌ Error during test: {e}")
            return
        
        # Display comprehensive comparison
        print("\n" + "="*100)
        print("📊 COMPREHENSIVE PADDING COMPARISON RESULTS")
        print("="*100)
        
        print(f"{'Encryption Type':<20} {'Success':<10} {'Encrypt Time':<15} {'Attack Time':<15} {'Status'}")
        print("-" * 100)
        
        # Non-padded results
        success_icon = "✅" if raw_result['successful'] else "❌"
        status = "VULNERABLE - Message recovered!" if raw_result['successful'] else "Attack failed"
        print(f"{'Raw RSA':<20} {success_icon:<10} {raw_result['encrypt_time']:.4f}s{'':<7} "
            f"{raw_result['attack_time']:.4f}s{'':<7} {status}")
        
        # OAEP results  
        success_icon = "❌" if not padded_result['successful'] else "⚠️"
        status = "SECURE - Attack prevented" if not padded_result['successful'] else "Unexpected result"
        print(f"{'OAEP Padded RSA':<20} {success_icon:<10} {padded_result['encrypt_time']:.4f}s{'':<7} "
            f"{padded_result['attack_time']:.4f}s{'':<7} {status}")
        
        return {
            'raw_result': raw_result,
            'padded_result': padded_result,
            'num_recipients': num_recipients,
            'message': message
        }
    def wiener_attack_demo(self):
        """Demonstrate Wiener's attack on RSA with small private exponent"""
        clear_screen()
        print_header("WIENER'S ATTACK DEMONSTRATION")
        
        try:
            print("\nWiener's attack exploits RSA keys with small private exponents (d).")
            print("This attack works when d < n^(1/4) / 3, which violates the usual RSA security assumptions.")
            print("\nNote: In practice, RSA implementations use large values for d, making them")
            print("      resistant to this attack. This is for educational purposes only.")
            
            # Choose demo mode
            print("\nChoose demonstration mode:")
            print("1. Single Key Attack")
            print("2. Compare Different Key Sizes")
            
            mode_choice = input("\nSelect mode (1-2): ").strip()
            
            if mode_choice == "2":
                self._wiener_compare_key_sizes()
            else:
                self._wiener_single_attack()
        
        except Exception as e:
            logger.error(f"Wiener attack demonstration failed: {e}")
            print(f"\n❌ Demonstration failed: {e}")
        
        input("\nPress Enter to continue...")
    
    def _wiener_single_attack(self):
        """Run a single Wiener attack with user-specified parameters"""
        try:
            # Configure attack parameters
            print("\nConfigure attack demonstration:")
            
            key_size = 1024  # Default key size
            d_size_ratio = 0.25  # Default d size ratio (d < n^0.25 for vulnerability)
            
            # User enters key size
            try:
                size_input = input("\nEnter key size in bits: ").strip()
                if size_input:
                    key_size = int(size_input)
            except ValueError:
                print("\n❌ Invalid input, using default 1024 bits")
            
            # User enters d size ratio
            try:
                ratio_input = input("\nEnter d size ratio (0.20-0.25, smaller = more vulnerable): ").strip()
                if ratio_input:
                    d_size_ratio = float(ratio_input)
                    if d_size_ratio < 0.20:
                        print("\n⚠️ Ratio too small, setting to 0.20")
                        d_size_ratio = 0.20
                    elif d_size_ratio > 0.25:
                        print("\n⚠️ Ratio too large (attack may fail), setting to 0.25")
                        d_size_ratio = 0.25
            except ValueError:
                print("\n❌ Invalid input, using default ratio of 0.25")
                
            # User enters message to encrypt and recover
            print("\nEnter a message to encrypt with the vulnerable key:")
            message = input("Message: ").strip()
            if not message:
                message = "attack at dawn"
                print(f"Using default message: '{message}'")
                
            # Convert message to integer
            message_bytes = message.encode('utf-8')
            
            message_int = int.from_bytes(message_bytes, 'big')
            
            # Run the Wiener attack demonstration
            print(f"\n🚀 Starting Wiener's attack with {key_size}-bit key and d-size ratio {d_size_ratio}")
            print(f"\n📝 Message to encrypt: '{message}'")
            print("\n⚙️  This might take a moment...")
            
            # Add the message to the parameters
            result = self.attacker.demonstrate_wiener_attack(
                key_size=key_size, 
                d_size_ratio=d_size_ratio,
                message=message_int
            )
            
            self._display_wiener_attack_result(result, message)
            
            # Save option
            save_choice = input("\n💾 Save attack result? (y/n): ").strip().lower()
            if save_choice == 'y':
                filename = f"wiener_attack_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                try:
                    with open(filename, 'w') as f:
                        json.dump(result, f, indent=2, default=str)
                    print(f"\n✅ Results saved to {filename}")
                except Exception as e:
                    print(f"\n❌ Failed to save results: {e}")
                
        except Exception as e:
            logger.error(f"Single Wiener attack failed: {e}")
            print(f"\n❌ Attack failed: {e}")
    
    def _wiener_compare_key_sizes(self):
        """Compare Wiener attack results for different key sizes"""
        try:
            print("\n📊 WIENER'S ATTACK KEY SIZE COMPARISON")
            
            # Get key sizes to test
            print("\nEnter key sizes to test (comma-separated, e.g., 512,768,1024,2048):")
            key_sizes_input = input("Key sizes: ").strip()
            if not key_sizes_input:
                key_sizes = [256, 512, 768, 1024, 1536, 2048]
                print(f"Using default key sizes: {key_sizes}")
            else:
                try:
                    key_sizes = [int(k.strip()) for k in key_sizes_input.split(',')]
                    # Validate and limit key sizes
                    key_sizes = [max(256, min(k, 2048)) for k in key_sizes]
                    key_sizes.sort()  # Sort in ascending order
                except ValueError:
                    print("\n❌ Invalid input, using default key sizes")
                    key_sizes = [256, 512, 768, 1024, 1536, 2048]
            
            # Get d size ratio
            try:
                ratio_input = input("\nEnter d size ratio (0.20-0.25): ").strip()
                if not ratio_input:
                    d_size_ratio = 0.25
                    print(f"Using default ratio: {d_size_ratio}")
                else:
                    d_size_ratio = float(ratio_input)
                    if d_size_ratio < 0.20:
                        print("\n⚠️ Ratio too small, setting to 0.20")
                        d_size_ratio = 0.20
                    elif d_size_ratio > 0.25:
                        print("\n⚠️ Ratio too large (attack may fail), setting to 0.25")
                        d_size_ratio = 0.25
            except ValueError:
                print("\n❌ Invalid input, using default ratio")
                d_size_ratio = 0.25
            
            # Get message to encrypt
            print("\nEnter a message to encrypt with all key sizes:")
            message = input("Message: ").strip()
            if not message:
                message = "attack at dawn"
                print(f"Using default message: '{message}'")
            
            # Convert message to integer
            message_bytes = message.encode('utf-8')
            message_int = int.from_bytes(message_bytes, 'big')
            
            # Run attack for each key size
            results = []
            print("\n🚀 Running Wiener's attack comparison...")
            
            for key_size in key_sizes:
                print(f"\n📝 Testing {key_size}-bit key with ratio {d_size_ratio}...")
                
                result = self.attacker.demonstrate_wiener_attack(
                    key_size=key_size,
                    d_size_ratio=d_size_ratio,
                    message=message_int
                )
                
                result['key_size'] = key_size 
                results.append(result)
                
                # Show brief result
                if result['successful']:
                    print(f"   ✅ Attack successful! Time: {result.get('attack_time', 'N/A'):.4f}s")
                else:
                    print(f"   ❌ Attack failed. {result.get('error', '')}")
            
            # Display comparison table
            self._display_wiener_comparison_results(results, message, d_size_ratio)
            
            # Save option
            save_choice = input("\n💾 Save comparison results? (y/n): ").strip().lower()
            if save_choice == 'y':
                filename = f"wiener_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                try:
                    with open(filename, 'w') as f:
                        json.dump(results, f, indent=2, default=str)
                    print(f"\n✅ Comparison results saved to {filename}")
                except Exception as e:
                    print(f"\n❌ Failed to save results: {e}")
            
        except Exception as e:
            logger.error(f"Wiener key size comparison failed: {e}")
            print(f"\n❌ Comparison failed: {e}")
    
    def _display_wiener_comparison_results(self, results, message, d_size_ratio):
        """Display comprehensive comparison of Wiener attack results"""
        print("\n" + "=" * 100)
        print("📊 WIENER'S ATTACK KEY SIZE COMPARISON RESULTS")
        print("=" * 100)
        
        print(f"Test parameters:")
        print(f"   • Message: '{message}'")
        print(f"   • Message size: {len(message.encode('utf-8'))} bytes")
        print(f"   • d size ratio: {d_size_ratio}")
        
        print("\n" + "-" * 100)
        print(f"{'Key Size':<12} {'Status':<12} {'Attack Time':<15} {'d recovered':<15} {'d bits':<10} {'Factors Found'}")
        print("-" * 100)
        
        successful_count = 0
        for result in results:
            key_size = result.get('key_size_bits', result.get('key_size', 'N/A'))
            status = "✅ SUCCESS" if result.get('successful', False) else "❌ FAILED"
            attack_time = f"{result.get('attack_time', 'N/A'):.4f}s" if result.get('attack_time') else "N/A"
            
            if result.get('successful', False):
                d_value = str(result.get('recovered_d', 'N/A'))
                if len(d_value) > 12:  # Truncate if too long
                    d_value = d_value[:9] + '...'
                d_bits = result.get('d_bit_length', 'N/A')
                factors = "Yes" if result.get('factors') else "No"
                successful_count += 1
            else:
                d_value = "N/A"
                d_bits = "N/A"
                factors = "No"
            
            print(f"{key_size:<12} {status:<12} {attack_time:<15} {d_value:<15} {d_bits:<10} {factors}")
        
        print("-" * 100)
        success_rate = (successful_count / len(results)) * 100 if results else 0
        print(f"Success rate: {successful_count}/{len(results)} ({success_rate:.1f}%)")
        
        # Analysis section
        print("\n📋 ANALYSIS")
        print("-" * 100)
        if successful_count > 0:
            successful_keys = [r.get('key_size_bits', r.get('key_size')) for r in results if r.get('successful', False)]
            print(f"• Successful attacks on key sizes: {', '.join(map(str, successful_keys))}")
            
            min_time = min([r.get('attack_time', float('inf')) for r in results if r.get('successful', False)])
            min_time_key = next(r.get('key_size_bits', r.get('key_size')) for r in results 
                              if r.get('successful', False) and r.get('attack_time') == min_time)
            print(f"• Fastest attack: {min_time:.4f}s on {min_time_key}-bit key")
            
            avg_time = sum([r.get('attack_time', 0) for r in results if r.get('successful', False)]) / successful_count
            print(f"• Average attack time for successful attacks: {avg_time:.4f}s")
        else:
            print("• No successful attacks across all key sizes")
        
        print("• Observations:")
        print("  - Wiener's attack is theoretically feasible when d < n^(1/4)/3")
        print("  - Success rate decreases as key size increases")
        print("  - Attack time generally increases with key size")
        print("  - Smaller d size ratios increase vulnerability")
    
    def _display_wiener_attack_result(self, result, message):
        """Display results of a single Wiener attack"""
        if result['successful']:
            print("\n" + "=" * 80)
            print("🏆 WIENER'S ATTACK SUCCESSFUL!")
            print("=" * 80)
            print(f"Key size: {result['key_size_bits']} bits")
            print(f"Public exponent (e): {result['e']}")
            print(f"Private exponent (d): {result.get('recovered_d', 'Unknown')}")
            print(f"Original d: {result.get('d', 'Unknown')}")
            print(f"Attack time: {result.get('attack_time', 'Unknown'):.4f} seconds")
            
            if result.get('factors'):
                p, q = result['factors']
                print(f"\n🔑 Recovered factors:")
                print(f"p = {p}")
                print(f"q = {q}")
                print(f"Verification: p × q = {p * q}")
            
            # Display message recovery information
            if 'original_message' in result and 'recovered_message' in result:
                print("\n📨 MESSAGE RECOVERY RESULTS:")
                print(f"Original message (int): {result['original_message']}")
                print(f"Encrypted message: {result.get('ciphertext', 'Not available')}")
                print(f"Recovered message (int): {result['recovered_message']}")
                
                # Convert recovered integer back to text
                try:
                    recovered_bytes = result['recovered_message'].to_bytes(
                        (result['recovered_message'].bit_length() + 7) // 8, 'big')
                    recovered_text = recovered_bytes.decode('utf-8')
                    print(f"\n✅ Recovered text: '{recovered_text}'")
                    
                    if recovered_text == message:
                        print("✓ Message perfectly recovered!")
                    else:
                        print("⚠️ Message recovery has some issues.")
                except Exception as e:
                    print(f"\n❌ Failed to convert recovered value to text: {e}")
        else:
            print("\n" + "=" * 80)
            print("❌ WIENER'S ATTACK FAILED")
            print("=" * 80)
            print(f"Key size: {result.get('key_size_bits', 'Unknown')} bits")
            if 'error' in result:
                print(f"Error: {result['error']}")
            print("\nPossible reasons for failure:")
            print("• The private exponent (d) might be too large")
            print("• The continued fraction expansion didn't yield good approximations")
            print("• Key generation parameters didn't produce a vulnerable key")
    
    def _display_hastad_result(self, result, original_message):
        """Display the results of a Hastad attack"""
        if result['successful']:
            print("\n✅ Attack successful!")
            print(f"Original message: '{original_message}'")
            try:
                recovered_bytes = result['recovered_message'].to_bytes(
                    (result['recovered_message'].bit_length() + 7) // 8, 
                    'big'
                )
                recovered_text = recovered_bytes.decode('utf-8')
                print(f"Recovered message: '{recovered_text}'")
            except Exception as e:
                print(f"Recovered value: {result['recovered_message']}")
                
            print(f"Time taken: {result['attack_time']:.4f} seconds")
        
        else:
            print("\n❌ Attack failed!")
            if 'error' in result:
                print(f"Error: {result['error']}")
            if 'attack_time' in result:
                print(f"Time taken: {result['attack_time']:.4f} seconds")
    
    def display_single_attack_result(self, result):
        """Display results of a single attack"""
        print("\n" + "=" * 70)
        print("🎯 ATTACK RESULT")
        print("=" * 70)
        
        key_size = result.get('key_size_bits', 'Unknown')
        successful = result.get('successful', False)
        
        print(f"Key Size: {key_size} bits")
        print(f"Attack Status: {'✅ SUCCESSFUL' if successful else '❌ FAILED'}")
        
        if successful:
            print(f"First Successful Method: {result.get('successful_method', 'Unknown').replace('_', ' ').title()}")
            print(f"Fastest Attack Time: {result.get('attack_time', 'Unknown'):.4f} seconds")
            
            if result.get('factors'):
                p, q = result['factors']
                print(f"Factor p: {p}")
                print(f"Factor q: {q}")
                print(f"Verification: {p} × {q} = {p * q}")
        
        # Show details of all attempted methods
        print(f"\n📋 Detailed Method Results:")
        print("-" * 70)
        
        for method, details in result.get('attacks', {}).items():
            method_name = method.replace('_', ' ').title()
            status = "✅ Success" if details.get('successful', False) else "❌ Failed"
            time_taken = details.get('time_taken', 0)
            
            print(f"\n🔍 {method_name}:")
            print(f"   Status: {status}")
            print(f"   Time: {time_taken:.4f} seconds")
            
            if details.get('successful', False) and details.get('factors'):
                p, q = details['factors']
                print(f"   Factors: p = {p}, q = {q}")
                print(f"   Verification: {p} × {q} = {p * q}")
            
            if details.get('iterations'):
                print(f"   Iterations: {details['iterations']}")
        
        print("-" * 70)
        
        # Summary of successful methods
        successful_methods = [method for method, details in result.get('attacks', {}).items() 
                            if details.get('successful', False)]
        
        if successful_methods:
            print(f"\n🏆 Summary:")
            print(f"   Successful Methods: {len(successful_methods)}/{len(result.get('attacks', {}))}")
            print(f"   Methods: {', '.join([m.replace('_', ' ').title() for m in successful_methods])}")
            
            # Show time comparison
            if len(successful_methods) > 1:
                print(f"\n⚡ Time Comparison:")
                for method in successful_methods:
                    time_taken = result['attacks'][method]['time_taken']
                    print(f"   {method.replace('_', ' ').title()}: {time_taken:.4f}s")
        else:
            print(f"\n❌ No methods were successful against this {key_size}-bit key")
    def display_benchmark_results(self, results):
        """Display benchmark results summary"""
        print("\n" + "=" * 70)
        print("📊 BENCHMARK RESULTS SUMMARY")
        print("=" * 70)
        
        successful_count = sum(1 for r in results if r.get('successful', False))
        total_count = len(results)
        
        print(f"Total Keys Tested: {total_count}")
        print(f"Successful Attacks: {successful_count}")
        print(f"Failed Attacks: {total_count - successful_count}")
        print(f"Success Rate: {(successful_count/total_count)*100:.1f}%")
        
        if successful_count > 0:
            successful_results = [r for r in results if r.get('successful', False)]
            avg_time = sum(r.get('attack_time', 0) for r in successful_results) / len(successful_results)
            min_time = min(r.get('attack_time', 0) for r in successful_results)
            max_time = max(r.get('attack_time', 0) for r in successful_results)
            
            print(f"\nAttack Time Statistics:")
            print(f"   Average: {avg_time:.4f} seconds")
            print(f"   Minimum: {min_time:.4f} seconds")
            print(f"   Maximum: {max_time:.4f} seconds")