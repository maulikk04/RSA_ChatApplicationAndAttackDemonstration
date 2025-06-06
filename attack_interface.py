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
            "1. Single Key Attack",
            "2. Benchmark Different Key Sizes",
            "3. View Previous Results",
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
                    self.view_previous_results()
                elif choice == '0':
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
                # if key_size < 64 or key_size > 2048:
                #     print("⚠️  Warning: Recommended range is 64-1024 bits for demonstration purposes")
            except ValueError:
                print("❌ Invalid key size. Using default 256 bits.")
                key_size = 256
            
            # Ask for attack methods
            print(f"\nAvailable attack methods:")
            print("1. Trial Division (good for very small keys)")
            print("2. Pollard's Rho (general purpose)")
            print("3. Fermat's Method (good for close factors)")
            print("4. All methods (recommended)")
            
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
            
            # Ask to generate plots
            plot_choice = input("\n📊 Generate visualization plots? (y/n): ").strip().lower()
            if plot_choice == 'y':
                try:
                    self.attacker.plot_attack_results(results)
                except ImportError:
                    print("❌ Matplotlib not available. Install with: pip install matplotlib")
                except Exception as e:
                    print(f"❌ Failed to generate plots: {e}")
            
            # Save results
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