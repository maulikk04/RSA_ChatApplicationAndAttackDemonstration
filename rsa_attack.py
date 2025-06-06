#!/usr/bin/env python3
"""
RSA Attack Module
Demonstrates various RSA attacks including small key attacks and factorization
"""

import os
import time
import math
import json
import logging
import threading
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import matplotlib.pyplot as plt
import numpy as np

logger = logging.getLogger(__name__)

class RSAAttacker:
    """Implements various RSA attacks for demonstration purposes"""
    
    def __init__(self):
        """Initialize RSA Attacker"""
        self.attack_results = []
        self.timing_results = {}
        
    def trial_division_factorization(self, n, max_attempts=1000000):
        """
        Simple trial division factorization for small numbers
        
        Args:
            n (int): Number to factorize
            max_attempts (int): Maximum number of attempts
            
        Returns:
            tuple: (p, q) if factorization successful, (None, None) otherwise
        """
        start_time = time.time()
        
        # Check for small factors first
        for i in range(2, min(int(math.sqrt(n)) + 1, max_attempts)):
            if n % i == 0:
                p = i
                q = n // i
                end_time = time.time()
                return p, q, end_time - start_time
                
        return None, None, time.time() - start_time
    
    def pollard_rho_factorization(self, n, max_iterations=100000):
        """
        Pollard's Rho algorithm for factorization
        
        Args:
            n (int): Number to factorize
            max_iterations (int): Maximum iterations
            
        Returns:
            tuple: (factor, time_taken) or (None, time_taken)
        """
        start_time = time.time()
        
        def f(x):
            return (x * x + 1) % n
        
        def gcd(a, b):
            while b:
                a, b = b, a % b
            return a
        
        x = 2
        y = 2
        d = 1
        
        iterations = 0
        while d == 1 and iterations < max_iterations:
            x = f(x)
            y = f(f(y))
            d = gcd(abs(x - y), n)
            iterations += 1
        
        end_time = time.time()
        
        if d != 1 and d != n:
            return d, end_time - start_time, iterations
        else:
            return None, end_time - start_time, iterations
    
    def fermat_factorization(self, n, max_iterations=100000):
        """
        Fermat's factorization method (optimized version)
        
        Args:
            n (int): Number to factorize
            max_iterations (int): Maximum iterations
            
        Returns:
            tuple: (p, q, time_taken) or (None, None, time_taken)
        """
        start_time = time.time()
        
        try:
            # Handle even numbers
            if n % 2 == 0:
                return 2, n // 2, time.time() - start_time
            
            # For very large numbers, set a reasonable limit
            # Fermat's method is inefficient when factors are far apart
            sqrt_n = int(math.sqrt(n))
            
            # If the number is close to being a perfect square, Fermat's method works well
            # Otherwise, it's very slow. Set a practical limit.
            if n.bit_length() > 512:  # For keys larger than 512 bits
                max_iterations = min(max_iterations, 10000)  # Reduce iterations
            
            # Start with the ceiling of sqrt(n)
            a = sqrt_n
            if a * a < n:
                a += 1
            
            iterations = 0
            while iterations < max_iterations:
                a_squared = a * a
                b_squared = a_squared - n
                
                # Skip if b_squared is negative (shouldn't happen)
                if b_squared < 0:
                    a += 1
                    iterations += 1
                    continue
                
                # Quick check: if b_squared is too large, this method won't be efficient
                if b_squared > sqrt_n:
                    # For efficiency, give up early if we're not finding close factors
                    break
                
                # Check if b_squared is a perfect square
                b = int(math.sqrt(b_squared))
                
                if b * b == b_squared:
                    p = a - b
                    q = a + b
                    
                    # Verify the factorization
                    if p > 1 and q > 1 and p * q == n:
                        end_time = time.time()
                        return p, q, end_time - start_time
                
                a += 1
                iterations += 1
            
            return None, None, time.time() - start_time
            
        except Exception as e:
            logger.error(f"Error in Fermat factorization: {e}")
            return None, None, time.time() - start_time
    
    def extract_rsa_modulus(self, public_key_pem):
        """
        Extract RSA modulus from public key
        
        Args:
            public_key_pem (bytes): Public key in PEM format
            
        Returns:
            int: RSA modulus (n)
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            return public_key.public_numbers().n
        except Exception as e:
            logger.error(f"Failed to extract RSA modulus: {e}")
            raise
    
    def attack_small_key(self, public_key_pem, key_size_bits, attack_methods=None):
        """
        Attempt to attack RSA key using multiple factorization methods
        
        Args:
            public_key_pem (bytes): Public key in PEM format
            key_size_bits (int): Key size in bits
            attack_methods (list): List of attack methods to use
            
        Returns:
            dict: Attack results
        """
        if attack_methods is None:
            attack_methods = ['trial_division', 'pollard_rho', 'fermat']
        
        results = {
            'key_size_bits': key_size_bits,
            'timestamp': datetime.now().isoformat(),
            'attacks': {},
            'successful': False,
            'factors': None
        }
        
        try:
            # Extract modulus
            n = self.extract_rsa_modulus(public_key_pem)
            results['modulus'] = str(n)
            
            print(f"\n🎯 Starting RSA attack on {key_size_bits}-bit key")
            print(f"   Modulus (n): {n}")
            print(f"   Modulus length: {n.bit_length()} bits")
            
            # Try different factorization methods
            for method in attack_methods:
                print(f"\n🔍 Trying {method.replace('_', ' ').title()} attack...")
                
                if method == 'trial_division':
                    p, q, time_taken = self.trial_division_factorization(n)
                    results['attacks'][method] = {
                        'time_taken': time_taken,
                        'successful': p is not None,
                        'factors': [int(p), int(q)] if p else None
                    }
                    
                elif method == 'pollard_rho':
                    factor, time_taken, iterations = self.pollard_rho_factorization(n)
                    if factor:
                        p = factor
                        q = n // factor
                        results['attacks'][method] = {
                            'time_taken': time_taken,
                            'successful': True,
                            'factors': [int(p), int(q)],
                            'iterations': iterations
                        }
                    else:
                        results['attacks'][method] = {
                            'time_taken': time_taken,
                            'successful': False,
                            'factors': None,
                            'iterations': iterations
                        }
                        
                elif method == 'fermat':
                    p, q, time_taken = self.fermat_factorization(n)
                    results['attacks'][method] = {
                        'time_taken': time_taken,
                        'successful': p is not None,
                        'factors': [int(p), int(q)] if p else None
                    }
                
                # Check if attack was successful
                attack_result = results['attacks'][method]
                if attack_result['successful']:
                    print(f"   ✅ {method.replace('_', ' ').title()} attack SUCCESSFUL!")
                    print(f"   ⏱️  Time taken: {attack_result['time_taken']:.4f} seconds")
                    print(f"   🔑 Factors found: p = {attack_result['factors'][0]}, q = {attack_result['factors'][1]}")
                    
                    results['successful'] = True
                    results['factors'] = attack_result['factors']
                    results['successful_method'] = method
                    results['attack_time'] = attack_result['time_taken']
                    
                    # Verify factorization
                    if attack_result['factors'][0] * attack_result['factors'][1] == n:
                        print(f"   ✅ Factorization verified: {attack_result['factors'][0]} × {attack_result['factors'][1]} = {n}")
                    else:
                        print(f"   ❌ Factorization verification failed!")
                    
                    #break
                else:
                    print(f"   ❌ {method.replace('_', ' ').title()} attack failed")
                    print(f"   ⏱️  Time taken: {attack_result['time_taken']:.4f} seconds")
            
            if not results['successful']:
                print(f"\n❌ All attack methods failed for {key_size_bits}-bit key")
            
        except Exception as e:
            logger.error(f"RSA attack failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def benchmark_key_sizes(self, key_sizes=[128, 256, 384, 512, 768, 1024], attack_methods=None):
        """
        Benchmark RSA attacks against different key sizes
        
        Args:
            key_sizes (list): List of key sizes to test
            attack_methods (list): Attack methods to use
            
        Returns:
            list: List of attack results
        """
        if attack_methods is None:
            attack_methods = ['trial_division', 'pollard_rho', 'fermat']
        
        results = []
        
        print(f"\n🚀 Starting RSA Attack Benchmark")
        print(f"   Key sizes to test: {key_sizes}")
        print(f"   Attack methods: {attack_methods}")
        print("=" * 60)
        
        for key_size in key_sizes:
            print(f"\n📊 Testing {key_size}-bit RSA key...")
            
            try:
                # Generate key pair for testing
                from rsa_key_manager import RSAKeyManager
                private_key, public_key = RSAKeyManager.generate_key_pair(key_size)
                public_key_pem = RSAKeyManager.serialize_public_key(public_key)
                
                # Attack the key
                result = self.attack_small_key(public_key_pem, key_size, attack_methods)
                results.append(result)
                
                # Store for plotting
                self.attack_results.append(result)
                
            except Exception as e:
                logger.error(f"Failed to test {key_size}-bit key: {e}")
                results.append({
                    'key_size_bits': key_size,
                    'error': str(e),
                    'successful': False
                })
        
        return results
    
    def save_results(self, results, filename="rsa_attack_results.json"):
        """Save attack results to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n💾 Results saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
    
    def generate_attack_report(self, results):
        """Generate a comprehensive attack report"""
        print("\n" + "=" * 80)
        print("🎯 RSA ATTACK ANALYSIS REPORT")
        print("=" * 80)
        
        successful_attacks = [r for r in results if r.get('successful', False)]
        failed_attacks = [r for r in results if not r.get('successful', False)]
        
        print(f"\n📊 SUMMARY:")
        print(f"   Total keys tested: {len(results)}")
        print(f"   Successful attacks: {len(successful_attacks)}")
        print(f"   Failed attacks: {len(failed_attacks)}")
        
        if successful_attacks:
            print(f"\n✅ SUCCESSFUL ATTACKS:")
            for result in successful_attacks:
                print(f"   • {result['key_size_bits']}-bit key: {result['successful_method']} in {result['attack_time']:.4f}s")
        
        if failed_attacks:
            print(f"\n❌ FAILED ATTACKS:")
            for result in failed_attacks:
                if 'error' not in result:
                    print(f"   • {result['key_size_bits']}-bit key: All methods failed")
        
        print("\n🔍 DETAILED ANALYSIS:")
        for result in results:
            if result.get('successful', False):
                print(f"\n   {result['key_size_bits']}-bit Key Analysis:")
                print(f"   ├── Modulus: {result.get('modulus', 'N/A')[:50]}...")
                print(f"   ├── Successful Method: {result['successful_method']}")
                print(f"   ├── Attack Time: {result['attack_time']:.4f} seconds")
                if result.get('factors'):
                    print(f"   ├── Factor p: {result['factors'][0]}")
                    print(f"   └── Factor q: {result['factors'][1]}")
    
    def plot_attack_results(self, results, save_plot=True):
        """Create visualization of attack results"""
        try:
            # Prepare data for plotting
            key_sizes = []
            attack_times = []
            success_status = []
            
            for result in results:
                if result.get('successful', False):
                    key_sizes.append(result['key_size_bits'])
                    attack_times.append(result['attack_time'])
                    success_status.append('Success')
                else:
                    key_sizes.append(result['key_size_bits'])
                    attack_times.append(0)  # 0 for failed attacks
                    success_status.append('Failed')
            
            if not key_sizes:
                print("No data available for plotting")
                return
            
            # Create plots
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
            
            # Plot 1: Attack time vs Key size
            successful_indices = [i for i, status in enumerate(success_status) if status == 'Success']
            failed_indices = [i for i, status in enumerate(success_status) if status == 'Failed']
            
            if successful_indices:
                successful_key_sizes = [key_sizes[i] for i in successful_indices]
                successful_times = [attack_times[i] for i in successful_indices]
                ax1.scatter(successful_key_sizes, successful_times, c='green', label='Successful', s=100, alpha=0.7)
                ax1.plot(successful_key_sizes, successful_times, 'g--', alpha=0.5)
            
            if failed_indices:
                failed_key_sizes = [key_sizes[i] for i in failed_indices]
                ax1.scatter(failed_key_sizes, [0.001] * len(failed_key_sizes), c='red', label='Failed', s=100, alpha=0.7)
            
            ax1.set_xlabel('Key Size (bits)')
            ax1.set_ylabel('Attack Time (seconds)')
            ax1.set_title('RSA Attack Time vs Key Size')
            ax1.set_yscale('log')
            ax1.legend()
            ax1.grid(True, alpha=0.3)
            
            # Plot 2: Success rate
            unique_key_sizes = sorted(list(set(key_sizes)))
            success_rates = []
            
            for key_size in unique_key_sizes:
                total = sum(1 for ks in key_sizes if ks == key_size)
                successful = sum(1 for i, ks in enumerate(key_sizes) if ks == key_size and success_status[i] == 'Success')
                success_rates.append(successful / total * 100)
            
            bars = ax2.bar(unique_key_sizes, success_rates, color=['green' if rate > 0 else 'red' for rate in success_rates], alpha=0.7)
            ax2.set_xlabel('Key Size (bits)')
            ax2.set_ylabel('Success Rate (%)')
            ax2.set_title('Attack Success Rate by Key Size')
            ax2.set_ylim(0, 105)
            
            # Add value labels on bars
            for bar, rate in zip(bars, success_rates):
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height + 1,
                        f'{rate:.1f}%', ha='center', va='bottom')
            
            ax2.grid(True, alpha=0.3)
            
            plt.tight_layout()
            
            if save_plot:
                plt.savefig('rsa_attack_analysis.png', dpi=300, bbox_inches='tight')
                print(f"\n📊 Plot saved as 'rsa_attack_analysis.png'")
            
            plt.show()
            
        except Exception as e:
            logger.error(f"Failed to create plot: {e}")
            print(f"❌ Failed to create plot: {e}")
    
    def create_comparison_table(self, results):
        """Create a comparison table of attack results"""
        print("\n" + "=" * 100)
        print("📊 RSA ATTACK COMPARISON TABLE")
        print("=" * 100)
        
        # Table header
        print(f"{'Key Size':<10} {'Status':<10} {'Method':<15} {'Time (s)':<12} {'Factors Found':<30}")
        print("-" * 100)
        
        for result in results:
            key_size = result['key_size_bits']
            
            if result.get('successful', False):
                status = "✅ SUCCESS"
                method = result['successful_method'].replace('_', ' ').title()
                time_taken = f"{result['attack_time']:.4f}"
                if result.get('factors'):
                    factors = f"p={result['factors'][0]}, q={result['factors'][1]}"
                    if len(factors) > 28:
                        factors = factors[:25] + "..."
                else:
                    factors = "N/A"
            else:
                status = "❌ FAILED"
                method = "All methods"
                time_taken = "N/A"
                factors = "None"
            
            print(f"{key_size:<10} {status:<10} {method:<15} {time_taken:<12} {factors:<30}")
        
        print("-" * 100)