#!/usr/bin/env python3
"""
Pattern matching optimization demonstration
"""

import time
import numpy as np

def slow_pattern_matching(public_keys, target_first_two):
    """Slow pattern matching (current approach)."""
    target_bytes = bytes.fromhex(target_first_two)
    matches = []
    
    for i, public_key in enumerate(public_keys):
        # Convert to hex and check pattern (expensive)
        public_hex = public_key.hex()
        if public_hex.startswith(target_first_two):
            matches.append(i)
    
    return matches

def fast_pattern_matching(public_keys, target_first_two):
    """Fast pattern matching (optimized approach)."""
    target_bytes = bytes.fromhex(target_first_two)
    print(f"Target bytes: {target_bytes} (length: {len(target_bytes)})")
    matches = []
    
    for i, public_key in enumerate(public_keys):
        # Direct byte comparison (fast)
        if len(public_key) >= 2 and len(target_bytes) >= 2:
            if public_key[0] == target_bytes[0] and public_key[1] == target_bytes[1]:
                matches.append(i)
    
    return matches

def vectorized_pattern_matching(public_keys, target_first_two):
    """Vectorized pattern matching (fastest approach)."""
    target_bytes = bytes.fromhex(target_first_two)
    
    # Convert to numpy array for vectorized operations
    public_array = np.array([list(key) for key in public_keys])
    
    # Vectorized comparison
    if len(target_bytes) >= 2:
        matches = np.where((public_array[:, 0] == target_bytes[0]) & 
                          (public_array[:, 1] == target_bytes[1]))[0]
    else:
        matches = np.where(public_array[:, 0] == target_bytes[0])[0]
    
    return matches.tolist()

# Test with 100,000 keys
print("Generating test data...")
public_keys = []
for i in range(100000):
    # Create test keys with some matching the pattern
    if i % 1000 == 0:  # Every 1000th key matches F8
        key = bytes([0xF8, 0x00] + [0] * 30)
    else:
        key = bytes([i % 256, (i >> 8) % 256] + [0] * 30)
    public_keys.append(key)
target_first_two = "F800"  # Two bytes: F8 and 00

print(f"Testing pattern matching on {len(public_keys)} keys...")
print(f"Target pattern: {target_first_two}")

# Test slow approach
start_time = time.time()
slow_matches = slow_pattern_matching(public_keys, target_first_two)
slow_time = time.time() - start_time
print(f"Slow approach: {len(slow_matches)} matches in {slow_time:.3f}s")

# Test fast approach
start_time = time.time()
fast_matches = fast_pattern_matching(public_keys, target_first_two)
fast_time = time.time() - start_time
print(f"Fast approach: {len(fast_matches)} matches in {fast_time:.3f}s")

# Test vectorized approach
start_time = time.time()
vectorized_matches = vectorized_pattern_matching(public_keys, target_first_two)
vectorized_time = time.time() - start_time
print(f"Vectorized approach: {len(vectorized_matches)} matches in {vectorized_time:.3f}s")

print(f"\nSpeedup:")
print(f"Fast vs Slow: {slow_time/fast_time:.1f}x faster")
print(f"Vectorized vs Slow: {slow_time/vectorized_time:.1f}x faster")
