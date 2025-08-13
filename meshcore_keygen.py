#!/usr/bin/env python3
"""
MeshCore Ed25519 Vanity Key Generator
Generates Ed25519 keys with various vanity patterns.
Now uses the CORRECT Ed25519 format that MeshCore actually expects.

Requirements:
    pip install PyNaCl
    pip install psutil (optional, for health monitoring)

KEY INSIGHT: MeshCore uses Ed25519 with custom scalar clamping!
- PRV_KEY_SIZE = 64 (Ed25519 extended private key: [clamped_scalar][random_filler])
- PUB_KEY_SIZE = 32 (Ed25519 public key)
- Uses crypto_scalarmult_ed25519_base_noclamp with manually clamped scalars

NEW: Batch Processing System
Workers now process keys in configurable batches and check in with the main process.
This allows for faster termination when a key is found and better resource utilization.
Use --batch-size to configure batch size (default: 1M keys).

NEW: Health Check System
Monitors performance and automatically restarts workers if performance degrades.
Features:
- Memory usage monitoring (requires psutil)
- Performance tracking with automatic worker restart
- Garbage collection optimization
- System resource monitoring
- Performance degradation detection and recovery

Vanity Pattern Modes:
  --vanity-2: First 2 hex chars == last 2 hex chars OR palindromic
  --vanity-4: First 4 hex chars == last 4 hex chars OR palindromic  
  --vanity-6: First 6 hex chars == last 6 hex chars OR palindromic
  --vanity-8: First 8 hex chars == last 8 hex chars OR palindromic (default)
  --four-char: Legacy mode with 4-char vanity + optional --first-two constraint
  --prefix: Keys starting with specific hex prefix
  --prefix-vanity: Prefix + 8-char vanity pattern
  --simple: Only check first two hex chars (requires --first-two)

Usage:
    python meshcore_keygen.py                    # Run until max iterations
    python meshcore_keygen.py --keys 100         # Run for 100 million keys
    python meshcore_keygen.py --time 2           # Run for 2 hours
    python meshcore_keygen.py --batch-size 500K  # Use 500K keys per batch
    python meshcore_keygen.py --first-two F8     # Search for keys starting with F8
    python meshcore_keygen.py --vanity-4         # Search for 4-char vanity patterns
    python meshcore_keygen.py --vanity-6         # Search for 6-char vanity patterns
    python meshcore_keygen.py --health-check     # Enable health monitoring (default)
    python meshcore_keygen.py --no-health-check  # Disable health monitoring
"""

import os
import time
import multiprocessing as mp
import platform
import subprocess
import argparse
import hashlib
import secrets
import gc
import threading
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any, List
from enum import Enum
from multiprocessing import Manager
import concurrent.futures

# Use PyNaCl for the correct crypto functions that MeshCore uses
from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp
from nacl.utils import random as random_bytes

# Try to import psutil for health monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not installed. Health monitoring will be limited.")
    print("Install with: pip install psutil")


class VanityMode(Enum):
    """Enum for different vanity pattern modes."""
    SIMPLE = "simple"
    PREFIX = "prefix"
    FOUR_CHAR = "four_char"
    PREFIX_VANITY = "prefix_vanity"
    VANITY_2 = "vanity_2"
    VANITY_4 = "vanity_4"
    VANITY_6 = "vanity_6"
    VANITY_8 = "vanity_8"
    DEFAULT = "default"


@dataclass
class WatchlistPattern:
    """Represents a pattern to watch for in the public key."""
    pattern: str  # e.g., "ABCD...EFGH" or "ABCD...ABCDEFGH"
    description: str  # Optional description
    first_chars: str  # First part of pattern
    last_chars: str   # Last part of pattern
    first_length: int  # Length of first part
    last_length: int   # Length of last part
    
    @classmethod
    def from_string(cls, pattern_str: str, description: str = "") -> 'WatchlistPattern':
        """Create a WatchlistPattern from a string like 'ABCD...EFGH'."""
        if '...' not in pattern_str:
            raise ValueError(f"Invalid pattern format: {pattern_str}. Must contain '...'")
        
        parts = pattern_str.split('...')
        if len(parts) != 2:
            raise ValueError(f"Invalid pattern format: {pattern_str}. Must have exactly one '...'")
        
        first_part = parts[0].strip()
        last_part = parts[1].strip()
        
        if not first_part or not last_part:
            raise ValueError(f"Invalid pattern format: {pattern_str}. Both parts must be non-empty")
        
        # Validate hex characters
        try:
            int(first_part, 16)
            int(last_part, 16)
        except ValueError:
            raise ValueError(f"Invalid pattern format: {pattern_str}. Parts must be valid hex")
        
        return cls(
            pattern=pattern_str,
            description=description,
            first_chars=first_part.upper(),
            last_chars=last_part.upper(),
            first_length=len(first_part),
            last_length=len(last_part)
        )
    
    def matches(self, public_hex: str) -> bool:
        """Check if a public key matches this pattern."""
        public_hex = public_hex.upper()
        return (public_hex[:self.first_length] == self.first_chars and 
                public_hex[-self.last_length:] == self.last_chars)


@dataclass
class VanityConfig:
    """Configuration for vanity key generation."""
    mode: VanityMode
    target_first_two: Optional[str] = None
    target_prefix: Optional[str] = None
    vanity_length: int = 8
    max_iterations: Optional[int] = None
    max_time: Optional[int] = None
    num_workers: Optional[int] = None
    batch_size: int = 1000000  # Default batch size: 1 million keys
    watchlist_file: Optional[str] = None  # Path to watchlist file
    watchlist_patterns: List[WatchlistPattern] = None  # Loaded watchlist patterns
    health_check: bool = True # Default to True for health monitoring
    verbose: bool = False # Default to False for clean output


@dataclass
class KeyInfo:
    """Container for generated key information."""
    public_hex: str
    private_hex: str
    public_bytes: bytes
    private_bytes: bytes
    matching_pattern: str
    first_8_hex: str
    last_8_hex: str


@dataclass
class BatchResult:
    """Result from a worker batch."""
    worker_id: int
    attempts: int
    found_key: Optional[KeyInfo] = None
    batch_completed: bool = True


def load_watchlist_patterns(file_path: str) -> List[WatchlistPattern]:
    """Load watchlist patterns from a file."""
    patterns = []
    
    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse pattern and optional description
                if '|' in line:
                    pattern_part, description = line.split('|', 1)
                    pattern_part = pattern_part.strip()
                    description = description.strip()
                else:
                    pattern_part = line.strip()
                    description = ""
                
                try:
                    pattern = WatchlistPattern.from_string(pattern_part, description)
                    patterns.append(pattern)
                except ValueError as e:
                    print(f"Warning: Invalid pattern on line {line_num}: {e}")
                    continue
        
        print(f"Loaded {len(patterns)} watchlist patterns from {file_path}")
        return patterns
        
    except FileNotFoundError:
        print(f"Warning: Watchlist file not found: {file_path}")
        return []
    except Exception as e:
        print(f"Error loading watchlist file: {e}")
        return []


def save_watchlist_key(key_info: KeyInfo, pattern: WatchlistPattern) -> Tuple[str, str]:
    """Save a watchlist key to files and return filenames."""
    # Create a safe filename from the pattern
    safe_pattern = pattern.pattern.replace('...', '_').replace('|', '_')
    key_id = key_info.public_hex[:8].upper()
    
    pub_filename = f"watchlist_{safe_pattern}_{key_id}_public.txt"
    priv_filename = f"watchlist_{safe_pattern}_{key_id}_private.txt"
    
    with open(pub_filename, 'w') as f:
        f.write(key_info.public_hex)
    
    with open(priv_filename, 'w') as f:
        f.write(key_info.private_hex)
    
    print(f"  Saved watchlist key to:")
    print(f"    Public:  {pub_filename}")
    print(f"    Private: {priv_filename}")
    
    return pub_filename, priv_filename


class KeyValidator:
    """Validates generated keys against patterns."""
    
    @staticmethod
    def check_vanity_pattern(public_hex: str, config: VanityConfig) -> bool:
        """Check if a public key matches the desired vanity pattern."""
        if config.mode == VanityMode.SIMPLE:
            return KeyValidator._check_simple_pattern(public_hex, config.target_first_two)
        elif config.mode == VanityMode.PREFIX:
            return KeyValidator._check_prefix_pattern(public_hex, config.target_prefix)
        elif config.mode == VanityMode.VANITY_2:
            return KeyValidator._check_vanity_n_pattern(public_hex, 2)
        elif config.mode == VanityMode.VANITY_4:
            return KeyValidator._check_vanity_n_pattern(public_hex, 4)
        elif config.mode == VanityMode.VANITY_6:
            return KeyValidator._check_vanity_n_pattern(public_hex, 6)
        elif config.mode == VanityMode.VANITY_8:
            return KeyValidator._check_vanity_n_pattern(public_hex, 8)
        elif config.mode == VanityMode.FOUR_CHAR:
            return KeyValidator._check_four_char_pattern(public_hex, config.target_first_two)
        elif config.mode == VanityMode.PREFIX_VANITY:
            return KeyValidator._check_prefix_vanity_pattern(public_hex, config.target_prefix, config.vanity_length)
        else:  # DEFAULT
            return KeyValidator._check_default_pattern(public_hex, config.target_first_two)
    
    @staticmethod
    def check_watchlist_patterns(public_hex: str, config: VanityConfig) -> List[WatchlistPattern]:
        """Check if a public key matches any watchlist patterns."""
        matches = []
        if config.watchlist_patterns:
            for pattern in config.watchlist_patterns:
                if pattern.matches(public_hex):
                    matches.append(pattern)
        return matches
    
    @staticmethod
    def _check_simple_pattern(public_hex: str, target_first_two: Optional[str]) -> bool:
        """Check simple pattern: specific first two hex characters."""
        if not target_first_two:
            return True
        return public_hex[:2].upper() == target_first_two.upper()
    
    @staticmethod
    def _check_prefix_pattern(public_hex: str, target_prefix: Optional[str]) -> bool:
        """Check prefix pattern: key starts with specific prefix."""
        if not target_prefix:
            return False
        prefix_length = len(target_prefix)
        return public_hex[:prefix_length].upper() == target_prefix.upper()
    
    @staticmethod
    def _check_vanity_n_pattern(public_hex: str, n: int) -> bool:
        """Check if first n hex chars match last n hex chars or are palindromic."""
        first_n = public_hex[:n]
        last_n = public_hex[-n:]
        return first_n == last_n or first_n == last_n[::-1]
    
    @staticmethod
    def _check_four_char_pattern(public_hex: str, target_first_two: Optional[str]) -> bool:
        """Check four-char pattern with optional first-two constraint."""
        if not KeyValidator._check_vanity_n_pattern(public_hex, 4):
            return False
        if target_first_two:
            return KeyValidator._check_simple_pattern(public_hex, target_first_two)
        return True
    
    @staticmethod
    def _check_prefix_vanity_pattern(public_hex: str, target_prefix: Optional[str], vanity_length: int = 8) -> bool:
        """Check prefix-vanity pattern: specific prefix AND n-char vanity."""
        return (KeyValidator._check_prefix_pattern(public_hex, target_prefix) and 
                KeyValidator._check_vanity_n_pattern(public_hex, vanity_length))
    
    @staticmethod
    def _check_default_pattern(public_hex: str, target_first_two: Optional[str]) -> bool:
        """Check default pattern: 8-char vanity with optional first-two constraint."""
        if not KeyValidator._check_vanity_n_pattern(public_hex, 8):
            return False
        if target_first_two:
            return KeyValidator._check_simple_pattern(public_hex, target_first_two)
        return True


class Ed25519KeyGenerator:
    """Generates Ed25519 keys in MeshCore format using the CORRECT algorithm."""
    
    @staticmethod
    def generate_meshcore_keypair():
        """
        Generate a MeshCore-compatible Ed25519 keypair.
        This uses the CORRECT algorithm that MeshCore actually uses:
        1. Generate 32-byte random seed
        2. SHA512 hash the seed
        3. Manually clamp the first 32 bytes (scalar clamping)
        4. Use crypto_scalarmult_ed25519_base_noclamp to get public key
        5. Private key = [clamped_scalar][random_filler]
        """
        # Step 1: Generate 32-byte random seed
        seed = random_bytes(32)
        
        # Step 2: Hash the seed with SHA512
        digest = hashlib.sha512(seed).digest()
        
        # Step 3: Clamp the first 32 bytes according to Ed25519 rules
        clamped = bytearray(digest[:32])
        clamped[0] &= 248      # Clear bottom 3 bits (make it divisible by 8)
        clamped[31] &= 63      # Clear top 2 bits
        clamped[31] |= 64      # Set bit 6 (ensure it's in the right range)
        
        # Step 4: Use the clamped scalar to generate the public key
        public_key = crypto_scalarmult_ed25519_base_noclamp(bytes(clamped))
        
        # Step 5: Create 64-byte private key [clamped_scalar][random_filler]
        filler = random_bytes(32)
        private_key = bytes(clamped) + filler
        
        return public_key, private_key
    
    @staticmethod
    def generate_single_key(config: VanityConfig) -> Optional[KeyInfo]:
        """Generate a single Ed25519 key in MeshCore format."""
        public_bytes, private_bytes = Ed25519KeyGenerator.generate_meshcore_keypair()
        public_hex = public_bytes.hex()
        
        if KeyValidator.check_vanity_pattern(public_hex, config):
            return KeyInfo(
                public_hex=public_hex,
                private_hex=private_bytes.hex(),  # 128 hex characters (64 bytes)
                public_bytes=public_bytes,
                private_bytes=private_bytes,
                matching_pattern=public_hex[:8],
                first_8_hex=public_hex[:8],
                last_8_hex=public_hex[-8:]
            )
        
        return None
    
    @staticmethod
    def generate_any_key() -> KeyInfo:
        """Generate any Ed25519 key in MeshCore format (no pattern constraints)."""
        public_bytes, private_bytes = Ed25519KeyGenerator.generate_meshcore_keypair()
        public_hex = public_bytes.hex()
        
        return KeyInfo(
            public_hex=public_hex,
            private_hex=private_bytes.hex(),  # 128 hex characters (64 bytes)
            public_bytes=public_bytes,
            private_bytes=private_bytes,
            matching_pattern=public_hex[:8],
            first_8_hex=public_hex[:8],
            last_8_hex=public_hex[-8:]
        )
    
    @staticmethod
    def verify_key_compatibility(private_hex: str, expected_public_hex: str) -> bool:
        """Verify that a MeshCore private key produces the expected public key."""
        try:
            private_bytes = bytes.fromhex(private_hex)
            
            if len(private_bytes) != 64:
                print(f"Error: Private key must be 64 bytes, got {len(private_bytes)}")
                return False
            
            # Extract the clamped scalar (first 32 bytes)
            clamped_scalar = private_bytes[:32]
            
            # Regenerate the public key using MeshCore's method
            derived_public_bytes = crypto_scalarmult_ed25519_base_noclamp(clamped_scalar)
            derived_public_hex = derived_public_bytes.hex()
            
            return derived_public_hex == expected_public_hex
            
        except Exception as e:
            print(f"Key verification failed: {e}")
            return False


class SystemUtils:
    """Utility functions for system information."""
    
    @staticmethod
    def get_optimal_worker_count() -> int:
        """Detect optimal number of worker processes."""
        if platform.system() == 'Windows':
            return SystemUtils._get_windows_worker_count()
        elif platform.system() == 'Darwin':
            return SystemUtils._get_macos_worker_count()
        else:
            return mp.cpu_count()
    
    @staticmethod
    def _get_windows_worker_count() -> int:
        """Get optimal worker count for Windows."""
        cpu_count = mp.cpu_count()
        physical_cores = cpu_count // 2
        recommended_cores = max(2, physical_cores - 2)
        print(f"Windows detected: {physical_cores} estimated physical cores, {cpu_count} logical cores")
        print(f"Using {recommended_cores} cores (n-2 strategy)")
        return recommended_cores
    
    @staticmethod
    def _get_macos_worker_count() -> int:
        """Get optimal worker count for macOS."""
        try:
            result = subprocess.run(['sysctl', '-n', 'machdep.cpu.brand_string'], 
                                  capture_output=True, text=True, check=False)
            if 'Apple' in result.stdout:
                return SystemUtils._get_apple_silicon_cores()
            else:
                return SystemUtils._get_intel_mac_cores()
        except Exception as e:
            print(f"Warning: Could not detect processor type: {e}")
            return mp.cpu_count()
    
    @staticmethod
    def _get_apple_silicon_cores() -> int:
        """Get performance cores for Apple Silicon."""
        try:
            result = subprocess.run(['sysctl', '-n', 'hw.perflevel0.physicalcpu'], 
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0:
                perf_cores = int(result.stdout.strip())
                print(f"Detected {perf_cores} performance cores on Apple Silicon")
                return perf_cores
        except Exception:
            pass
        
        # Fallback estimation
        try:
            result = subprocess.run(['sysctl', '-n', 'hw.ncpu'], 
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0:
                total_cores = int(result.stdout.strip())
                perf_cores = SystemUtils._estimate_apple_perf_cores(total_cores)
                print(f"Estimated {perf_cores} performance cores (total: {total_cores})")
                return perf_cores
        except Exception:
            pass
        
        return 4  # Safe fallback
    
    @staticmethod
    def _estimate_apple_perf_cores(total_cores: int) -> int:
        """Estimate Apple Silicon performance cores from total cores."""
        if total_cores >= 16:
            return 8  # M1 Pro/Max or M2/M3/M4 Pro/Max
        elif total_cores >= 12:
            return 6  # M2/M3/M4 with 6-8 perf cores
        else:
            return 4  # M1 or M2 with 4 perf cores
    
    @staticmethod
    def _get_intel_mac_cores() -> int:
        """Get optimal cores for Intel Mac."""
        try:
            result = subprocess.run(['sysctl', '-n', 'hw.physicalcpu'], 
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0:
                physical_cores = int(result.stdout.strip())
                recommended_cores = max(2, physical_cores - 2)
                print(f"Intel Mac detected: {physical_cores} physical cores")
                print(f"Using {recommended_cores} cores (n-2 strategy)")
                return recommended_cores
        except Exception:
            pass
        
        return max(2, mp.cpu_count() // 2 - 2)


class HealthMonitor:
    """Monitors system health and performance metrics."""
    
    def __init__(self, worker_id: int, config: VanityConfig):
        self.worker_id = worker_id
        self.config = config
        self.start_time = time.time()
        self.last_gc_time = time.time()
        self.last_memory_check = time.time()
        self.initial_memory = self._get_memory_usage()
        self.performance_history = []
        self.max_history_size = 10
        self.gc_interval = 120  # Force GC every 2 minutes (reduced frequency)
        self.memory_check_interval = 30  # Check memory every 30 seconds (reduced frequency)
        self.memory_threshold = 200 * 1024 * 1024  # 200MB increase threshold (increased threshold)
        self.performance_threshold = 0.7  # 70% performance degradation threshold
        
    def _get_memory_usage(self) -> int:
        """Get current memory usage in bytes."""
        if not PSUTIL_AVAILABLE:
            return 0
        
        try:
            process = psutil.Process()
            return process.memory_info().rss
        except Exception:
            return 0
    
    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        if not PSUTIL_AVAILABLE:
            return 0.0
        
        try:
            process = psutil.Process()
            return process.cpu_percent(interval=0.1)
        except Exception:
            return 0.0
    
    def check_health(self, current_rate: float, batch_attempts: int, batch_time: float) -> Dict[str, Any]:
        """Check system health and return health status."""
        current_time = time.time()
        health_status = {
            'healthy': True,
            'warnings': [],
            'actions_taken': [],
            'memory_usage': 0,
            'cpu_usage': 0.0,
            'performance_ratio': 1.0
        }
        
        # Check memory usage (only if psutil is available)
        if PSUTIL_AVAILABLE and current_time - self.last_memory_check >= self.memory_check_interval:
            current_memory = self._get_memory_usage()
            memory_increase = current_memory - self.initial_memory
            
            health_status['memory_usage'] = current_memory
            health_status['cpu_usage'] = self._get_cpu_usage()
            
            if memory_increase > self.memory_threshold:
                health_status['warnings'].append(f"Memory usage increased by {memory_increase / 1024 / 1024:.1f}MB")
                health_status['actions_taken'].append("Triggered garbage collection")
                gc.collect()
                self.last_gc_time = current_time
            
            self.last_memory_check = current_time
        
        # Force periodic garbage collection (always available)
        if current_time - self.last_gc_time >= self.gc_interval:
            health_status['actions_taken'].append("Periodic garbage collection")
            gc.collect()
            self.last_gc_time = current_time
        
        # Track performance
        if batch_time > 0:
            current_rate = batch_attempts / batch_time
            self.performance_history.append(current_rate)
            
            # Keep only recent history
            if len(self.performance_history) > self.max_history_size:
                self.performance_history.pop(0)
            
            # Calculate performance ratio
            if len(self.performance_history) >= 3:
                recent_avg = sum(self.performance_history[-3:]) / 3
                older_avg = sum(self.performance_history[:-3]) / max(1, len(self.performance_history) - 3)
                
                if older_avg > 0:
                    performance_ratio = recent_avg / older_avg
                    health_status['performance_ratio'] = performance_ratio
                    
                    if performance_ratio < self.performance_threshold:
                        health_status['warnings'].append(f"Performance degraded to {performance_ratio:.1%} of baseline")
                        health_status['healthy'] = False
        
        return health_status


class PerformanceTracker:
    """Tracks and analyzes performance metrics over time."""
    
    def __init__(self, probability: float = None, verbose: bool = False):
        self.start_time = time.time()
        self.last_update = time.time()
        self.probability = probability
        self.verbose = verbose
        self.performance_samples = []
        self.max_samples = 20
        self.degradation_threshold = 0.6  # 60% performance drop triggers restart
        
        # Calculate expected attempts based on probability (50% chance of finding)
        if probability and probability > 0:
            self.expected_attempts = int(0.693 / probability)  # ln(2) / p for 50% chance
        else:
            self.expected_attempts = None
    
    def should_update(self, attempts: int, interval_seconds: int = 5, 
                     interval_attempts: int = 1000000) -> bool:
        """Check if progress should be updated."""
        current_time = time.time()
        return (current_time - self.last_update >= interval_seconds or 
                attempts % interval_attempts == 0)
    
    def update(self, worker_id: int, attempts: int, current_rate: float = None):
        """Update progress display."""
        elapsed = time.time() - self.start_time
        rate = attempts / elapsed if elapsed > 0 else 0
        
        # Track performance samples
        if current_rate is not None:
            self.performance_samples.append({
                'time': elapsed,
                'rate': current_rate,
                'attempts': attempts
            })
            
            # Keep only recent samples
            if len(self.performance_samples) > self.max_samples:
                self.performance_samples.pop(0)
        
        eta = self._estimate_eta(attempts, elapsed, rate)
        
        # Only print if verbose mode is enabled
        if self.verbose:
            print(f"Worker {worker_id}: {attempts:,} attempts | "
                  f"{rate:,.0f} keys/sec | {elapsed:.1f}s | ETA: {eta}")
        
        self.last_update = time.time()
    
    def check_performance_degradation(self) -> Tuple[bool, float]:
        """Check if performance has degraded significantly."""
        if len(self.performance_samples) < 5:
            return False, 1.0
        
        # Calculate recent vs baseline performance
        recent_samples = self.performance_samples[-3:]
        baseline_samples = self.performance_samples[:-3]
        
        if len(baseline_samples) < 2:
            return False, 1.0
        
        recent_avg = sum(s['rate'] for s in recent_samples) / len(recent_samples)
        baseline_avg = sum(s['rate'] for s in baseline_samples) / len(baseline_samples)
        
        if baseline_avg > 0:
            performance_ratio = recent_avg / baseline_avg
            return performance_ratio < self.degradation_threshold, performance_ratio
        
        return False, 1.0
    
    def _estimate_eta(self, attempts: int, elapsed: float, rate: float) -> str:
        """Estimate time remaining based on probability and current progress."""
        if attempts == 0 or rate == 0:
            return "Calculating..."
        
        if self.expected_attempts is None:
            return "Unknown"
        
        # Calculate remaining attempts (expected - current)
        remaining_attempts = max(0, self.expected_attempts - attempts)
        
        # If we've exceeded expected attempts, show a more conservative estimate
        if remaining_attempts <= 0:
            # Use 90% confidence interval (2.3 / probability)
            conservative_attempts = int(2.3 / self.probability) - attempts
            remaining_attempts = max(0, conservative_attempts)
        
        remaining_seconds = remaining_attempts / rate
        
        if remaining_seconds < 60:
            return f"{remaining_seconds:.0f}s"
        elif remaining_seconds < 3600:
            return f"{remaining_seconds/60:.1f}m"
        else:
            return f"{remaining_seconds/3600:.1f}h"


def worker_process_batch(worker_id: int, config: VanityConfig, shared_state: Dict[str, Any]) -> BatchResult:
    """Worker process that generates keys in batches and checks in with main process."""
    batch_size = config.batch_size
    max_time = config.max_time
    start_time = time.time()
    
    # Calculate probability for accurate ETA
    probability = calculate_pattern_probability(config)
    tracker = PerformanceTracker(probability, config.verbose)
    
    # Initialize health monitor if enabled
    health_monitor = None
    if config.health_check:
        try:
            health_monitor = HealthMonitor(worker_id, config)
            if config.verbose:
                print(f"Worker {worker_id}: Health monitoring enabled")
        except Exception as e:
            if config.verbose:
                print(f"Worker {worker_id}: Failed to initialize health monitor: {e}")
    
    total_attempts = 0
    consecutive_slow_batches = 0
    max_slow_batches = 3  # Restart after 3 consecutive slow batches
    
    while True:
        batch_start_time = time.time()
        batch_attempts = 0
        
        # Check if another worker found a key
        if shared_state.get('key_found', False):
            return BatchResult(worker_id=worker_id, attempts=total_attempts, batch_completed=False)
        
        # Check time limit
        if max_time and (time.time() - start_time) > max_time:
            return BatchResult(worker_id=worker_id, attempts=total_attempts, batch_completed=False)
        
        # Process this batch
        for attempt in range(batch_size):
            # Check if another worker found a key (check every 100K attempts to reduce overhead)
            if attempt % 100000 == 0 and attempt > 0 and shared_state.get('key_found', False):
                return BatchResult(worker_id=worker_id, attempts=total_attempts + attempt, batch_completed=False)
            
            # Check time limit
            if max_time and (time.time() - start_time) > max_time:
                return BatchResult(worker_id=worker_id, attempts=total_attempts + attempt, batch_completed=False)
            
            # Update progress
            if tracker.should_update(total_attempts + attempt):
                tracker.update(worker_id, total_attempts + attempt)
            
            # Generate and check key
            result = Ed25519KeyGenerator.generate_single_key(config)
            
            # Always generate a key to check for watchlist patterns
            any_key = Ed25519KeyGenerator.generate_any_key()
            if Ed25519KeyGenerator.verify_key_compatibility(any_key.private_hex, any_key.public_hex):
                # Check for watchlist matches
                watchlist_matches = KeyValidator.check_watchlist_patterns(any_key.public_hex, config)
                if watchlist_matches:
                    for pattern in watchlist_matches:
                        print(f"Worker {worker_id}: Found WATCHLIST match! Pattern: {pattern.pattern}")
                        if pattern.description:
                            print(f"  Description: {pattern.description}")
                        
                        # Save watchlist key
                        save_watchlist_key(any_key, pattern)
            
            if result:
                # Verify the generated key works correctly
                if Ed25519KeyGenerator.verify_key_compatibility(result.private_hex, result.public_hex):
                    # Check if this matches the primary target
                    if KeyValidator.check_vanity_pattern(result.public_hex, config):
                        print(f"Worker {worker_id}: Found valid MeshCore Ed25519 key!")
                        # Set the shared state to indicate a key was found
                        shared_state['key_found'] = True
                        shared_state['found_key'] = result
                        return BatchResult(worker_id=worker_id, attempts=total_attempts + attempt + 1, found_key=result)
                    else:
                        continue
                else:
                    print(f"Worker {worker_id}: Generated key failed compatibility check!")
                    continue
            
            batch_attempts += 1
        
        total_attempts += batch_attempts
        batch_time = time.time() - batch_start_time
        current_rate = batch_attempts / batch_time if batch_time > 0 else 0
        
        # Health monitoring and performance checks
        if health_monitor:
            health_status = health_monitor.check_health(current_rate, batch_attempts, batch_time)
            
            # Report health status if there are warnings or actions (only in verbose mode)
            if config.verbose and (health_status['warnings'] or health_status['actions_taken']):
                print(f"Worker {worker_id} Health Check:")
                for warning in health_status['warnings']:
                    print(f"  ⚠️  {warning}")
                for action in health_status['actions_taken']:
                    print(f"  🔧 {action}")
                
                if health_status['memory_usage'] > 0:
                    print(f"  📊 Memory: {health_status['memory_usage'] / 1024 / 1024:.1f}MB")
                if health_status['cpu_usage'] > 0:
                    print(f"  📊 CPU: {health_status['cpu_usage']:.1f}%")
                if health_status['performance_ratio'] < 1.0:
                    print(f"  📊 Performance: {health_status['performance_ratio']:.1%} of baseline")
            
            # Check for severe performance degradation
            if not health_status['healthy']:
                consecutive_slow_batches += 1
                if config.verbose:
                    print(f"Worker {worker_id}: Performance degradation detected ({consecutive_slow_batches}/{max_slow_batches})")
                
                if consecutive_slow_batches >= max_slow_batches:
                    if config.verbose:
                        print(f"Worker {worker_id}: Restarting due to performance degradation")
                    # Force garbage collection before restart
                    gc.collect()
                    return BatchResult(worker_id=worker_id, attempts=total_attempts, batch_completed=False)
            else:
                consecutive_slow_batches = 0
        
        # Update tracker with current rate for performance analysis
        tracker.update(worker_id, total_attempts, current_rate)
        
        # Report batch completion (only in verbose mode)
        if config.verbose:
            print(f"Worker {worker_id}: Completed batch of {batch_attempts:,} keys in {batch_time:.1f}s "
                  f"({current_rate:,.0f} keys/sec) | Total: {total_attempts:,}")
        
        # Check if we should continue (another worker might have found a key)
        if shared_state.get('key_found', False):
            return BatchResult(worker_id=worker_id, attempts=total_attempts, batch_completed=False)
    
    return BatchResult(worker_id=worker_id, attempts=total_attempts, batch_completed=False)


def worker_process(worker_id: int, config: VanityConfig) -> Tuple[Optional[KeyInfo], int]:
    """Legacy worker process that generates keys until finding a match or hitting limits."""
    max_iterations = config.max_iterations or 100000000
    max_time = config.max_time
    start_time = time.time()
    
    # Calculate probability for accurate ETA
    probability = calculate_pattern_probability(config)
    tracker = PerformanceTracker(probability)
    
    for attempt in range(max_iterations):
        # Check time limit
        if max_time and (time.time() - start_time) > max_time:
            return None, attempt
        
        # Update progress
        if tracker.should_update(attempt):
            tracker.update(worker_id, attempt)
        
        # Generate and check key
        result = Ed25519KeyGenerator.generate_single_key(config)
        if result:
            # Verify the generated key works correctly
            if Ed25519KeyGenerator.verify_key_compatibility(result.private_hex, result.public_hex):
                print(f"Worker {worker_id}: Found valid MeshCore Ed25519 key!")
                return result, attempt + 1
            else:
                print(f"Worker {worker_id}: Generated key failed compatibility check!")
                continue
    
    return None, max_iterations


class ArgumentParser:
    """Handles command line argument parsing and validation."""
    
    @staticmethod
    def create_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="MeshCore Ed25519 Vanity Key Generator (Fixed)",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=ArgumentParser._get_examples()
        )
        
        ArgumentParser._add_arguments(parser)
        return parser
    
    @staticmethod
    def _add_arguments(parser: argparse.ArgumentParser):
        """Add command line arguments."""
        parser.add_argument('--keys', type=ArgumentParser._parse_keys,
                          help='Number of keys to check (e.g., 100 for 100M, 1b for 1B)')
        parser.add_argument('--time', type=ArgumentParser._parse_time,
                          help='Max runtime (e.g., 2 or 2:30)')
        parser.add_argument('--batch-size', type=ArgumentParser._parse_batch_size,
                          help='Batch size for worker processes (e.g., 500K, 1M, 2M)')
        parser.add_argument('--watchlist', type=str,
                          help='Path to watchlist file with patterns to monitor (auto-loads watchlist.txt if not specified)')
        parser.add_argument('--first-two', type=str,
                          help='First two hex chars to search for (e.g., F8)')
        parser.add_argument('--prefix', type=str,
                          help='Hex prefix to search for (e.g., F8A1)')
        parser.add_argument('--simple', action='store_true',
                          help='Simple mode: only check first two hex chars (requires --first-two)')
        parser.add_argument('--four-char', action='store_true',
                          help='Legacy 4-char vanity mode with optional --first-two constraint')
        parser.add_argument('--prefix-vanity', type=str,
                          help='Prefix + 8-char vanity pattern (e.g., F8 for prefix + vanity)')
        parser.add_argument('--vanity-2', action='store_true',
                          help='2-char vanity pattern (first 2 hex == last 2 hex OR palindromic)')
        parser.add_argument('--vanity-4', action='store_true',
                          help='4-char vanity pattern (first 4 hex == last 4 hex OR palindromic)')
        parser.add_argument('--vanity-6', action='store_true',
                          help='6-char vanity pattern (first 6 hex == last 6 hex OR palindromic)')
        parser.add_argument('--vanity-8', action='store_true',
                          help='8-char vanity pattern (first 8 hex == last 8 hex OR palindromic)')
        parser.add_argument('--health-check', action='store_true', default=True,
                          help='Enable health monitoring (default) to restart workers if performance degrades.')
        parser.add_argument('--no-health-check', action='store_false', dest='health_check',
                          help='Disable health monitoring and do not restart workers on performance degradation.')
        parser.add_argument('--verbose', '-v', action='store_true',
                          help='Enable verbose output including per-worker progress and health monitoring details.')
        
        # Test functions
        parser.add_argument('--test-compatibility', action='store_true',
                          help='Test compatibility with known MeshCore keys')
        parser.add_argument('--test-distribution', nargs='?', const=1, type=float,
                          metavar='MILLIONS',
                          help='Test distribution of first two hex chars (default: 1M keys)')
        parser.add_argument('--test-entropy', nargs='?', const=1, type=float,
                          metavar='THOUSANDS',
                          help='Test entropy and randomness (default: 10K keys)')
        parser.add_argument('--test-meshcore-id', nargs='?', const=1, type=float,
                          metavar='THOUSANDS',
                          help='Test MeshCore node ID format (default: 1K keys)')
        
        # Output options
        parser.add_argument('--json', action='store_true',
                          help='Output keys in JSON format for MeshCore app import')
    
    @staticmethod
    def _parse_keys(keys_str: str) -> int:
        """Parse keys argument."""
        try:
            if keys_str.lower().endswith('b'):
                return int(float(keys_str[:-1]) * 1000000000)
            
            keys = float(keys_str)
            if keys <= 1000:
                keys *= 1000000
            return int(keys)
        except ValueError:
            raise argparse.ArgumentTypeError("Invalid number format")
    
    @staticmethod
    def _parse_time(time_str: str) -> int:
        """Parse time argument."""
        try:
            if ':' in time_str:
                hours, minutes = time_str.split(':')
                return int(hours) * 3600 + int(minutes) * 60
            else:
                return int(time_str) * 3600
        except ValueError:
            raise argparse.ArgumentTypeError("Invalid time format")
    
    @staticmethod
    def _parse_batch_size(size_str: str) -> int:
        """Parse batch size argument."""
        try:
            if size_str.lower().endswith('k'):
                return int(float(size_str[:-1]) * 1000)
            elif size_str.lower().endswith('m'):
                return int(float(size_str[:-1]) * 1000000)
            else:
                return int(size_str)
        except ValueError:
            raise argparse.ArgumentTypeError("Invalid batch size format")
    
    @staticmethod
    def _get_examples() -> str:
        return """
Examples:
  python meshcore_keygen.py --keys 100         # 100 million keys
  python meshcore_keygen.py --keys 1b          # 1 billion keys
  python meshcore_keygen.py --time 2           # 2 hours
  python meshcore_keygen.py --time 2:30        # 2 hours 30 minutes
  python meshcore_keygen.py --batch-size 500K  # 500K keys per batch
  python meshcore_keygen.py --batch-size 2M    # 2M keys per batch
  python meshcore_keygen.py --watchlist patterns.txt  # Monitor specific patterns file
  python meshcore_keygen.py --first-two F8     # Keys starting with F8 (auto-loads watchlist.txt)
  python meshcore_keygen.py --first-two F8 --simple  # Simple mode
  python meshcore_keygen.py --prefix F8A1      # Keys starting with F8A1
  python meshcore_keygen.py --four-char        # 4-char vanity (legacy mode)
  python meshcore_keygen.py --four-char --first-two F8  # 4-char + F8 start
  python meshcore_keygen.py --vanity-2         # 2-char vanity pattern
  python meshcore_keygen.py --vanity-4         # 4-char vanity pattern
  python meshcore_keygen.py --vanity-6         # 6-char vanity pattern
  python meshcore_keygen.py --vanity-8         # 8-char vanity pattern
  python meshcore_keygen.py --prefix-vanity F8 # Prefix + vanity pattern
  python meshcore_keygen.py --test-compatibility  # Test known MeshCore keys
  python meshcore_keygen.py --test-distribution 0.1  # Test with 100K keys
  python meshcore_keygen.py --test-entropy 10  # Test with 10K keys
  python meshcore_keygen.py --vanity-4 --json  # Generate vanity key in JSON format
  python meshcore_keygen.py --first-two F8 --verbose  # Enable verbose output
  python meshcore_keygen.py --vanity-6 -v  # Short form for verbose mode

Vanity Pattern Modes:
  --vanity-2: First 2 hex chars == last 2 hex chars OR palindromic
  --vanity-4: First 4 hex chars == last 4 hex chars OR palindromic  
  --vanity-6: First 6 hex chars == last 6 hex chars OR palindromic
  --vanity-8: First 8 hex chars == last 8 hex chars OR palindromic (default)
  --four-char: Legacy mode with 4-char vanity + optional --first-two constraint
  --prefix: Keys starting with specific hex prefix
  --prefix-vanity: Prefix + 8-char vanity pattern
  --simple: Only check first two hex chars (requires --first-two)

Batch Processing:
  Workers now process keys in configurable batches and check in with the main process.
  This allows for faster termination when a key is found and better resource utilization.
  Default batch size is 1M keys. Use --batch-size to adjust (e.g., 500K, 2M).

Watchlist Feature:
  Use --watchlist to monitor for additional patterns while searching for your primary target.
  If no --watchlist is specified, the script automatically loads watchlist.txt if it exists.
  Watchlist keys are automatically saved when found, and the search continues.
  
  Watchlist file format (one pattern per line):
    ABCD...EFGH                    # First 4 chars and last 4 chars
    ABCD...ABCDEFGH               # First 4 chars and last 8 chars  
    ABCDEFGH...ABCD               # First 8 chars and last 4 chars
    ABCD...EFGH|My cool pattern   # With optional description
    # This is a comment line
        """


class MeshCoreKeyGenerator:
    """Main key generator class."""
    
    def __init__(self):
        self.start_time = None
    
    def generate_vanity_key(self, config: VanityConfig) -> Optional[KeyInfo]:
        """Generate a vanity key using the specified configuration."""
        # Load watchlist patterns if specified
        if config.watchlist_file:
            config.watchlist_patterns = load_watchlist_patterns(config.watchlist_file)
        
        num_workers = config.num_workers or SystemUtils.get_optimal_worker_count()
        
        self._print_generation_info(config, num_workers)
        
        self.start_time = time.time()
        
        try:
            return self._run_generation(config, num_workers)
        except KeyboardInterrupt:
            print("\n\nKey generation interrupted by user.")
            return None
    
    def _print_generation_info(self, config: VanityConfig, num_workers: int):
        """Print information about the generation process."""
        print("Starting MeshCore Ed25519 key generation...")
        print(f"Mode: {config.mode.value}")
        print(f"Using {num_workers} worker processes")
        print(f"Batch size: {config.batch_size:,} keys per batch")
        
        if config.max_iterations:
            print(f"Max iterations per worker: {config.max_iterations:,}")
        if config.max_time:
            print(f"Max runtime: {config.max_time/3600:.1f} hours")
        
        print("-" * 60)
    
    def _run_generation(self, config: VanityConfig, num_workers: int) -> Optional[KeyInfo]:
        """Run the key generation process."""
        with Manager() as manager:
            shared_state = manager.dict()
            shared_state['key_found'] = False
            shared_state['found_key'] = None
            
            # Global health monitoring
            global_health_monitor = None
            if config.health_check:
                try:
                    global_health_monitor = HealthMonitor(-1, config)  # -1 indicates global monitor
                    if config.verbose:
                        print("Global health monitoring enabled")
                except Exception as e:
                    if config.verbose:
                        print(f"Failed to initialize global health monitor: {e}")
            
            worker_restart_count = 0
            max_restarts_per_worker = 5
            worker_restarts = {}
            
            # Progress tracking for non-verbose mode
            worker_progress = {}
            last_progress_update = time.time()
            progress_update_interval = 5  # Update progress every 5 seconds
            
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                futures = []
                active_workers = set()
                
                # Start initial workers
                for worker_id in range(num_workers):
                    future = executor.submit(worker_process_batch, worker_id, config, shared_state)
                    futures.append(future)
                    active_workers.add(worker_id)
                
                try:
                    while futures:
                        # Wait for any future to complete
                        done_futures, _ = concurrent.futures.wait(
                            futures, 
                            return_when=concurrent.futures.FIRST_COMPLETED
                        )
                        
                        for future in done_futures:
                            futures.remove(future)
                            
                            try:
                                result = future.result()
                                
                                if result.found_key:
                                    # Cancel all remaining futures immediately
                                    for f in futures:
                                        if not f.done():
                                            f.cancel()
                                    
                                    # Give a small delay for cancellation to take effect
                                    time.sleep(0.5)
                                    
                                    self._print_success(result.found_key, num_workers)
                                    print("Note: Other workers may continue briefly - this is normal multiprocessing behavior.")
                                    return result.found_key
                                
                                # Track worker progress for non-verbose mode
                                worker_progress[result.worker_id] = result.attempts
                                
                                # Check if worker needs restart (performance degradation)
                                if not result.batch_completed and config.health_check:
                                    # Find which worker this was
                                    worker_id = result.worker_id
                                    worker_restarts[worker_id] = worker_restarts.get(worker_id, 0) + 1
                                    
                                    if worker_restarts[worker_id] <= max_restarts_per_worker:
                                        if config.verbose:
                                            print(f"Restarting worker {worker_id} (restart {worker_restarts[worker_id]}/{max_restarts_per_worker})")
                                        
                                        # Start a new worker to replace the failed one
                                        new_future = executor.submit(worker_process_batch, worker_id, config, shared_state)
                                        futures.append(new_future)
                                        
                                        # Global health check
                                        if global_health_monitor and config.verbose:
                                            health_status = global_health_monitor.check_health(0, 0, 0)
                                            if health_status['warnings']:
                                                print("Global Health Check:")
                                                for warning in health_status['warnings']:
                                                    print(f"  ⚠️  {warning}")
                                    else:
                                        if config.verbose:
                                            print(f"Worker {worker_id} exceeded maximum restarts, continuing with remaining workers")
                                        active_workers.discard(worker_id)
                                
                            except Exception as e:
                                if config.verbose:
                                    print(f"Worker failed with exception: {e}")
                                # Don't restart on exceptions, just continue with remaining workers
                        
                        # Show consolidated progress update for non-verbose mode
                        current_time = time.time()
                        if not config.verbose and current_time - last_progress_update >= progress_update_interval:
                            if worker_progress:
                                total_attempts = sum(worker_progress.values())
                                elapsed = current_time - self.start_time
                                rate = total_attempts / elapsed if elapsed > 0 else 0
                                print(f"Progress: {total_attempts:,} total attempts | {rate:,.0f} keys/sec | {elapsed:.1f}s elapsed")
                            last_progress_update = current_time
                        
                        # Check if we still have active workers
                        if not futures and not active_workers:
                            if not config.verbose:
                                print("All workers have completed or failed.")
                            break
                    
                    print("\nNo match found after maximum iterations.")
                    return None
                    
                except KeyboardInterrupt:
                    # Cancel all workers on interrupt
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    raise


    def _print_success(self, key_info: KeyInfo, num_workers: int):
        """Print success information."""
        elapsed = time.time() - self.start_time
        
        print("\n" + "="*60)
        print("SUCCESS! Found matching Ed25519 key!")
        print(f"Total time: {elapsed:.1f}s ({elapsed/60:.1f}m)")
        print("="*60)
    
    def save_keys(self, key_info: KeyInfo) -> Tuple[str, str]:
        """Save keys to files and return filenames."""
        key_id = key_info.public_hex[:8].upper()
        
        pub_filename = f"meshcore_{key_id}_public.txt"
        priv_filename = f"meshcore_{key_id}_private.txt"
        
        with open(pub_filename, 'w') as f:
            f.write(key_info.public_hex)
        
        with open(priv_filename, 'w') as f:
            f.write(key_info.private_hex)
        
        return pub_filename, priv_filename
    
    def save_keys_json(self, key_info: KeyInfo) -> str:
        """Save keys in JSON format for MeshCore app import."""
        import json
        
        key_id = key_info.public_hex[:8].upper()
        json_filename = f"meshcore_{key_id}.json"
        
        meshcore_data = {
            "public_key": key_info.public_hex,
            "private_key": key_info.private_hex
        }
        
        with open(json_filename, 'w') as f:
            json.dump(meshcore_data, f, indent=2)
        
        return json_filename


def calculate_pattern_probability(config: VanityConfig) -> float:
    """Calculate the probability of finding the requested pattern."""
    if config.mode == VanityMode.SIMPLE:
        # Simple mode: first two hex chars match
        return 1.0 / 256  # 1 in 256 chance
    
    elif config.mode == VanityMode.PREFIX:
        # Prefix mode: key starts with specific prefix
        prefix_length = len(config.target_prefix) if config.target_prefix else 0
        return 1.0 / (16 ** prefix_length)  # 1 in 16^length chance
    
    elif config.mode == VanityMode.VANITY_2:
        # 2-char vanity: first 2 hex == last 2 hex OR palindromic
        # Each hex char has 16 possibilities, so 2 chars = 16^2 = 256
        # We need either direct match OR palindromic match
        # Probability = 2 / 256 = 1/128
        return 2.0 / 256
    
    elif config.mode == VanityMode.VANITY_4:
        # 4-char vanity: first 4 hex == last 4 hex OR palindromic
        # Each hex char has 16 possibilities, so 4 chars = 16^4 = 65,536
        # We need either direct match OR palindromic match
        # Probability = 2 / 65,536 = 1/32,768
        return 2.0 / (16 ** 4)
    
    elif config.mode == VanityMode.VANITY_6:
        # 6-char vanity: first 6 hex == last 6 hex OR palindromic
        # Each hex char has 16 possibilities, so 6 chars = 16^6 = 16,777,216
        # We need either direct match OR palindromic match
        # Probability = 2 / 16,777,216 = 1/8,388,608
        return 2.0 / (16 ** 6)
    
    elif config.mode == VanityMode.VANITY_8:
        # 8-char vanity: first 8 hex == last 8 hex OR palindromic
        # Each hex char has 16 possibilities, so 8 chars = 16^8 = 4,294,967,296
        # We need either direct match OR palindromic match
        # Probability = 2 / 4,294,967,296 = 1/2,147,483,648
        return 2.0 / (16 ** 8)
    
    elif config.mode == VanityMode.FOUR_CHAR:
        # Legacy 4-char mode with optional first-two constraint
        base_prob = 2.0 / (16 ** 4)  # 4-char vanity
        if config.target_first_two:
            # Additional constraint: first two hex chars must match
            base_prob *= (1.0 / 256)
        return base_prob
    
    elif config.mode == VanityMode.PREFIX_VANITY:
        # Prefix + 8-char vanity pattern
        prefix_length = len(config.target_prefix) if config.target_prefix else 0
        prefix_prob = 1.0 / (16 ** prefix_length)
        vanity_prob = 2.0 / (16 ** 8)  # 8-char vanity
        return prefix_prob * vanity_prob
    
    else:  # DEFAULT
        # Default: 8-char vanity with optional first-two constraint
        base_prob = 2.0 / (16 ** 8)  # 8-char vanity
        if config.target_first_two:
            # Additional constraint: first two hex chars must match
            base_prob *= (1.0 / 256)
        return base_prob


def format_probability(probability: float) -> str:
    """Format probability in a human-readable way."""
    if probability >= 0.1:
        return f"{probability:.1%} (1 in {int(1/probability):,})"
    elif probability >= 0.01:
        return f"{probability:.2%} (1 in {int(1/probability):,})"
    elif probability >= 0.001:
        return f"{probability:.3%} (1 in {int(1/probability):,})"
    else:
        # For very small probabilities, show scientific notation
        return f"{probability:.2e} (1 in {int(1/probability):,})"


def get_system_resources() -> Dict[str, Any]:
    """Get current system resource usage."""
    if not PSUTIL_AVAILABLE:
        return {}
    
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        
        # Disk usage (for temp files)
        disk = psutil.disk_usage('/')
        
        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_available': memory.available,
            'memory_total': memory.total,
            'disk_percent': disk.percent,
            'disk_free': disk.free
        }
    except Exception as e:
        print(f"Warning: Could not get system resources: {e}")
        return {}


def print_system_status():
    """Print current system status."""
    resources = get_system_resources()
    if resources:
        print("\n" + "="*60)
        print("SYSTEM RESOURCE STATUS")
        print("="*60)
        print(f"CPU Usage:     {resources.get('cpu_percent', 0):.1f}%")
        print(f"Memory Usage:  {resources.get('memory_percent', 0):.1f}% "
              f"({resources.get('memory_available', 0) / 1024 / 1024 / 1024:.1f}GB available)")
        print(f"Disk Usage:    {resources.get('disk_percent', 0):.1f}% "
              f"({resources.get('disk_free', 0) / 1024 / 1024 / 1024:.1f}GB free)")
        print("="*60)


def test_meshcore_compatibility():
    """Test the key generation against the known MeshCore example."""
    print("="*60)
    print("TESTING MESHCORE COMPATIBILITY (FIXED Ed25519)")
    print("="*60)
    
    # Known MeshCore keypair (if we have one to test against)
    known_public = "d86fff61471b086d87d895ed10c86e67a6cd5bfef551f6a81f33a54f9bc0c219"
    known_private = "305e0b1b3142a95882915c43cd806df904247a2d505505f73dfb0cde9e666c4d656591bb4b5a23b6f47c786bf6cccfa0c4423c4617bbc9ab51dfb6f016f84144"
    
    print(f"Known public key:  {known_public}")
    print(f"Known private key: {known_private}")
    
    # Test our verification function with the known key
    is_compatible = Ed25519KeyGenerator.verify_key_compatibility(known_private, known_public)
    print(f"\nKnown key compatibility test: {'✓ PASS' if is_compatible else '✗ FAIL'}")
    
    if not is_compatible:
        print("The known MeshCore key doesn't verify with our method.")
        
        # Analyze the key structure
        private_bytes = bytes.fromhex(known_private)
        first_half = private_bytes[:32].hex()
        second_half = private_bytes[32:].hex()
        
        print(f"\nAnalyzing known key structure:")
        print(f"First 32 bytes:  {first_half}")
        print(f"Second 32 bytes: {second_half}")
        
        # Check if first half is properly clamped
        first_byte = private_bytes[0]
        last_byte = private_bytes[31]
        print(f"\nClamping analysis:")
        print(f"First byte: 0x{first_byte:02x} & 248 = {first_byte & 248} (should be {first_byte})")
        print(f"Last byte:  0x{last_byte:02x} & 63 = {last_byte & 63}, | 64 = {last_byte | 64}")
        
        # Test if it follows our expected clamping
        is_clamped = ((first_byte & 248) == first_byte and 
                     (last_byte & 63) == (last_byte & 63) and 
                     (last_byte | 64) == last_byte)
        print(f"Is properly clamped: {is_clamped}")
    
    # Test generating our own compatible keys
    print(f"\n" + "="*60)
    print("TESTING OUR FIXED Ed25519 KEY GENERATION")
    print("="*60)
    
    config = VanityConfig(mode=VanityMode.SIMPLE, target_first_two="D8")
    for attempt in range(5):  # Try a few times
        result = Ed25519KeyGenerator.generate_single_key(config)
        if result:
            print(f"\nGenerated key (attempt {attempt + 1}):")
            print(f"Public:  {result.public_hex}")
            print(f"Private: {result.private_hex}")
            
            # Verify it works
            is_valid = Ed25519KeyGenerator.verify_key_compatibility(result.private_hex, result.public_hex)
            print(f"Verification: {'✓ PASS' if is_valid else '✗ FAIL'}")
            
            if is_valid:
                print("✓ Successfully generated compatible MeshCore Ed25519 key!")
                
                # Show the key structure
                private_bytes = bytes.fromhex(result.private_hex)
                clamped_scalar = private_bytes[:32]
                filler = private_bytes[32:]
                
                print(f"\nKey structure:")
                print(f"Clamped scalar: {clamped_scalar.hex()}")
                print(f"Random filler:  {filler.hex()}")
                
                # Verify clamping
                print(f"Clamping verification:")
                print(f"First byte & 248: {clamped_scalar[0] & 248} (should equal {clamped_scalar[0]})")
                print(f"Last byte & 63:   {clamped_scalar[31] & 63}")
                print(f"Last byte | 64:   {clamped_scalar[31] | 64} (should equal {clamped_scalar[31]})")
                
                break
            else:
                print("✗ Generated key failed verification")
        else:
            print(f"No match found in attempt {attempt + 1}")
    
    else:
        print("No matching keys found in test attempts")
    
    print(f"\n" + "="*60)
    print("COMPATIBILITY TEST COMPLETE")
    print("="*60)


def test_first_two_distribution(num_samples: int = 100000):
    """Test the distribution of first two hex characters (MeshCore node IDs) in Ed25519 public keys."""
    print(f"Testing distribution of first two hex characters (MeshCore node IDs) in {num_samples:,} Ed25519 keys...")
    
    distribution = {}
    for i in range(num_samples):
        result = Ed25519KeyGenerator.generate_single_key(VanityConfig(mode=VanityMode.SIMPLE))
        if result:
            first_two_hex = result.public_hex[:2].upper()
            distribution[first_two_hex] = distribution.get(first_two_hex, 0) + 1
        
        # Show progress every 10% or every 100,000 keys, whichever is smaller
        progress_interval = min(100000, max(10000, num_samples // 10))
        if (i + 1) % progress_interval == 0:
            percentage = ((i + 1) / num_samples) * 100
            print(f"Progress: {i + 1:,} keys ({percentage:.1f}%)")
    
    print(f"\nDistribution of first two hex characters (top 20):")
    sorted_dist = sorted(distribution.items(), key=lambda x: x[1], reverse=True)
    for i, (first_two_hex, count) in enumerate(sorted_dist[:20]):
        percentage = (count / num_samples) * 100
        print(f"{i+1:2d}. {first_two_hex}: {count:,} ({percentage:.3f}%)")
    
    # Show some statistics
    total_unique = len(distribution)
    print(f"\nStatistics:")
    print(f"Total unique first-two patterns found: {total_unique:,}")
    print(f"Expected unique patterns: 256")
    print(f"Coverage: {total_unique/256*100:.1f}% of possible patterns")
    print(f"Expected probability per pattern: 1 in 256 = {100/256:.3f}%")
    
    # Show some random patterns that were found
    import random
    found_patterns = list(distribution.keys())
    if len(found_patterns) > 10:
        sample_patterns = random.sample(found_patterns, 10)
        print(f"Sample of found patterns: {', '.join(sorted(sample_patterns))}")
    
    return distribution


def test_entropy_and_randomness(num_samples: int = 10000):
    """Test the entropy and randomness of our Ed25519 key generation process."""
    print(f"Testing entropy and randomness of Ed25519 key generation...")
    print(f"Generating {num_samples:,} keys for analysis...")
    
    # Test 1: Check for repeated keys (should be extremely rare)
    seen_keys = set()
    repeated_count = 0
    
    # Test 2: Analyze byte distribution
    byte_counts = [0] * 256
    first_byte_counts = [0] * 256
    second_byte_counts = [0] * 256
    
    for i in range(num_samples):
        result = Ed25519KeyGenerator.generate_single_key(VanityConfig(mode=VanityMode.SIMPLE))
        if result:
            # Check for repeated keys
            key_hex = result.public_hex
            if key_hex in seen_keys:
                repeated_count += 1
            seen_keys.add(key_hex)
            
            # Count byte distributions
            for j, byte in enumerate(result.public_bytes):
                byte_counts[byte] += 1
                if j == 0:
                    first_byte_counts[byte] += 1
                elif j == 1:
                    second_byte_counts[byte] += 1
        
        if (i + 1) % 1000 == 0:
            print(f"Progress: {i + 1:,} keys analyzed...")
    
    print(f"\n=== ENTROPY TEST RESULTS ===")
    print(f"Total keys generated: {num_samples:,}")
    print(f"Unique keys: {len(seen_keys):,}")
    print(f"Repeated keys: {repeated_count}")
    print(f"Collision rate: {repeated_count/num_samples*100:.6f}%")
    
    # Check if we have good entropy (should be close to 0% collision rate)
    if repeated_count == 0:
        print("✓ Excellent: No key collisions detected")
    elif repeated_count < num_samples * 0.0001:  # Less than 0.01%
        print("✓ Good: Very low collision rate")
    else:
        print("⚠️  Warning: Higher than expected collision rate")
    
    # Analyze first byte distribution
    print(f"\n=== FIRST BYTE DISTRIBUTION ===")
    print("Most common first bytes:")
    sorted_first = sorted(enumerate(first_byte_counts), key=lambda x: x[1], reverse=True)
    for i, (byte_val, count) in enumerate(sorted_first[:10]):
        percentage = (count / num_samples) * 100
        print(f"  {byte_val:3d} (0x{byte_val:02X}): {count:,} ({percentage:.3f}%)")


def test_meshcore_node_id_format(num_samples: int = 1000):
    """Test MeshCore node ID format (first two hex characters)."""
    print(f"Testing MeshCore node ID format in {num_samples:,} keys...")
    
    node_ids = {}
    for i in range(num_samples):
        result = Ed25519KeyGenerator.generate_single_key(VanityConfig(mode=VanityMode.SIMPLE))
        if result:
            # Get the hex representation for MeshCore node ID
            node_id = result.public_hex[:2].upper()
            node_ids[node_id] = node_ids.get(node_id, 0) + 1
        
        if (i + 1) % 100 == 0:
            print(f"Progress: {i + 1:,} keys analyzed...")
    
    print(f"\n=== MESHCORE NODE ID TEST RESULTS ===")
    print(f"Total keys analyzed: {num_samples:,}")
    print(f"Unique node IDs found: {len(node_ids)}")
    print(f"Expected unique node IDs: 256")
    print(f"Coverage: {len(node_ids)/256*100:.1f}% of possible node IDs")
    
    # Show most common node IDs
    print(f"\nMost common node IDs:")
    sorted_node_ids = sorted(node_ids.items(), key=lambda x: x[1], reverse=True)
    for i, (node_id, count) in enumerate(sorted_node_ids[:10]):
        percentage = (count / num_samples) * 100
        print(f"  {node_id}: {count:,} ({percentage:.3f}%)")
    
    # Show expected probability
    print(f"\nExpected probability per node ID: 1 in 256 = {100/256:.3f}%")


def main():
    """Main entry point."""
    # Set multiprocessing method
    mp.set_start_method('spawn', force=True)
    
    parser = ArgumentParser.create_parser()
    args = parser.parse_args()
    
    # Handle test functions first
    if args.test_compatibility:
        test_meshcore_compatibility()
        return
    
    if args.test_distribution is not None:
        num_keys_to_test = int(args.test_distribution * 1000000)
        test_first_two_distribution(num_keys_to_test)
        return
    
    if args.test_entropy is not None:
        num_keys_to_test = int(args.test_entropy * 1000)
        test_entropy_and_randomness(num_keys_to_test)
        return
    
    if args.test_meshcore_id is not None:
        num_keys_to_test = int(args.test_meshcore_id * 1000)
        test_meshcore_node_id_format(num_keys_to_test)
        return
    
    # Validate arguments
    if args.keys and args.time:
        print("Error: Cannot specify both --keys and --time. Choose one or the other.")
        return
    
    if args.keys:
        if args.keys < 1000000:
            print("Error: Minimum key count is 1 million keys.")
            return
        if args.keys > 10000000000:  # 10 billion
            print("Error: Maximum key count is 10 billion keys.")
            return
    
    if args.time:
        if args.time < 60:  # 1 minute minimum
            print("Error: Minimum runtime is 1 minute.")
            return
        if args.time > 86400:  # 24 hours maximum
            print("Error: Maximum runtime is 24 hours.")
            return
    
    if args.batch_size:
        if args.batch_size < 10000:  # 10K minimum
            print("Error: Minimum batch size is 10,000 keys.")
            return
        if args.batch_size > 10000000:  # 10M maximum
            print("Error: Maximum batch size is 10 million keys.")
            return
    
    if args.first_two:
        # Validate first-two argument
        if len(args.first_two) != 2:
            print("Error: --first-two must be exactly 2 characters (e.g., F8)")
            return
        try:
            # Try to convert to int to validate it's valid hex
            int(args.first_two, 16)
        except ValueError:
            print("Error: --first-two must be a valid 2-character hex string (e.g., F8, 1A, 00)")
            return
    
    if args.simple and not args.first_two:
        print("Error: --simple mode requires --first-two to be specified.")
        return
    
    if args.prefix:
        # Validate prefix argument
        if len(args.prefix) < 1:
            print("Error: --prefix must be at least 1 character long.")
            return
        if len(args.prefix) > 8:
            print("Error: --prefix cannot be longer than 8 characters.")
            return
        try:
            # Try to convert to int to validate it's valid hex
            int(args.prefix, 16)
        except ValueError:
            print("Error: --prefix must be a valid hex string (e.g., F8A1, 1234)")
            return
    
    if args.prefix_vanity:
        # Validate prefix-vanity argument
        if len(args.prefix_vanity) < 1:
            print("Error: --prefix-vanity must be at least 1 character long.")
            return
        if len(args.prefix_vanity) > 8:
            print("Error: --prefix-vanity cannot be longer than 8 characters.")
            return
        try:
            # Try to convert to int to validate it's valid hex
            int(args.prefix_vanity, 16)
        except ValueError:
            print("Error: --prefix-vanity must be a valid hex string (e.g., F8A1, 1234)")
            return
    
    # Check for conflicting modes
    mode_count = sum([args.simple, args.prefix is not None, args.four_char, 
                     args.prefix_vanity is not None, args.vanity_8, args.vanity_4, args.vanity_2, args.vanity_6])
    if mode_count > 1:
        print("Error: Cannot specify multiple vanity modes. Choose one of --simple, --prefix, --four-char, --prefix-vanity, --vanity-8, --vanity-4, --vanity-2, or --vanity-6.")
        return
    
    # Create configuration
    config = create_config_from_args(args)
    
    # Show header information
    print("="*60)
    print("MESHCORE Ed25519 VANITY KEY GENERATOR")
    print("="*60)
    print("This version generates MeshCore-compatible Ed25519 keys")
    print("Format: 64-byte private key [clamped_scalar][random_filler]")
    print("        32-byte public key from crypto_scalarmult_ed25519_base_noclamp")
    print("="*60)
    
    # Show health monitoring status
    if config.health_check:
        print("🔧 Health Monitoring: ENABLED")
        if PSUTIL_AVAILABLE:
            print("   - Memory usage monitoring ✓")
            print("   - CPU usage monitoring ✓")
            print("   - Performance tracking ✓")
            print("   - Automatic worker restart on degradation ✓")
            print("   - Garbage collection optimization ✓")
        else:
            print("   - Memory usage monitoring ✗ (psutil not available)")
            print("   - CPU usage monitoring ✗ (psutil not available)")
            print("   - Performance tracking ✓")
            print("   - Automatic worker restart on degradation ✓")
            print("   - Garbage collection optimization ✓")
    else:
        print("⚠️  Health Monitoring: DISABLED")
        print("   - No performance monitoring")
        print("   - No automatic worker restart")
    
    # Show verbose mode status
    if config.verbose:
        print("📝 Verbose Mode: ENABLED")
        print("   - Per-worker progress updates ✓")
        print("   - Health monitoring details ✓")
        print("   - Batch completion reports ✓")
    else:
        print("📝 Verbose Mode: DISABLED")
        print("   - Consolidated progress updates ✓")
        print("   - Clean output mode ✓")
    
    # Show system status
    print_system_status()
    
    # Calculate and display probability
    probability = calculate_pattern_probability(config)
    print(f"Probability of finding a key matching your pattern: {format_probability(probability)}")
    
    # Generate key
    generator = MeshCoreKeyGenerator()
    key_info = generator.generate_vanity_key(config)
    
    if key_info:
        # Display results
        print("\nGenerated MeshCore Ed25519 Vanity Key:")
        print("-" * 40)
        print(f"Matching Pattern: {key_info.matching_pattern}")
        print(f"First 8 hex:     {key_info.first_8_hex}")
        print(f"Last 8 hex:      {key_info.last_8_hex}")
        print(f"\nPublic Key (hex):\n{key_info.public_hex}")
        print(f"\nPrivate Key (hex):\n{key_info.private_hex}")
        
        # Verify the key works
        is_valid = Ed25519KeyGenerator.verify_key_compatibility(key_info.private_hex, key_info.public_hex)
        print(f"\nKey Verification: {'✓ PASS' if is_valid else '✗ FAIL'}")
        
        if is_valid:
            # Save keys
            if args.json:
                # Save in JSON format for MeshCore app
                json_file = generator.save_keys_json(key_info)
                print(f"\nKeys saved to JSON file for MeshCore app import:")
                print(f"  {json_file}")
            else:
                # Save in text format
                pub_file, priv_file = generator.save_keys(key_info)
                print(f"\nKeys saved to:")
                print(f"  Public:  {pub_file}")
                print(f"  Private: {priv_file}")
            
            node_id = key_info.public_hex[:2].upper()
            print(f"  Node ID: {node_id}")
            print("\n⚠️  Keep your private key secure and never share it!")
            print("\n✓ This Ed25519 key should now work with MeshCore!")
        else:
            print("\n⚠️  Warning: Generated key failed verification!")
            print("This indicates a problem with the key format.")
    else:
        print("Key generation failed or was interrupted.")


def create_config_from_args(args) -> VanityConfig:
    """Create a VanityConfig from parsed arguments."""
    # Determine mode and vanity length
    mode = VanityMode.DEFAULT
    vanity_length = 8  # Default
    
    if args.simple:
        mode = VanityMode.SIMPLE
    elif args.prefix:
        mode = VanityMode.PREFIX
    elif args.four_char:
        mode = VanityMode.FOUR_CHAR
        vanity_length = 4
    elif args.prefix_vanity:
        mode = VanityMode.PREFIX_VANITY
        vanity_length = 8
    elif args.vanity_2:
        mode = VanityMode.VANITY_2
        vanity_length = 2
    elif args.vanity_4:
        mode = VanityMode.VANITY_4
        vanity_length = 4
    elif args.vanity_6:
        mode = VanityMode.VANITY_6
        vanity_length = 6
    elif args.vanity_8:
        mode = VanityMode.VANITY_8
        vanity_length = 8
    
    # Calculate max_iterations from keys if specified
    max_iterations = None
    if args.keys:
        num_workers = SystemUtils.get_optimal_worker_count()
        max_iterations = args.keys // num_workers
    
    # Set batch size (default 1M if not specified)
    batch_size = args.batch_size if args.batch_size else 1000000
    
    # Handle watchlist file
    watchlist_file = args.watchlist
    if not watchlist_file:
        # Check if watchlist.txt exists in the same directory as the script
        import os
        script_dir = os.path.dirname(os.path.abspath(__file__))
        default_watchlist = os.path.join(script_dir, "watchlist.txt")
        if os.path.exists(default_watchlist):
            watchlist_file = default_watchlist
            print(f"Auto-loading watchlist from: {default_watchlist}")
    
    return VanityConfig(
        mode=mode,
        target_first_two=args.first_two,
        target_prefix=args.prefix or args.prefix_vanity,
        vanity_length=vanity_length,
        max_iterations=max_iterations,
        max_time=args.time,
        batch_size=batch_size,
        watchlist_file=watchlist_file,
        health_check=args.health_check, # Pass health_check argument
        verbose=args.verbose # Pass verbose argument
    )


if __name__ == "__main__":
    main()