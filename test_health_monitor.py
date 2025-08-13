#!/usr/bin/env python3
"""
Test script for the health monitoring system.
This script tests the health monitoring functionality without running the full key generation.
"""

import time
import gc
from meshcore_keygen import HealthMonitor, PerformanceTracker, VanityConfig, VanityMode

def test_health_monitor():
    """Test the health monitoring system."""
    print("Testing Health Monitoring System")
    print("=" * 50)
    
    # Create a test config
    config = VanityConfig(
        mode=VanityMode.DEFAULT,
        health_check=True
    )
    
    # Test HealthMonitor
    print("\n1. Testing HealthMonitor...")
    monitor = HealthMonitor(1, config)
    
    # Simulate some work
    for i in range(5):
        print(f"  Test iteration {i + 1}")
        
        # Simulate batch processing
        batch_attempts = 1000000
        batch_time = 1.0 + (i * 0.1)  # Simulate performance degradation
        current_rate = batch_attempts / batch_time
        
        health_status = monitor.check_health(current_rate, batch_attempts, batch_time)
        
        print(f"    Rate: {current_rate:,.0f} keys/sec")
        print(f"    Memory: {health_status['memory_usage'] / 1024 / 1024:.1f}MB")
        print(f"    CPU: {health_status['cpu_usage']:.1f}%")
        print(f"    Performance ratio: {health_status['performance_ratio']:.1%}")
        
        if health_status['warnings']:
            print(f"    Warnings: {health_status['warnings']}")
        if health_status['actions_taken']:
            print(f"    Actions: {health_status['actions_taken']}")
        
        print(f"    Healthy: {health_status['healthy']}")
        print()
        
        time.sleep(1)
    
    # Test PerformanceTracker
    print("\n2. Testing PerformanceTracker...")
    tracker = PerformanceTracker(probability=0.001)
    
    for i in range(10):
        attempts = (i + 1) * 1000000
        current_rate = 15000 + (i * 100)  # Simulate varying performance
        
        tracker.update(1, attempts, current_rate)
        
        # Check for performance degradation
        degraded, ratio = tracker.check_performance_degradation()
        if degraded:
            print(f"    Performance degradation detected: {ratio:.1%}")
        
        time.sleep(0.5)
    
    print("\n3. Testing garbage collection...")
    # Create some objects to test GC
    test_objects = []
    for i in range(10000):
        test_objects.append([i] * 100)
    
    print(f"    Created {len(test_objects)} test objects")
    
    # Force garbage collection
    gc.collect()
    
    print("    Garbage collection completed")
    
    print("\nHealth monitoring test completed successfully!")
    print("=" * 50)

if __name__ == "__main__":
    test_health_monitor()
