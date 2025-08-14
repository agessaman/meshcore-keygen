#!/usr/bin/env python3
"""
Test script to debug OpenCL issues on Windows
"""

import os
import sys

# Suppress OpenCL compiler warnings
os.environ['PYOPENCL_COMPILER_OUTPUT'] = '0'

try:
    import pyopencl as cl
    print("✓ OpenCL imported successfully")
except ImportError as e:
    print(f"✗ Failed to import OpenCL: {e}")
    sys.exit(1)

try:
    # Get platforms
    platforms = cl.get_platforms()
    print(f"✓ Found {len(platforms)} OpenCL platform(s)")
    
    for i, platform in enumerate(platforms):
        print(f"  Platform {i}: {platform.name}")
        
        # Get devices
        devices = platform.get_devices(cl.device_type.GPU)
        print(f"    Found {len(devices)} GPU device(s)")
        
        for j, device in enumerate(devices):
            print(f"      Device {j}: {device.name}")
            print(f"        Memory: {device.global_mem_size // (1024*1024)} MB")
            print(f"        Compute Units: {device.max_compute_units}")
            
            # Test context creation
            try:
                context = cl.Context([device])
                print(f"        ✓ Context created successfully")
                
                # Test command queue
                queue = cl.CommandQueue(context)
                print(f"        ✓ Command queue created successfully")
                
                # Test simple kernel
                kernel_source = """
                __kernel void test_kernel(__global int* output) {
                    int tid = get_global_id(0);
                    output[tid] = tid * 2;
                }
                """
                
                try:
                    program = cl.Program(context, kernel_source).build(options=["-w"])
                    kernel = program.test_kernel
                    print(f"        ✓ Kernel compiled successfully")
                    
                    # Test kernel execution
                    test_size = 10
                    output_buffer = cl.Buffer(context, cl.mem_flags.WRITE_ONLY, test_size * 4)
                    kernel(queue, (test_size,), None, output_buffer)
                    queue.finish()
                    print(f"        ✓ Kernel executed successfully")
                    
                except Exception as e:
                    print(f"        ✗ Kernel test failed: {e}")
                
            except Exception as e:
                print(f"        ✗ Context/queue creation failed: {e}")
    
except Exception as e:
    print(f"✗ OpenCL test failed: {e}")
    sys.exit(1)

print("\n✓ OpenCL test completed successfully!")
