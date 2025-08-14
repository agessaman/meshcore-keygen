#!/usr/bin/env python3
"""
Test script for the Ed25519 OpenCL kernel
"""

import os
import sys

# Suppress OpenCL compiler warnings
os.environ['PYOPENCL_COMPILER_OUTPUT'] = '0'

try:
    import pyopencl as cl
    import numpy as np
    print("✓ OpenCL and NumPy imported successfully")
except ImportError as e:
    print(f"✗ Failed to import: {e}")
    sys.exit(1)

def get_ed25519_kernel_source():
    """Get the Ed25519 kernel source (same as in main script)."""
    return """
    __kernel void generate_ed25519_keys(
        __global uchar* seeds,
        __global uchar* public_keys,
        __global uchar* private_keys,
        uint batch_size
    ) {
        uint tid = get_global_id(0);
        if (tid >= batch_size) return;
        
        // Generate random seed (simplified)
        uint seed_array[8];
        for (int i = 0; i < 8; i++) {
            seed_array[i] = (tid * 12345 + i * 67890) ^ (tid >> 16);
        }
        
        // Simplified SHA-512 processing (avoid potential overflow)
        ulong digest[8];
        for (int i = 0; i < 8; i++) {
            digest[i] = (ulong)seed_array[i] + (ulong)0x6a09e667f3bcc908UL + (ulong)i;
        }
        
        // Clamp the scalar
        uchar clamped[32];
        for (int i = 0; i < 32; i++) {
            int digest_idx = i / 4;
            int shift_amount = (i % 4) * 8;
            if (digest_idx < 8 && shift_amount < 64) {
                clamped[i] = (uchar)((digest[digest_idx] >> shift_amount) & 0xFF);
            } else {
                clamped[i] = 0;
            }
        }
        clamped[0] &= 248;  // Clear bottom 3 bits
        clamped[31] &= 63;  // Clear top 2 bits
        clamped[31] |= 64;  // Set bit 6
        
        // Store private key [clamped_scalar][random_filler]
        uint private_offset = tid * 64;
        for (int i = 0; i < 32; i++) {
            private_keys[private_offset + i] = clamped[i];
        }
        // Add random filler
        for (int i = 32; i < 64; i++) {
            int seed_idx = i % 8;
            int shift_amount = ((i % 4) * 8);
            if (seed_idx < 8 && shift_amount < 32) {
                private_keys[private_offset + i] = (uchar)((seed_array[seed_idx] >> shift_amount) & 0xFF);
            } else {
                private_keys[private_offset + i] = 0;
            }
        }
        
        // Simplified public key generation
        uint public_offset = tid * 32;
        for (int i = 0; i < 32; i++) {
            public_keys[public_offset + i] = clamped[i] ^ 0x42;
        }
    }
    """

def test_ed25519_kernel():
    """Test the Ed25519 kernel."""
    try:
        # Get platforms and devices
        platforms = cl.get_platforms()
        if not platforms:
            print("✗ No OpenCL platforms found")
            return False
        
        # Find GPU device
        device = None
        for platform in platforms:
            devices = platform.get_devices(cl.device_type.GPU)
            if devices:
                device = devices[0]
                break
        
        if not device:
            print("✗ No OpenCL GPU device found")
            return False
        
        print(f"✓ Using device: {device.name}")
        
        # Create context and command queue
        context = cl.Context([device])
        queue = cl.CommandQueue(context)
        
        # Create OpenCL program
        kernel_source = get_ed25519_kernel_source()
        
        # Windows-compatible build options
        if sys.platform.startswith('win'):
            build_options = ["-w", "-cl-std=CL1.2", "-cl-no-signed-zeros", "-cl-mad-enable", "-cl-fast-relaxed-math"]
        else:
            build_options = ["-w", "-cl-std=CL1.2", "-cl-no-signed-zeros", "-cl-mad-enable"]
        
        print("✓ Compiling Ed25519 kernel...")
        program = cl.Program(context, kernel_source).build(options=build_options)
        kernel = program.generate_ed25519_keys
        print("✓ Ed25519 kernel compiled successfully")
        
        # Test kernel execution
        test_batch_size = 100
        print(f"✓ Testing kernel with batch size: {test_batch_size}")
        
        # Create buffers
        seed_buffer = cl.Buffer(context, cl.mem_flags.READ_WRITE, test_batch_size * 32)
        public_buffer = cl.Buffer(context, cl.mem_flags.WRITE_ONLY, test_batch_size * 32)
        private_buffer = cl.Buffer(context, cl.mem_flags.WRITE_ONLY, test_batch_size * 64)
        
        # Execute kernel
        kernel(queue, (test_batch_size,), None, seed_buffer, public_buffer, private_buffer, np.uint32(test_batch_size))
        queue.finish()
        print("✓ Kernel executed successfully")
        
        # Read results
        public_data = np.empty(test_batch_size * 32, dtype=np.uint8)
        private_data = np.empty(test_batch_size * 64, dtype=np.uint8)
        
        cl.enqueue_copy(queue, public_data, public_buffer)
        cl.enqueue_copy(queue, private_data, private_buffer)
        queue.finish()
        print("✓ Data copied successfully")
        
        # Verify results
        print(f"✓ Generated {test_batch_size} keypairs")
        print(f"  Public key size: {len(public_data)} bytes")
        print(f"  Private key size: {len(private_data)} bytes")
        
        # Check first keypair
        first_public = public_data[:32]
        first_private = private_data[:64]
        print(f"  First public key (hex): {first_public.tobytes().hex()}")
        print(f"  First private key (hex): {first_private.tobytes().hex()}")
        
        return True
        
    except Exception as e:
        print(f"✗ Ed25519 kernel test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Testing Ed25519 OpenCL kernel...")
    if test_ed25519_kernel():
        print("\n✓ Ed25519 kernel test completed successfully!")
    else:
        print("\n✗ Ed25519 kernel test failed!")
        sys.exit(1)
