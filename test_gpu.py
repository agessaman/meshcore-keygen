#!/usr/bin/env python3
"""
Test script for GPU acceleration in MeshCore key generator.
This script tests GPU detection and basic functionality.
"""

import sys
import platform

def test_gpu_detection():
    """Test GPU detection functionality."""
    print("="*60)
    print("GPU ACCELERATION TEST")
    print("="*60)
    
    # Test imports
    print("Testing GPU library imports...")
    
    # Test Metal (Apple Silicon)
    try:
        import Metal
        import MetalPerformanceShaders as MPS
        import Foundation
        print("✓ Apple Metal GPU support available")
        METAL_AVAILABLE = True
    except ImportError as e:
        print(f"✗ Apple Metal GPU support not available: {e}")
        METAL_AVAILABLE = False
    except Exception as e:
        print(f"✗ Apple Metal GPU support error: {e}")
        METAL_AVAILABLE = False
    
    # Test OpenCL
    try:
        import pyopencl as cl
        print("✓ OpenCL GPU support available")
        OPENCL_AVAILABLE = True
    except ImportError as e:
        print(f"✗ OpenCL GPU support not available: {e}")
        OPENCL_AVAILABLE = False
    except Exception as e:
        print(f"✗ OpenCL GPU support error: {e}")
        OPENCL_AVAILABLE = False
    
    # Test Vulkan
    try:
        import vulkan as vk
        print("✓ Vulkan GPU support available")
        VULKAN_AVAILABLE = True
    except ImportError as e:
        print(f"✗ Vulkan GPU support not available: {e}")
        VULKAN_AVAILABLE = False
    except Exception as e:
        print(f"✗ Vulkan GPU support error: {e}")
        VULKAN_AVAILABLE = False
    
    # Test NumPy
    try:
        import numpy as np
        print("✓ NumPy available for GPU operations")
        NUMPY_AVAILABLE = True
    except ImportError as e:
        print(f"✗ NumPy not available: {e}")
        NUMPY_AVAILABLE = False
    except Exception as e:
        print(f"✗ NumPy error: {e}")
        NUMPY_AVAILABLE = False
    
    print("\n" + "="*60)
    print("SYSTEM INFORMATION")
    print("="*60)
    print(f"Platform: {platform.system()}")
    print(f"Architecture: {platform.machine()}")
    print(f"Python version: {sys.version}")
    
    # Test GPU detection
    print("\n" + "="*60)
    print("GPU DETECTION TEST")
    print("="*60)
    
    # Import GPU detection from main script
    try:
        from meshcore_keygen2 import GPUDetector, GPUMode
        print("✓ GPU detection module imported successfully")
        
        # Detect GPUs
        print("\nDetecting available GPUs...")
        gpus = GPUDetector.detect_gpus()
        
        if gpus:
            print(f"✓ Found {len(gpus)} GPU(s):")
            for i, gpu in enumerate(gpus, 1):
                print(f"  {i}. {gpu}")
            
            # Test GPU accelerator creation
            print("\nTesting GPU accelerator creation...")
            for gpu in gpus:
                for mode in [GPUMode.METAL, GPUMode.OPENCL, GPUMode.VULKAN, GPUMode.AUTO]:
                    if mode == GPUMode.METAL and gpu.gpu_type == "metal":
                        accelerator = GPUDetector.create_gpu_accelerator(gpu, mode)
                        if accelerator:
                            print(f"✓ Created {mode.value} accelerator for {gpu.name}")
                        else:
                            print(f"✗ Failed to create {mode.value} accelerator for {gpu.name}")
                    elif mode == GPUMode.OPENCL and gpu.gpu_type == "opencl":
                        accelerator = GPUDetector.create_gpu_accelerator(gpu, mode)
                        if accelerator:
                            print(f"✓ Created {mode.value} accelerator for {gpu.name}")
                        else:
                            print(f"✗ Failed to create {mode.value} accelerator for {gpu.name}")
                    elif mode == GPUMode.VULKAN and gpu.gpu_type == "vulkan":
                        accelerator = GPUDetector.create_gpu_accelerator(gpu, mode)
                        if accelerator:
                            print(f"✓ Created {mode.value} accelerator for {gpu.name}")
                        else:
                            print(f"✗ Failed to create {mode.value} accelerator for {gpu.name}")
        else:
            print("⚠️  No GPUs detected")
        
    except ImportError as e:
        print(f"✗ Failed to import GPU detection module: {e}")
    except Exception as e:
        print(f"✗ GPU detection test failed: {e}")
    
    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)
    
    if not any([METAL_AVAILABLE, OPENCL_AVAILABLE, VULKAN_AVAILABLE]):
        print("⚠️  No GPU acceleration libraries available")
        print("Install GPU dependencies:")
        print("  pip install pyobjc-framework-Metal  # Apple Silicon")
        print("  pip install pyopencl               # NVIDIA/AMD OpenCL")
        print("  pip install vulkan                 # NVIDIA/AMD Vulkan")
    else:
        print("✓ GPU acceleration libraries available")
        print("You can now use GPU acceleration with:")
        print("  python3 meshcore_keygen2.py --gpu")


if __name__ == "__main__":
    test_gpu_detection()
