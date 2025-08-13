# MeshCore Ed25519 Vanity Key Generator

A high-performance vanity key generator for MeshCore nodes that creates Ed25519 keypairs with custom patterns. This tool generates MeshCore-compatible Ed25519 keys with various vanity patterns for personalized node identification.

## Features

- **MeshCore-Compatible**: Generates Ed25519 keys in the exact format MeshCore expects
- **Multiple Vanity Modes**: Support for various pattern matching modes
- **High Performance**: Multi-processor support with optimized batch processing
- **Health Monitoring**: Automatic performance monitoring and worker restart
- **Watchlist Support**: Monitor for additional patterns while searching
- **Flexible Output**: Save keys in text or JSON format for MeshCore app import

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Dependencies

Install the required packages:

```bash
pip install PyNaCl
pip install psutil  # Optional, for enhanced health monitoring
```

## Usage

### Basic Commands

```bash
# Generate a key with default 8-char vanity pattern
python meshcore_keygen.py

# Search for keys starting with specific hex prefix
python meshcore_keygen.py --first-two F8

# Generate key with 4-char vanity pattern
python meshcore_keygen.py --vanity-4

# Search for keys with specific prefix
python meshcore_keygen.py --prefix F8A1

# Run for specific number of keys
python meshcore_keygen.py --keys 100  # 100 million keys

# Run for specific time
python meshcore_keygen.py --time 2    # 2 hours
```

### Vanity Pattern Modes

#### 1. Simple Mode
Search for keys starting with specific hex characters:
```bash
python meshcore_keygen.py --simple --first-two F8
```

#### 2. Prefix Mode
Search for keys starting with a specific hex prefix:
```bash
python meshcore_keygen.py --prefix F8A1
```

#### 3. Vanity Patterns
Search for keys where first N hex characters match last N hex characters:

```bash
# 2-char vanity (first 2 == last 2 OR palindromic)
python meshcore_keygen.py --vanity-2

# 4-char vanity (first 4 == last 4 OR palindromic)
python meshcore_keygen.py --vanity-4

# 6-char vanity (first 6 == last 6 OR palindromic)
python meshcore_keygen.py --vanity-6

# 8-char vanity (first 8 == last 8 OR palindromic) - DEFAULT
python meshcore_keygen.py --vanity-8
```

#### 4. Prefix + Vanity
Combine prefix with vanity pattern:
```bash
python meshcore_keygen.py --prefix-vanity F8
```

#### 5. Legacy 4-Char Mode
Legacy mode with optional first-two constraint:
```bash
python meshcore_keygen.py --four-char
python meshcore_keygen.py --four-char --first-two F8
```

### Performance Options

#### Batch Size
Control the batch size for worker processes:
```bash
python meshcore_keygen.py --batch-size 500K  # 500K keys per batch
python meshcore_keygen.py --batch-size 2M    # 2M keys per batch
```

#### Health Monitoring
Enable or disable health monitoring:
```bash
python meshcore_keygen.py --health-check     # Enable (default)
python meshcore_keygen.py --no-health-check  # Disable
```

### Watchlist Feature

Monitor for additional patterns while searching for your primary target:

```bash
# Use custom watchlist file
python meshcore_keygen.py --watchlist patterns.txt

# Auto-loads watchlist.txt if it exists in the same directory
python meshcore_keygen.py --first-two F8
```

#### Watchlist File Format

Create a `watchlist.txt` file with patterns to monitor:

```
# Watchlist patterns (one per line)
ABCD...EFGH                    # First 4 chars and last 4 chars
ABCD...ABCDEFGH               # First 4 chars and last 8 chars  
ABCDEFGH...ABCD               # First 8 chars and last 4 chars
ABCD...EFGH|My cool pattern   # With optional description
# This is a comment line
```

### Output Formats

#### Text Format (Default)
Keys are saved as separate text files:
- `meshcore_XXXXXXXX_public.txt` - Public key
- `meshcore_XXXXXXXX_private.txt` - Private key

#### JSON Format
Save keys in JSON format for MeshCore app import:
```bash
python meshcore_keygen.py --vanity-4 --json
```

### Testing Functions

#### Compatibility Test
Test against known MeshCore keys:
```bash
python meshcore_keygen.py --test-compatibility
```

#### Distribution Test
Test distribution of first two hex characters:
```bash
python meshcore_keygen.py --test-distribution 0.1  # 100K keys
```

#### Entropy Test
Test randomness and entropy:
```bash
python meshcore_keygen.py --test-entropy 10  # 10K keys
```

#### Node ID Test
Test MeshCore node ID format:
```bash
python meshcore_keygen.py --test-meshcore-id 1  # 1K keys
```

## Examples

### Example 1: Find a Key Starting with "F8"
```bash
python meshcore_keygen.py --first-two F8
```
This will search for keys where the first two hex characters are "F8".

### Example 2: Find a 4-Char Vanity Key
```bash
python meshcore_keygen.py --vanity-4
```
This will search for keys where the first 4 hex characters match the last 4 hex characters.

### Example 3: Find a Key with Specific Prefix and Vanity
```bash
python meshcore_keygen.py --prefix-vanity F8
```
This will search for keys starting with "F8" AND having an 8-char vanity pattern.

### Example 4: Run for 2 Hours with Health Monitoring
```bash
python meshcore_keygen.py --vanity-6 --time 2 --health-check
```
This will search for 6-char vanity keys for 2 hours with health monitoring enabled.

### Example 5: Use Custom Watchlist
```bash
python meshcore_keygen.py --first-two F8 --watchlist my_patterns.txt
```
This will search for keys starting with "F8" while also monitoring patterns in `my_patterns.txt`.

## Output

When a matching key is found, the script will:

1. Display the key information
2. Verify the key compatibility
3. Save the keys to files
4. Show the MeshCore node ID

Example output:
```
SUCCESS! Found matching Ed25519 key!
Total time: 45.2s (0.8m)
============================================================

Generated MeshCore Ed25519 Vanity Key:
----------------------------------------
Matching Pattern: F8A1B2C3
First 8 hex:     F8A1B2C3
Last 8 hex:      D4E5F678

Public Key (hex):
f8a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12

Private Key (hex):
305e0b1b3142a95882915c43cd806df904247a2d505505f73dfb0cde9e666c4d656591bb4b5a23b6f47c786bf6cccfa0c4423c4617bbc9ab51dfb6f016f84144

Key Verification: ✓ PASS

Keys saved to:
  Public:  meshcore_F8A1B2C3_public.txt
  Private: meshcore_F8A1B2C3_private.txt
  Node ID: F8

⚠️  Keep your private key secure and never share it!

✓ This Ed25519 key should now work with MeshCore!
```

## Technical Details

### Key Format
- **Private Key**: 64 bytes (128 hex characters)
  - First 32 bytes: Clamped Ed25519 scalar
  - Last 32 bytes: Random filler
- **Public Key**: 32 bytes (64 hex characters)
  - Generated using `crypto_scalarmult_ed25519_base_noclamp`

### Algorithm
The script uses the correct Ed25519 algorithm that MeshCore expects:
1. Generate 32-byte random seed
2. SHA512 hash the seed
3. Manually clamp the first 32 bytes (scalar clamping)
4. Use `crypto_scalarmult_ed25519_base_noclamp` to get public key
5. Private key = `[clamped_scalar][random_filler]`

### Performance
- **Multi-processing**: Automatically detects optimal number of CPU cores
- **Batch Processing**: Configurable batch sizes for efficient resource usage
- **Health Monitoring**: Automatic worker restart on performance degradation
- **Memory Management**: Garbage collection optimization

## System Requirements

- **CPU**: Multi-core processor recommended
- **Memory**: 2GB+ RAM recommended for high-performance operation
- **Storage**: Minimal disk space for key files
- **OS**: Windows, macOS, or Linux

## Troubleshooting

### Common Issues

1. **"psutil not installed" warning**
   - Install with: `pip install psutil`
   - Health monitoring will work without it, but with limited features

2. **Performance issues**
   - Try reducing batch size: `--batch-size 500K`
   - Disable health monitoring: `--no-health-check`

3. **Memory usage**
   - The script automatically manages memory with garbage collection
   - Health monitoring will restart workers if memory usage is high

### Getting Help

If you encounter issues:
1. Check that all dependencies are installed
2. Try running with `--test-compatibility` to verify installation
3. Use smaller batch sizes if experiencing performance issues
4. Ensure you have sufficient system resources

## Security Notes

- **Private keys are sensitive**: Never share your private key
- **Generated keys are random**: Each run produces different results
- **Backup your keys**: Save generated keys in a secure location
- **Test before use**: Verify keys work with your MeshCore setup

## License

This project is open source. Please ensure you comply with any applicable licenses for dependencies.

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

---

**Note**: This tool generates vanity keys for MeshCore nodes. The generated keys are cryptographically secure Ed25519 keypairs that are compatible with the MeshCore protocol.
