# MeshCore Ed25519 Key Generator

A key generator for MeshCore nodes that creates Ed25519 keypairs with custom patterns. This tool generates MeshCore-compatible Ed25519 keys with various cosmetic patterns for personalized node identification.

## Features

- **MeshCore-Compatible**: Generates Ed25519 keys in the exact format MeshCore expects
- **Multiple Pattern Modes**: Support for various cosmetic pattern matching modes
- **Multi-Processing**: Multi-processor support with batch processing
- **Health Monitoring**: Automatic performance monitoring and worker restart
- **Watchlist Support**: Monitor for additional patterns while searching
- **Flexible Output**: Save keys in text or JSON format for MeshCore app import
- **Progress Bars**: Visual progress tracking with tqdm (when not in verbose mode)
- **Verbose Mode**: Control output detail level with `--verbose` option
- **Memory Management**: Configurable garbage collection and memory monitoring

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Dependencies

Install the required packages:

```bash
pip install PyNaCl
pip install tqdm    # Required for progress bars
pip install psutil  # Optional, for enhanced health monitoring
```

## Usage

### Basic Commands

```bash
# Generate a key with default 8-char pattern
python meshcore_keygen.py

# Search for keys starting with specific hex prefix
python meshcore_keygen.py --first-two F8

# Generate key with 4-char pattern
python meshcore_keygen.py --pattern-4

# Search for keys with specific prefix
python meshcore_keygen.py --prefix F8A1

# Run for specific number of keys
python meshcore_keygen.py --keys 100  # 100 million keys

# Run for specific time
python meshcore_keygen.py --time 2    # 2 hours

# Enable verbose output for detailed progress
python meshcore_keygen.py --verbose   # Show per-worker details (disables progress bar)
python meshcore_keygen.py -v          # Short form for verbose mode
```

### Cosmetic Pattern Modes

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

#### 3. Cosmetic Pattern Matching
Search for keys where first N hex characters match last N hex characters:

```bash
# 2-char cosmetic pattern (first 2 == last 2 OR palindromic)
python meshcore_keygen.py --pattern-2

# 4-char cosmetic pattern (first 4 == last 4 OR palindromic)
python meshcore_keygen.py --pattern-4

# 6-char cosmetic pattern (first 6 == last 6 OR palindromic)
python meshcore_keygen.py --pattern-6

# 8-char cosmetic pattern (first 8 == last 8 OR palindromic) - DEFAULT
python meshcore_keygen.py --pattern-8
```

#### 4. Prefix + Cosmetic Pattern
Combine prefix with cosmetic pattern matching:
```bash
python meshcore_keygen.py --prefix-pattern F8
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

#### Progress Display
Control how progress is displayed:
```bash
# Default: Progress bar with consolidated updates (when tqdm is available)
python meshcore_keygen.py --first-two F8

# Verbose mode: Detailed per-worker output (disables progress bar)
python meshcore_keygen.py --verbose          # Enable verbose mode (per-worker details)
python meshcore_keygen.py -v                 # Short form for verbose mode
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
  python meshcore_keygen.py --pattern-4 --json
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

### Example 2: Find a 4-Char Cosmetic Pattern Key
```bash
python meshcore_keygen.py --pattern-4
```
This will search for keys where the first 4 hex characters match the last 4 hex characters.

### Example 3: Find a Key with Specific Prefix and Cosmetic Pattern
```bash
python meshcore_keygen.py --prefix-pattern F8
```
This will search for keys starting with "F8" AND having an 8-char cosmetic pattern.

### Example 4: Run for 2 Hours with Health Monitoring
```bash
python meshcore_keygen.py --pattern-6 --time 2 --health-check
```
This will search for 6-char cosmetic pattern keys for 2 hours with health monitoring enabled.

### Example 5: Use Custom Watchlist
```bash
python meshcore_keygen.py --first-two F8 --watchlist my_patterns.txt
```
This will search for keys starting with "F8" while also monitoring patterns in `my_patterns.txt`.

### Example 6: Verbose Mode for Debugging
```bash
python meshcore_keygen.py --pattern-6 --verbose
```
This will search for 6-char cosmetic pattern keys with detailed per-worker progress and health monitoring information.

### Example 7: Clean Output Mode (Default)
```bash
python meshcore_keygen.py --first-two F8
```
This will search for keys starting with "F8" with clean, consolidated progress updates every 5 seconds.

## Output

### Default Mode (Progress Bar)
- **Visual progress bar** showing current progress, rate, and estimated time remaining
- **Consolidated progress updates** every 5 seconds showing total attempts, rate, and elapsed time
- **Key finds reported immediately** when discovered
- **Watchlist matches reported immediately** when found
- **Clean output** for focused operation

### Verbose Mode (`--verbose` or `-v`)
- **Per-worker progress updates** with individual rates and ETAs
- **Health monitoring details** including memory/CPU usage
- **Batch completion reports** for each worker
- **Performance degradation warnings**
- **Worker restart notifications**
- **Garbage collection information**

### Key Discovery
When a matching key is found, the script will:

1. Display the key information
2. Verify the key compatibility
3. Save the keys to files
4. Show the MeshCore node ID

Example output:

**Default Mode Progress:**
```
Progress: 15,234,567 total attempts | 6,688 keys/sec | 2,278.5s elapsed
```

**Verbose Mode Progress:**
```
Worker 0: 3,234,567 attempts | 6,688 keys/sec | 483.7s | ETA: 2.1h
Worker 1: 3,245,678 attempts | 6,712 keys/sec | 483.7s | ETA: 2.1h
Worker 2: 3,256,789 attempts | 6,745 keys/sec | 483.7s | ETA: 2.0h
Worker 3: 3,267,890 attempts | 6,678 keys/sec | 483.7s | ETA: 2.1h
```

**Key Discovery (Both Modes):**
```
SUCCESS! Found matching Ed25519 key!
Total time: 45.2s (0.8m)
============================================================

Generated MeshCore Ed25519 Key:
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
- **Batch Processing**: Configurable batch sizes for resource usage
- **Health Monitoring**: Automatic worker restart on performance degradation
- **Memory Management**: Configurable garbage collection (every 2 minutes) and memory monitoring
- **Output Control**: Verbose mode for debugging, clean mode for standard use

## System Requirements

- **CPU**: Multi-core processor recommended
- **Memory**: 2GB+ RAM recommended
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
   - Use clean output mode (default) for better performance

3. **Memory usage**
   - The script automatically manages memory with configurable garbage collection
   - Health monitoring will restart workers if memory usage is high
   - Garbage collection frequency can be adjusted as needed

4. **Too much output**
   - Use default mode for clean output
   - Use `--verbose` only when debugging or monitoring performance

5. **Watchlist performance impact**
   - Large watchlists can reduce performance by ~27%
   - Consider using a smaller curated watchlist for better performance
   - Run without watchlist for improved speed

6. **Progress bar not showing**
   - Ensure tqdm is installed: `pip install tqdm`
   - Progress bars are disabled in verbose mode (`--verbose`)
   - For very long searches, progress bars may be indeterminate (no total shown)

### Getting Help

If you encounter issues:
1. Check that all dependencies are installed
2. Try running with `--test-compatibility` to verify installation
3. Use smaller batch sizes if experiencing performance issues
4. Ensure you have sufficient system resources
5. Use `--verbose` mode to debug performance or health monitoring issues
6. Check the troubleshooting section above for common solutions

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

**Note**: This tool generates cosmetic pattern keys for MeshCore nodes. The generated keys are Ed25519 keypairs that are compatible with the MeshCore protocol.
