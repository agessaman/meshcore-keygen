# Release Notes - MeshCore Ed25519 Key Generator

## Version 1.0.0 - Initial Release

**Release Date:** August 2025  
**Status:** Initial Release

---

## What's New

Initial release of the MeshCore Ed25519 Key Generator - a tool for generating vanity Ed25519 keypairs compatible with MeshCore protocol.

### Key Features

- **MeshCore-Compatible**: Generates Ed25519 keys in exact format MeshCore expects
- **Multiple Pattern Modes**: Simple, prefix, cosmetic patterns (2-8 chars)
- **Multi-Processing**: Auto-detects optimal CPU cores (75% usage)
- **Health Monitoring**: Automatic performance monitoring and worker restart
- **Watchlist Support**: Monitor additional patterns while searching
- **Flexible Output**: Text or JSON format for MeshCore app import

---

## Technical Details

### Key Format
- **Private Key**: 64 bytes (128 hex chars) - [clamped_scalar][random_filler]
- **Public Key**: 32 bytes (64 hex chars) - from crypto_scalarmult_ed25519_base_noclamp

### Algorithm
1. Generate 32-byte random seed
2. SHA512 hash the seed
3. Clamp first 32 bytes (Ed25519 scalar clamping)
4. Generate public key using clamped scalar
5. Create private key with clamped scalar + random filler

---

## Pattern Modes

- **Simple**: `--simple --first-two F8` (specific first two chars)
- **Prefix**: `--prefix F8A1` (specific hex prefix)
- **Cosmetic**: `--pattern-4` (first 4 chars == last 4 chars)
- **Combined**: `--prefix F8 --pattern-8` (prefix + cosmetic pattern)

---

## Quick Start

```bash
# Install
pip install PyNaCl tqdm psutil

# Generate key starting with F8
python meshcore_keygen.py --first-two F8

# Test compatibility
python meshcore_keygen.py --test-compatibility
```

---

## System Requirements

- Python 3.7+
- Multi-core CPU
- 2GB+ RAM
- Windows/macOS/Linux

---

## Testing

- `--test-compatibility`: Verify against known MeshCore keys
- `--test-distribution 0.1`: Test first-two char distribution (100K keys)
- `--test-entropy 10`: Test randomness (10K keys)
- `--test-meshcore-id 1`: Test node ID format (1K keys)

---

## Future Enhancements

- GPU acceleration support
- Additional pattern modes
- Web interface
- Real-time statistics dashboard

---

**Note**: Keep private keys secure and never share them.
