# Health Monitoring System

The MeshCore Ed25519 Vanity Key Generator now includes a comprehensive health monitoring system to maintain optimal performance over long running periods.

## Overview

The health monitoring system addresses the common issue of performance degradation that occurs when the script runs for extended periods. It automatically detects and responds to:

- Memory leaks
- Performance degradation
- System resource exhaustion
- Garbage collection issues

## Features

### 🔧 Memory Monitoring
- **Real-time memory usage tracking** (requires `psutil`)
- **Automatic garbage collection** when memory usage increases by 100MB
- **Periodic garbage collection** every 30 seconds

### 📊 Performance Tracking
- **Continuous performance monitoring** of keys/second rate
- **Performance degradation detection** when rate drops below 70% of baseline
- **Automatic worker restart** after 3 consecutive slow batches

### 🔄 Worker Management
- **Automatic worker restart** on performance degradation
- **Maximum restart limits** (5 restarts per worker)
- **Graceful degradation** when workers exceed restart limits

### 🛡️ System Resource Monitoring
- **CPU usage monitoring** (requires `psutil`)
- **Memory usage monitoring** (requires `psutil`)
- **Disk space monitoring** (requires `psutil`)

## Usage

### Basic Usage (Health Monitoring Enabled by Default)
```bash
python meshcore_keygen.py --vanity-4
```

### Disable Health Monitoring
```bash
python meshcore_keygen.py --vanity-4 --no-health-check
```

### Explicitly Enable Health Monitoring
```bash
python meshcore_keygen.py --vanity-4 --health-check
```

## Requirements

### Required
- `PyNaCl` - For Ed25519 key generation
- `Python 3.7+`

### Optional (for full health monitoring)
- `psutil` - For system resource monitoring
  ```bash
  pip install psutil
  ```

## Health Monitoring Output

When health monitoring is enabled, you'll see output like:

```
Worker 1: Health monitoring enabled
Worker 1: Completed batch of 1,000,000 keys in 45.2s (22,124 keys/sec) | Total: 1,000,000

Worker 1 Health Check:
  ⚠️  Memory usage increased by 125.3MB
  🔧 Triggered garbage collection
  📊 Memory: 245.7MB
  📊 CPU: 85.2%
  📊 Performance: 95% of baseline

Worker 1: Performance degradation detected (1/3)
```

## Configuration

### Health Monitoring Thresholds

The following thresholds can be adjusted in the `HealthMonitor` class:

- **Memory threshold**: 100MB increase triggers GC
- **Performance threshold**: 70% degradation triggers restart
- **GC interval**: 30 seconds between forced GC
- **Memory check interval**: 10 seconds between memory checks
- **Max slow batches**: 3 consecutive slow batches trigger restart
- **Max restarts per worker**: 5 restarts before giving up

### Batch Size Optimization

For optimal health monitoring, consider these batch size recommendations:

- **Small batch size** (500K-1M): More frequent health checks, faster restart
- **Large batch size** (2M+): Less overhead, but slower to detect issues

```bash
# For better health monitoring
python meshcore_keygen.py --batch-size 500K --vanity-4

# For maximum performance (less frequent health checks)
python meshcore_keygen.py --batch-size 2M --vanity-4
```

## Troubleshooting

### Performance Still Degrades

If you're still experiencing performance issues:

1. **Check system resources**:
   ```bash
   python meshcore_keygen.py --vanity-4
   # Look for system resource status at startup
   ```

2. **Reduce batch size**:
   ```bash
   python meshcore_keygen.py --batch-size 250K --vanity-4
   ```

3. **Monitor worker restarts**:
   - Look for "Restarting worker" messages
   - If workers restart frequently, consider reducing batch size

### Memory Issues

If you see memory warnings:

1. **Install psutil** for better memory monitoring:
   ```bash
   pip install psutil
   ```

2. **Reduce batch size** to trigger GC more frequently:
   ```bash
   python meshcore_keygen.py --batch-size 500K --vanity-4
   ```

3. **Monitor system memory**:
   - Check if other processes are consuming memory
   - Consider closing other applications

### Worker Restart Issues

If workers restart too frequently:

1. **Check system resources** at startup
2. **Reduce batch size** for more frequent health checks
3. **Monitor for external factors** affecting performance

## Testing

Test the health monitoring system:

```bash
python test_health_monitor.py
```

This will simulate various scenarios and verify the health monitoring functionality.

## Performance Impact

The health monitoring system has minimal performance impact:

- **Memory monitoring**: ~0.1% overhead (with psutil)
- **Performance tracking**: ~0.05% overhead
- **Garbage collection**: Temporary pauses, but improves overall performance
- **Worker restart**: Brief interruption, but maintains long-term performance

## Best Practices

1. **Always enable health monitoring** for long-running searches
2. **Install psutil** for full system monitoring
3. **Use appropriate batch sizes** (500K-1M for health monitoring, 2M+ for performance)
4. **Monitor system resources** at startup
5. **Watch for worker restart messages** to identify performance issues

## Example Long-Running Search

```bash
# Start a long-running search with health monitoring
python meshcore_keygen.py --vanity-6 --time 8 --batch-size 750K

# This will:
# - Search for 6-character vanity patterns
# - Run for 8 hours maximum
# - Use 750K batch size for good health monitoring
# - Automatically restart workers if performance degrades
# - Monitor memory and CPU usage
```

The health monitoring system ensures your key generation maintains optimal performance throughout the entire search process.
