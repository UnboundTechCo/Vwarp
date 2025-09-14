# Amnezia WireGuard Configuration Guide

This version of warp-plus includes Amnezia WireGuard obfuscation features that can help bypass deep packet inspection (DPI).

## Quick Start

### 1. Basic Usage (Without Amnezia)
```bash
# Normal WARP connection (uses old trick obfuscation)
./warp-plus.exe --bind 127.0.0.1:8080

# Disable old trick obfuscation completely
./warp-plus.exe --bind 127.0.0.1:8080 --endpoint 162.159.192.1:2408
```

### 2. Basic Amnezia Usage
```bash
# Enable Amnezia with basic obfuscation
./warp-plus.exe --bind 127.0.0.1:8080 --amnezia-enable

# With junk packets (recommended for bypassing DPI)
./warp-plus.exe --bind 127.0.0.1:8080 --amnezia-enable --amnezia-jc-enable

# With zero-size junk packets as requested
./warp-plus.exe --bind 127.0.0.1:8080 --amnezia-enable --amnezia-jc-enable --amnezia-junk-packet-min-size 0 --amnezia-junk-packet-max-size 0
```

### 3. Advanced Amnezia Configuration
```bash
# Full Amnezia configuration with custom signature packets and junk trains
./warp-plus.exe \
  --bind 127.0.0.1:8080 \
  --amnezia-enable \
  --amnezia-jc-enable \
  --amnezia-junk-packet-count 5 \
  --amnezia-junk-packet-min-size 0 \
  --amnezia-junk-packet-max-size 128 \
  --amnezia-junk-packet-min-delay 10 \
  --amnezia-junk-packet-max-delay 50 \
  --amnezia-init-packet-junk-size 64 \
  --amnezia-response-packet-junk-size 64 \
  --amnezia-init-packet-magic-header "c0ffee" \
  --amnezia-response-packet-magic-header "deadbeef" \
  --amnezia-underload-packet-magic-header "1337cafe"
```

## Amnezia Configuration Options

### Core Settings
- `--amnezia-enable`: Enable Amnezia WireGuard obfuscation
- `--amnezia-jc-enable`: Enable junk packet generation (recommended)

### I1-I5 Signature Packets
- `--amnezia-i1-packet`: Custom I1 signature packet (CPS format)
- `--amnezia-i2-packet`: Custom I2 signature packet (CPS format)
- `--amnezia-i3-packet`: Custom I3 signature packet (CPS format)
- `--amnezia-i4-packet`: Custom I4 signature packet (CPS format)
- `--amnezia-i5-packet`: Custom I5 signature packet (CPS format)

### Junk Packet Configuration
- `--amnezia-junk-packet-count`: Number of junk packets to send (1-10)
- `--amnezia-junk-packet-min-size`: Minimum junk packet size (0-1500)
- `--amnezia-junk-packet-max-size`: Maximum junk packet size (0-1500)
- `--amnezia-junk-packet-min-delay`: Minimum delay between junk packets (ms)
- `--amnezia-junk-packet-max-delay`: Maximum delay between junk packets (ms)

### Protocol Header Obfuscation
- `--amnezia-init-packet-junk-size`: Extra junk data size for init packets
- `--amnezia-response-packet-junk-size`: Extra junk data size for response packets
- `--amnezia-init-packet-magic-header`: Custom magic header for init packets (hex)
- `--amnezia-response-packet-magic-header`: Custom magic header for response packets (hex)
- `--amnezia-underload-packet-magic-header`: Custom magic header for underload packets (hex)

## CPS (Custom Protocol Signature) Format

The CPS format allows you to define custom signature packets:

```
<b hex_data>   - Insert raw hex bytes
<c>            - Insert random byte
<t>            - Insert current timestamp
<r length>     - Insert random data of specified length
```

Example:
```bash
--amnezia-i1-packet "<b c0ffee><c><t><r 64>"
```

This creates an I1 packet with:
- Raw bytes: 0xc0ffee
- One random byte
- Current timestamp
- 64 bytes of random data

## Testing Recommendations

### 1. Test Without Amnezia First
```bash
# Baseline test
./warp-plus.exe --bind 127.0.0.1:8080
curl --proxy socks5://127.0.0.1:8080 https://httpbin.org/ip
```

### 2. Test Basic Amnezia
```bash
# Basic Amnezia test
./warp-plus.exe --bind 127.0.0.1:8080 --amnezia-enable
curl --proxy socks5://127.0.0.1:8080 https://httpbin.org/ip
```

### 3. Test with Zero-Size Junk Packets (As Requested)
```bash
# Zero-size junk packets before handshake
./warp-plus.exe --bind 127.0.0.1:8080 --amnezia-enable --amnezia-jc-enable --amnezia-junk-packet-min-size 0 --amnezia-junk-packet-max-size 0
curl --proxy socks5://127.0.0.1:8080 https://httpbin.org/ip
```

### 4. Test with 1280-byte I1 Packets (As Requested)
```bash
# Send 1280-byte I1 packet before handshake
./warp-plus.exe --bind 127.0.0.1:8080 --amnezia-enable --amnezia-i1-packet "<r 1280>"
curl --proxy socks5://127.0.0.1:8080 https://httpbin.org/ip
```

## Key Changes Made

1. **Disabled Old Obfuscation**: When Amnezia is enabled, the old "trick" obfuscation is automatically disabled to prevent conflicts.

2. **Zero-Size Junk Support**: You can now send zero-size junk packets by setting both min and max size to 0.

3. **Custom I1-I5 Packets**: Send custom signature packets of any size before the handshake.

4. **Protocol Header Masking**: Add custom headers to make WireGuard traffic look like other protocols.

## Performance Notes

- Amnezia obfuscation adds some overhead compared to plain WireGuard
- Zero-size junk packets have minimal performance impact
- Large I1-I5 packets may increase handshake time
- Junk packet trains consume additional bandwidth

## Troubleshooting

1. If connection fails with Amnezia enabled, try without it first
2. Some networks may block large signature packets
3. Too many junk packets may trigger rate limiting
4. Check logs for Amnezia-specific error messages
