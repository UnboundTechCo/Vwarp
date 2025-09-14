# Amnezia WireGuard Features

This project now supports **Amnezia WireGuard** obfuscation features based on the [Amnezia WG specification](https://docs.amnezia.org/documentation/amnezia-wg). These features help bypass Deep Packet Inspection (DPI) by making WireGuard traffic look like common UDP protocols.

## Features

### Protocol Signature Packets (I1-I5)

The Amnezia implementation supports up to 5 signature packets that can mimic different protocols:

- **I1**: Main obfuscation packet (hex string) - typically contains a large payload to mimic QUIC Initial packets
- **I2-I5**: Additional signature packets using Custom Protocol Signature (CPS) format

### Custom Protocol Signature (CPS) Format

The CPS format allows you to create protocol-mimicking packets using tags:

- `<b hex_data>`: Static bytes to emulate protocols
- `<c>`: Packet counter (32-bit, network byte order)
- `<t>`: Unix timestamp (32-bit, network byte order)  
- `<r length>`: Cryptographically secure random bytes (max 1000)

Example: `<b 16030100><c><r 50>` creates a TLS-like packet

### Junk Packet Generation

- **Jc**: Number of junk packets (0-10)
- **Jmin/Jmax**: Size range for junk packets
- **JcAfterI1**: Junk packets after I1 packet
- **JcBeforeHS**: Junk packets before handshake
- **JcAfterHS**: Junk packets after handshake
- **AllowZeroSize**: Enable zero-size junk packets for better evasion

### Timing Controls

- **JunkInterval**: Interval between junk packets
- **HandshakeDelay**: Delay before actual handshake after I-sequence

## Usage

### Command Line Flags

```bash
# Basic Amnezia configuration
./warp-plus --amnezia-i1="c200000001..." --amnezia-jc=8 --amnezia-allow-zero-size

# Full configuration
./warp-plus \
  --amnezia-i1="c200000001..." \
  --amnezia-i2="<b 16030100><c><r 50>" \
  --amnezia-i3="<b 450000><t><r 32>" \
  --amnezia-i4="<b 534950><c><t><r 24>" \
  --amnezia-i5="<r 64>" \
  --amnezia-jc=8 \
  --amnezia-jmin=24 \
  --amnezia-jmax=96 \
  --amnezia-jc-after-i1=5 \
  --amnezia-jc-before-hs=3 \
  --amnezia-jc-after-hs=2 \
  --amnezia-junk-interval=10ms \
  --amnezia-allow-zero-size \
  --amnezia-handshake-delay=50ms
```

### Configuration File

Use a JSON configuration file for easier management:

```bash
./warp-plus --config=amnezia_example_config.json
```

See `amnezia_example_config.json` for a complete example.

### Available Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--amnezia-i1` | string | "" | I1 signature packet (hex string) |
| `--amnezia-i2` | string | "" | I2 signature packet (CPS format) |
| `--amnezia-i3` | string | "" | I3 signature packet (CPS format) |
| `--amnezia-i4` | string | "" | I4 signature packet (CPS format) |
| `--amnezia-i5` | string | "" | I5 signature packet (CPS format) |
| `--amnezia-s1` | int | 0 | Random prefix for Init packets (0-64 bytes) |
| `--amnezia-s2` | int | 0 | Random prefix for Response packets (0-64 bytes) |
| `--amnezia-jc` | int | 0 | Number of junk packets (0-10) |
| `--amnezia-jmin` | int | 24 | Minimum junk packet size |
| `--amnezia-jmax` | int | 1024 | Maximum junk packet size |
| `--amnezia-jc-after-i1` | int | 0 | Junk packets after I1 packet |
| `--amnezia-jc-before-hs` | int | 0 | Junk packets before handshake |
| `--amnezia-jc-after-hs` | int | 0 | Junk packets after handshake |
| `--amnezia-junk-interval` | duration | 10ms | Interval between junk packets |
| `--amnezia-allow-zero-size` | bool | false | Allow zero-size junk packets |
| `--amnezia-handshake-delay` | duration | 0ms | Delay before handshake after I-sequence |

## Protocol Mimicking Examples

### QUIC Protocol
```bash
--amnezia-i1="c200000001..." --amnezia-i2="<b 16030100><c><r 50>"
```

### DNS Query
```bash
--amnezia-i3="<b 450000><t><r 32>"
```

### SIP Protocol  
```bash
--amnezia-i4="<b 534950><c><t><r 24>"
```

### Random Traffic
```bash
--amnezia-i5="<r 64>" --amnezia-allow-zero-size --amnezia-jc=10
```

## How It Works

1. **Before Handshake**: Optional junk packets are sent (JcBeforeHS)
2. **I-Sequence**: I1-I5 signature packets are sent in order to mimic protocols
3. **After I1**: Additional junk packets follow I1 (JcAfterI1)
4. **Junk Train**: General junk packets are sent (Jc)
5. **Delay**: Optional delay before actual handshake (HandshakeDelay)
6. **Handshake**: Normal WireGuard handshake proceeds
7. **After Handshake**: Optional junk packets after handshake (JcAfterHS)

## Security

- All obfuscation happens at the transport layer
- WireGuard's cryptography remains unchanged
- Compatible with standard WireGuard when obfuscation is disabled
- Zero-size packets provide additional evasion capabilities

## Compatibility

When no Amnezia parameters are set, the application behaves exactly like standard WireGuard, ensuring backward compatibility.
