# DarkProbe

A powerful network reconnaissance and security testing utility for discovering hosts, fingerprinting operating systems, and performing advanced network diagnostics.

## Features

### Core Functionality
- **Network Discovery** - Automated subnet detection and host enumeration with OS fingerprinting
- **Passive Network Sniffing** - Capture and analyze live traffic for protocol detection and hostname discovery
- **WPA2-PSK Decryption** - Real-time wireless traffic decryption via 4-way handshake capture
- **Neighbor Discovery** - CDP/LLDP passive detection for network topology mapping
- **Routing Protocol Visibility** - Monitor RIP, BGP, and OSPF routing updates
- **Telemetry Reporting** - Centralized intelligence gathering via darkapi.io integration
- **Remote Execution** - gRPC daemon mode with mTLS and JWT authentication

### Advanced Testing Modules

#### Authentication Testing
- **RADIUS** - Test RADIUS authentication directly via Access-Request packets
- **802.1X EAPOL** - Inject EAPOL-Start frames to test switch port authentication requirements

#### Network Diagnostics
- **DNS Trace** - Perform recursive DNS resolution tracing from root to authoritative nameservers
- **UDP Jitter** - High-frequency UDP probing to measure network jitter and packet timing
- **SIP Discovery** - Active SIP OPTIONS scanning to discover PBX/SBC systems and supported methods
- **TLS/SSL Inspection** - Deep certificate chain inspection and validation

### Extensibility
- **Starlark Plugin System** - Write custom packet inspection logic in Starlark for threat hunting and anomaly detection
- **Anomaly Detection Engine** - Built-in pattern recognition for suspicious network activity

## Installation

### Prerequisites
- Go 1.24+
- Root/CAP_NET_RAW capabilities for packet capture features

### Build from Source
```bash
./build.sh
```

Or manually:
```bash
go build -o darkprobe
```

## Usage

### Basic Network Discovery
Auto-detect and scan your local subnet:
```bash
./darkprobe
```

Specify a subnet manually:
```bash
./darkprobe --subnet 192.168.1.0/24
```

### Passive Network Sniffing
Requires root privileges for packet capture:
```bash
sudo ./darkprobe sniff --interface en0 --duration 60s
```

Enable wireless monitor mode:
```bash
sudo ./darkprobe sniff --interface en0 --monitor-mode --duration 60s
```

Decrypt WPA2-PSK encrypted traffic (requires 4-way handshake):
```bash
sudo ./darkprobe sniff --interface en0 --monitor-mode --wpa-ssid "MyNetwork" --wpa-psk "MyPassphrase"
```

Load custom Starlark plugins:
```bash
sudo ./darkprobe sniff --interface en0 --plugin-dir ./plugins
```

View discovered CDP/LLDP neighbors:
```bash
# Neighbors are automatically detected during sniffing
sudo ./darkprobe sniff --interface en0 --duration 30s
```

### RADIUS Authentication Testing
```bash
./darkprobe radius --server 192.168.1.1:1812 --secret MySecret --user testuser --pass testpass
```

### 802.1X EAPOL Testing
Inject EAPOL-Start frames to test port-based authentication:
```bash
sudo ./darkprobe eapol --interface eth0
```

### DNS Trace
Trace DNS resolution from root nameservers:
```bash
./darkprobe dns-trace example.com
```

### Network Jitter Testing
```bash
./darkprobe jitter 192.168.1.1 --port 33434 --count 100 --interval 10
```

### SIP Discovery
```bash
./darkprobe sip 192.168.1.100 --port 5060 --udp
```

### TLS Certificate Inspection
```bash
./darkprobe cert example.com --port 443
```

## Daemon Mode

DarkProbe supports remote execution via a gRPC daemon with mTLS and JWT authentication.

### Starting the Daemon

```bash
sudo ./darkprobed \
  --listen localhost:50051 \
  --cert /path/to/server.crt \
  --key /path/to/server.key \
  --ca /path/to/ca.crt \
  --jwt-secret "your-shared-secret"
```

### Connecting as a Client

All commands support remote execution by specifying daemon connection parameters:

```bash
./darkprobe discover \
  --daemon-addr localhost:50051 \
  --tls /path/to/ca.crt \
  --jwt /path/to/token.json \
  --subnet 192.168.1.0/24
```

JWT token file format (`token.json`):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Remote sniffing with WPA2 decryption:
```bash
./darkprobe sniff \
  --daemon-addr localhost:50051 \
  --tls /path/to/ca.crt \
  --jwt /path/to/token.json \
  --interface en0 \
  --monitor-mode \
  --wpa-ssid "TargetNetwork" \
  --wpa-psk "Passphrase123"
```

## Telemetry Reporting

DarkProbe can report findings to darkapi.io for centralized intelligence:

```bash
export DARKAPI_TOKEN="your-api-key"
./darkprobe --subnet 192.168.1.0/24 --endpoint https://api.darkapi.io/api/v1/darkprobe/telemetry
```

Or specify the API key directly:
```bash
./darkprobe --subnet 192.168.1.0/24 --api-key your-api-key
```

## Starlark Plugin Development

Create custom packet inspection logic by writing Starlark scripts. Example plugin:

```python
def process_packet(pkt):
    print("Processing packet from: " + pkt["ip"])

    # Threat hunting logic
    if "802.1X (EAPOL)" in pkt.get("protocols", []):
        print(">>> ALERT: EAPOL handshake from " + pkt["mac"])

    if pkt.get("os"):
        print("Detected OS: " + pkt["os"])
```

Place your `.star` files in the `plugins/` directory or specify a custom path with `--plugin-dir`.

## Architecture

```
darkprobe/
├── cmd/
│   └── darkprobed/      # gRPC daemon server
├── scanner/             # Core scanning and detection engines
│   ├── discover.go       # Active network discovery
│   ├── pcap.go          # Passive packet capture (802.11 & Ethernet)
│   ├── wpa2_decrypt.go  # WPA2-PSK CCMP decryption
│   ├── neighbor.go      # CDP/LLDP neighbor discovery
│   ├── proto_types.go   # Routing protocol data structures
│   ├── starlark_engine.go  # Plugin runtime
│   ├── anomaly_engine.go   # Threat detection
│   └── *_tester.go      # Protocol-specific testers
├── reporter/            # Telemetry reporting
├── proto/              # gRPC protocol definitions
│   ├── darkprobe.proto  # Service definitions
│   └── *.pb.go         # Generated gRPC code
└── main.go             # CLI client
```

### Key Components

- **WPA2 Decryptor**: Captures EAPOL 4-way handshakes and derives PTK using PBKDF2 + PRF-512 for real-time AES-CCMP decryption
- **gRPC Service**: mTLS-secured remote execution with JWT authentication
- **Passive Scanner**: 802.11 monitor mode support with protocol fingerprinting
- **Neighbor Discovery**: Automatic CDP/LLDP parsing for network topology mapping

## Security Considerations

DarkProbe is designed for authorized security testing, network auditing, and defensive security research. Usage scenarios include:

- Internal network security audits
- Penetration testing engagements (with authorization)
- Network troubleshooting and diagnostics
- Security research and CTF challenges
- Defensive security monitoring
- Wireless security assessments (authorized networks only)

### Wireless Decryption

The WPA2-PSK decryption feature requires:
- Valid network credentials (SSID + passphrase)
- Capture of the 4-way EAPOL handshake
- Monitor mode support on the wireless interface

This feature is intended for:
- Testing security of networks you own/manage
- Authorized penetration testing engagements
- Defensive monitoring of your own infrastructure

### Daemon Security

When running in daemon mode:
- **mTLS** provides mutual authentication (server + client certificates)
- **JWT tokens** provide additional authorization layer
- All traffic is encrypted over TLS
- Use strong secrets for JWT signing

**Important**: Obtain proper authorization before scanning networks you do not own or manage. Unauthorized interception of wireless communications may violate laws including the Computer Fraud and Abuse Act (CFAA) and similar regulations.

## License

Copyright AfterDark Systems. All rights reserved.

## Contributing

Issues and pull requests are welcome at https://github.com/afterdarksys/darkprobe
