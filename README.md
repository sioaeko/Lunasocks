![Fotoram io](https://github.com/user-attachments/assets/04635a76-2e42-454f-aacb-2f7f1173c6b4)

# Lunasocks

A high-performance SOCKS5 proxy server written in Go with Shadowsocks protocol support, TLS encryption, and a web management interface.

## Features

- **SOCKS5 Protocol** - Full SOCKS5 support with TCP and UDP relay
- **Shadowsocks** - Encrypted proxy connections using AES-256-GCM or ChaCha20-Poly1305
- **TLS Encryption** - Optional TLS for the control channel
- **Plugin System** - Extensible plugin architecture for connection/data hooks
- **Web Dashboard** - Browser-based configuration and monitoring interface
- **Client Mode** - Built-in SOCKS5 client for connecting to Lunasocks servers

## Getting Started

```bash
git clone https://github.com/sioaeko/Lunasocks.git
cd Lunasocks
go mod tidy
go build -o lunasocks .
```

### Run the server

```bash
# With default config
./lunasocks --config config.yaml

# With TLS and web admin
./lunasocks --config config.yaml --tls --web-admin --web-admin-port 8080

# With debug logging
./lunasocks --config config.yaml --log-level debug
```

## Configuration

Edit `config.yaml`:

```yaml
server_address: "0.0.0.0:1080"
password: "your-secure-password"
method: "aes-256-gcm"        # or "chacha20-poly1305"
timeout: 30                   # seconds
use_tls: false
tls_cert_file: ""
tls_key_file: ""
```

## Project Structure

```
lunasocks/
├── main.go                 # Entry point, CLI flags
├── config.yaml             # Default configuration
├── config/
│   └── config.go           # YAML config loading & validation
├── crypto/
│   ├── aead.go             # AEAD cipher (AES-GCM, ChaCha20-Poly1305)
│   ├── kdf.go              # HKDF key derivation
│   └── crypto_test.go      # Cipher & KDF tests
├── logging/
│   └── logger.go           # Leveled logging (debug/info/error)
├── network/
│   ├── server.go           # Main server (TCP accept loop, auth, plugins)
│   ├── tcp.go              # Shadowsocks TCP server
│   └── udp.go              # Encrypted UDP relay
├── protocol/
│   ├── socks5.go           # SOCKS5 handshake & request parsing
│   └── shadowsocks.go      # Shadowsocks connection handler
├── socks/
│   ├── socks.go            # SOCKS address parsing utilities
│   └── socks_test.go       # Address parsing tests
├── plugin/
│   └── plugin.go           # Plugin interface & LoggingPlugin
├── client/
│   └── client.go           # SOCKS5 client with encryption
├── web/
│   └── server.go           # Web dashboard API server
├── pkg/
│   └── pool/
│       └── pool.go         # sync.Pool-based buffer pool
└── templates/
    └── index.html          # Web dashboard UI
```

## Plugin System

Create plugins by implementing the `Plugin` interface:

```go
type Plugin interface {
    Name() string
    OnConnect(conn net.Conn)
    OnData(data []byte) []byte
}
```

Register plugins before starting the server:

```go
server.AddPlugin(&plugin.LoggingPlugin{})
```

## Web Management

Start with `--web-admin` to access the dashboard at `http://localhost:8080`:

- View server status (running/stopped)
- Update configuration (address, password, encryption method, timeout)
- Auto-refreshing status indicator

## License

MIT License
