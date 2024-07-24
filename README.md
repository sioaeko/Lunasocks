
![Fotoram io](https://github.com/user-attachments/assets/04635a76-2e42-454f-aacb-2f7f1173c6b4)

# 🌙 Lunasocks: The Next-Gen SOCKS5 Proxy Server

## 🚀 Supercharge Your Network with Lunasocks! 🚀

Lunasocks is not just another SOCKS5 proxy - it's a high-performance, 
feature-rich server that takes your network capabilities to the next level.

## ✨ Key Features

- 🔒 Robust SOCKS5 protocol support with TLS encryption
- 🛡️ Secure authentication system
- 🧩 Extensible plugin architecture
- 🕹️ User-friendly web management interface

## 🏆 Why Choose Lunasocks?

1. **🚄 BLAZING FAST:** 
   Harnesses Go's concurrency for unparalleled speed and efficiency.

2. **🛠️ HIGHLY EXTENSIBLE:** 
   Customize and extend functionality with our powerful plugin system.

3. **🔐 FORT KNOX SECURITY:** 
   TLS support and authentication keep your connections fortress-strong.

4. **🎛️ FLEXIBLE CONFIGURATION:** 
   Easily adapt to any network environment.

5. **👨‍💼 EFFORTLESS MANAGEMENT:** 
   Intuitive web interface for smooth server administration.

## 🚀 Getting Started

1. Clone:    `git clone https://github.com/yourusername/lunasocks.git`
2. Install:  `cd lunasocks && go mod tidy`
3. Launch:   `go run main.go`

## 🔧 Configuration Made Easy

Edit `config.yaml` to tailor Lunasocks to your needs:
- `ServerAddress`: Your SOCKS5 server's home
- `Password`: Keep intruders out
- `UseTLS`: Encrypt like a pro
- `TLSCertFile` & `TLSKeyFile`: Your security credentials

## 💡 Extend with Plugins

Create powerful plugins with just a few lines of code!

```go
type LoggingPlugin struct{}

func (p *LoggingPlugin) OnConnect(conn net.Conn) {
    log.Printf("New SOCKS5 connection from %s", conn.RemoteAddr())
}

func (p *LoggingPlugin) OnData(data []byte) []byte {
    log.Printf("Proxying data: %d bytes", len(data))
    return data
}
```

## 🌐 Web Management at Your Fingertips:

Access your control center at port 8080:
  • Adjust configurations on the fly
  • Monitor your proxy's pulse
  • Track connection stats with ease

## 🤝 Join the Lunasocks Revolution:
We welcome your contributions! Send us a Pull Request and help shape the future of proxy servers.

## 📜 License:
Lunasocks is proudly distributed under the MIT License.

-----------------------------------------
Elevate your network experience with Lunasocks - 
Where speed meets security, and simplicity embraces power!
