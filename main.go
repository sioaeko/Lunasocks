package main

import (
    "flag"
    "log"
    "time"

    "your_project/client"
    "your_project/network"
    "your_project/plugin"
)

func main() {
    var mode string
    var serverAddr, localAddr, password string
    var timeout time.Duration
    var useTLS bool
    var certFile, keyFile string

    flag.StringVar(&mode, "mode", "server", "Run as 'server' or 'client'")
    flag.StringVar(&serverAddr, "server", "0.0.0.0:8388", "Server address")
    flag.StringVar(&localAddr, "local", "127.0.0.1:1080", "Local address (client mode only)")
    flag.StringVar(&password, "password", "", "Password")
    flag.DurationVar(&timeout, "timeout", 5*time.Minute, "Connection timeout")
    flag.BoolVar(&useTLS, "tls", false, "Use TLS")
    flag.StringVar(&certFile, "cert", "server.crt", "TLS certificate file")
    flag.StringVar(&keyFile, "key", "server.key", "TLS key file")
    flag.Parse()

    if password == "" {
        log.Fatal("Password is required")
    }

    switch mode {
    case "server":
        server := network.NewServer(serverAddr, password, timeout)
        if useTLS {
            err := server.EnableTLS(certFile, keyFile)
            if err != nil {
                log.Fatalf("Failed to enable TLS: %v", err)
            }
        }
        // 플러그인 추가 예시
        server.AddPlugin(&plugin.LoggingPlugin{})
        log.Fatal(server.Start())
    case "client":
        client := client.NewClient(serverAddr, localAddr, password, timeout)
        if useTLS {
            client.EnableTLS()
        }
        log.Fatal(client.Start())
    default:
        log.Fatalf("Invalid mode: %s", mode)
    }
}
