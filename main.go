package main

import (
    "flag"
    "log"
    "time"

    "your_project/client"
    "your_project/network"
)

func main() {
    var mode string
    var serverAddr, localAddr, password string
    var timeout time.Duration

    flag.StringVar(&mode, "mode", "server", "Run as 'server' or 'client'")
    flag.StringVar(&serverAddr, "server", "0.0.0.0:8388", "Server address")
    flag.StringVar(&localAddr, "local", "127.0.0.1:1080", "Local address (client mode only)")
    flag.StringVar(&password, "password", "", "Password")
    flag.DurationVar(&timeout, "timeout", 5*time.Minute, "Connection timeout")
    flag.Parse()

    if password == "" {
        log.Fatal("Password is required")
    }

    switch mode {
    case "server":
        server := network.NewServer(serverAddr, password, timeout)
        log.Fatal(server.Start())
    case "client":
        client := client.NewClient(serverAddr, localAddr, password, timeout)
        log.Fatal(client.Start())
    default:
        log.Fatalf("Invalid mode: %s", mode)
    }
}
