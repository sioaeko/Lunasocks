package server

import (
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "time"

    "your_project/crypto"
    "your_project/socks"
)

type UDPConn struct {
    conn     *net.UDPConn
    cipher   *crypto.Cipher
    timeout  time.Duration
    clientID string
}

func (s *Server) handleUDP() {
    addr, err := net.ResolveUDPAddr("udp", s.address)
    if err != nil {
        log.Fatalf("Failed to resolve UDP address: %v", err)
    }

    conn, err := net.ListenUDP("udp", addr)
    if err != nil {
        log.Fatalf("Failed to listen on UDP: %v", err)
    }
    defer conn.Close()

    log.Printf("Listening for UDP connections on %s", s.address)

    for {
        buf := make([]byte, 64*1024)
        n, remoteAddr, err := conn.ReadFromUDP(buf)
        if err != nil {
            log.Printf("Error reading UDP packet: %v", err)
            continue
        }

        go s.handleUDPPacket(conn, remoteAddr, buf[:n])
    }
}

func (s *Server) handleUDPPacket(conn *net.UDPConn, remoteAddr *net.UDPAddr, data []byte) {
    cipher, err := crypto.NewCipher([]byte(s.password))
    if err != nil {
        log.Printf("Failed to create cipher: %v", err)
        return
    }

    decrypted, err := cipher.Decrypt(data)
    if err != nil {
        log.Printf("Failed to decrypt UDP packet: %v", err)
        return
    }

    destAddr, err := socks.ParseAddress(decrypted)
    if err != nil {
        log.Printf("Failed to parse destination address: %v", err)
        return
    }

    udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
    if err != nil {
        log.Printf("Failed to resolve destination UDP address: %v", err)
        return
    }

    payload := decrypted[len(decrypted)-len(data)+3:]

    targetConn, err := net.DialUDP("udp", nil, udpAddr)
    if err != nil {
        log.Printf("Failed to connect to target: %v", err)
        return
    }
    defer targetConn.Close()

    _, err = targetConn.Write(payload)
    if err != nil {
        log.Printf("Failed to send data to target: %v", err)
        return
    }

    responseBuf := make([]byte, 64*1024)
    n, _, err := targetConn.ReadFromUDP(responseBuf)
    if err != nil {
        log.Printf("Failed to receive response from target: %v", err)
        return
    }

    responseAddr := make([]byte, 0, 300)
    responseAddr = append(responseAddr, 0x01) // IPv4
    responseAddr = append(responseAddr, udpAddr.IP.To4()...)
    responseAddr = binary.BigEndian.AppendUint16(responseAddr, uint16(udpAddr.Port))

    response := append(responseAddr, responseBuf[:n]...)
    encrypted, err := cipher.Encrypt(response)
    if err != nil {
        log.Printf("Failed to encrypt response: %v", err)
        return
    }

    _, err = conn.WriteToUDP(encrypted, remoteAddr)
    if err != nil {
        log.Printf("Failed to send response: %v", err)
        return
    }
}
