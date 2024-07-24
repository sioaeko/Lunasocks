package network

import (
    "net"

    "lunasocks/internal/protocol"
    "lunasocks/internal/logging"
)

func StartUDPServer(addr string, ss *protocol.Shadowsocks) error {
    conn, err := net.ListenPacket("udp", addr)
    if err != nil {
        return err
    }
    defer conn.Close()

    logging.Info("UDP Server listening on %s", addr)

    buf := make([]byte, 4096)
    for {
        n, remoteAddr, err := conn.ReadFrom(buf)
        if err != nil {
            logging.Error("Failed to read UDP packet: %v", err)
            continue
        }

        go handleUDPPacket(ss, conn, remoteAddr, buf[:n])
    }
}

func handleUDPPacket(ss *protocol.Shadowsocks, conn net.PacketConn, remoteAddr net.Addr, data []byte) {
    decrypted, err := ss.Cipher.Decrypt(data)
    if err != nil {
        logging.Error("Failed to decrypt UDP packet: %v", err)
        return
    }

    // UDP packet format: [target address][payload]
    targetAddr, payload, err := parseUDPPacket(decrypted)
    if err != nil {
        logging.Error("Failed to parse UDP packet: %v", err)
        return
    }

    targetConn, err := net.Dial("udp", targetAddr)
    if err != nil {
        logging.Error("Failed to connect to target: %v", err)
        return
    }
    defer targetConn.Close()

    _, err = targetConn.Write(payload)
    if err != nil {
        logging.Error("Failed to send payload to target: %v", err)
        return
    }

    response := make([]byte, 4096)
    n, err := targetConn.Read(response)
    if err != nil {
        logging.Error("Failed to read response from target: %v", err)
        return
    }

    encryptedResponse, err := ss.Cipher.Encrypt(response[:n])
    if err != nil {
        logging.Error("Failed to encrypt response: %v", err)
        return
    }

    _, err = conn.WriteTo(encryptedResponse, remoteAddr)
    if err != nil {
        logging.Error("Failed to send response to client: %v", err)
    }
}

func parseUDPPacket(packet []byte) (string, []byte, error) {
    // Implement UDP packet parsing logic here
    // Return target address and payload
    return "", nil, nil
}
