package client

import (
    "encoding/binary"
    "errors"
    "io"
    "log"
    "net"
    "sync"
    "time"

    "your_project/crypto"
    "your_project/socks"
)

type Client struct {
    serverAddr string
    localAddr  string
    password   string
    timeout    time.Duration
    udpAddr    *net.UDPAddr
    udpConn    *net.UDPConn
    cipher     *crypto.Cipher
}

func NewClient(serverAddr, localAddr, password string, timeout time.Duration) *Client {
    return &Client{
        serverAddr: serverAddr,
        localAddr:  localAddr,
        password:   password,
        timeout:    timeout,
    }
}

func (c *Client) Start() error {
    tcpListener, err := net.Listen("tcp", c.localAddr)
    if err != nil {
        return err
    }
    defer tcpListener.Close()

    c.udpAddr, err = net.ResolveUDPAddr("udp", c.localAddr)
    if err != nil {
        return err
    }

    c.udpConn, err = net.ListenUDP("udp", c.udpAddr)
    if err != nil {
        return err
    }
    defer c.udpConn.Close()

    c.cipher, err = crypto.NewCipher([]byte(c.password))
    if err != nil {
        return err
    }

    log.Printf("Client listening on TCP %s and UDP %s", c.localAddr, c.udpAddr)

    go c.handleUDP()

    for {
        conn, err := tcpListener.Accept()
        if err != nil {
            log.Printf("Failed to accept connection: %v", err)
            continue
        }

        go c.handleTCPConnection(conn)
    }
}

func (c *Client) handleUDP() {
    buf := make([]byte, 64*1024)
    for {
        n, remoteAddr, err := c.udpConn.ReadFromUDP(buf)
        if err != nil {
            log.Printf("Error reading UDP: %v", err)
            continue
        }

        go c.handleUDPPacket(remoteAddr, buf[:n])
    }
}

func (c *Client) handleUDPPacket(remoteAddr *net.UDPAddr, data []byte) {
    if len(data) < 3 {
        log.Printf("Invalid UDP packet")
        return
    }

    // SOCKS5 UDP request
    // +----+------+------+----------+----------+----------+
    // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    // +----+------+------+----------+----------+----------+
    // | 2  |  1   |  1   | Variable |    2     | Variable |
    // +----+------+------+----------+----------+----------+

    if data[2] != 0 {
        log.Printf("Fragmented UDP packets not supported")
        return
    }

    // Extract target address
    addrType := data[3]
    var dstAddr string
    var dstPort uint16
    var bodyStart int

    switch addrType {
    case 1: // IPv4
        dstAddr = net.IP(data[4:8]).String()
        dstPort = binary.BigEndian.Uint16(data[8:10])
        bodyStart = 10
    case 3: // Domain name
        addrLen := int(data[4])
        dstAddr = string(data[5 : 5+addrLen])
        dstPort = binary.BigEndian.Uint16(data[5+addrLen : 7+addrLen])
        bodyStart = 7 + addrLen
    case 4: // IPv6
        dstAddr = net.IP(data[4:20]).String()
        dstPort = binary.BigEndian.Uint16(data[20:22])
        bodyStart = 22
    default:
        log.Printf("Unsupported address type: %d", addrType)
        return
    }

    targetAddr := net.JoinHostPort(dstAddr, string(dstPort))

    // Encrypt and send to server
    encryptedData, err := c.cipher.Encrypt(data[bodyStart:])
    if err != nil {
        log.Printf("Error encrypting UDP data: %v", err)
        return
    }

    serverUDPAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
    if err != nil {
        log.Printf("Error resolving server address: %v", err)
        return
    }

    _, err = c.udpConn.WriteToUDP(encryptedData, serverUDPAddr)
    if err != nil {
        log.Printf("Error sending UDP data to server: %v", err)
        return
    }

    // Wait for response
    responseBuf := make([]byte, 64*1024)
    c.udpConn.SetReadDeadline(time.Now().Add(c.timeout))
    n, _, err := c.udpConn.ReadFromUDP(responseBuf)
    if err != nil {
        log.Printf("Error receiving UDP response: %v", err)
        return
    }

    // Decrypt response
    decryptedData, err := c.cipher.Decrypt(responseBuf[:n])
    if err != nil {
        log.Printf("Error decrypting UDP response: %v", err)
        return
    }

    // Construct SOCKS5 UDP response
    response := make([]byte, len(decryptedData)+bodyStart)
    copy(response[:bodyStart], data[:bodyStart])
    copy(response[bodyStart:], decryptedData)

    // Send response back to client
    _, err = c.udpConn.WriteToUDP(response, remoteAddr)
    if err != nil {
        log.Printf("Error sending UDP response to client: %v", err)
    }
}
