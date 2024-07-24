package network

import (
    "crypto/rand"
    "encoding/binary"
    "io"
    "log"
    "net"
    "sync"
    "time"

    "your_project/crypto"
    "your_project/socks"
)

type UDPSession struct {
    LastSeen time.Time
    Nonce    uint32
}

type Server struct {
    addr          string
    password      string
    timeout       time.Duration
    cipher        *crypto.Cipher
    udpConn       *net.UDPConn
    udpMutex      sync.Mutex
    udpSessions   map[string]*UDPSession
    udpSessionMutex sync.Mutex
}

var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 64*1024)
    },
}

func NewServer(addr, password string, timeout time.Duration) *Server {
    return &Server{
        addr:        addr,
        password:    password,
        timeout:     timeout,
        udpSessions: make(map[string]*UDPSession),
    }
}

func (s *Server) Start() error {
    cipher, err := crypto.NewCipher([]byte(s.password))
    if err != nil {
        return err
    }
    s.cipher = cipher

    tcpListener, err := net.Listen("tcp", s.addr)
    if err != nil {
        return err
    }
    defer tcpListener.Close()

    udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
    if err != nil {
        return err
    }

    s.udpConn, err = net.ListenUDP("udp", udpAddr)
    if err != nil {
        return err
    }
    defer s.udpConn.Close()

    log.Printf("Server listening on TCP and UDP %s", s.addr)

    go s.handleUDP()
    go s.cleanupUDPSessions()

    for {
        conn, err := tcpListener.Accept()
        if err != nil {
            log.Printf("Failed to accept connection: %v", err)
            continue
        }

        go s.handleTCPConnection(conn)
    }
}

func (s *Server) handleTCPConnection(conn net.Conn) {
    defer conn.Close()

    if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
        log.Printf("Failed to set deadline: %v", err)
        return
    }

    clientAddr := conn.RemoteAddr().String()
    log.Printf("New TCP connection from %s", clientAddr)

    encReader := crypto.NewReader(conn, s.cipher)
    encWriter := crypto.NewWriter(conn, s.cipher)

    // Read the SOCKS5 header
    header := make([]byte, 3)
    if _, err := io.ReadFull(encReader, header); err != nil {
        log.Printf("Failed to read SOCKS5 header: %v", err)
        return
    }

    if header[0] != socks.Version5 {
        log.Printf("Unsupported SOCKS version: %d", header[0])
        return
    }

    // Read the destination address
    dstAddr, err := socks.ReadAddr(encReader)
    if err != nil {
        log.Printf("Failed to read destination address: %v", err)
        return
    }

    log.Printf("TCP request from %s to %s", clientAddr, dstAddr)

    // Connect to the destination
    dstConn, err := net.DialTimeout("tcp", dstAddr.String(), s.timeout)
    if err != nil {
        log.Printf("Failed to connect to destination: %v", err)
        return
    }
    defer dstConn.Close()

    // Start proxying data
    go func() {
        if _, err := io.Copy(dstConn, encReader); err != nil {
            log.Printf("Failed to proxy data to destination: %v", err)
        }
    }()

    if _, err := io.Copy(encWriter, dstConn); err != nil {
        log.Printf("Failed to proxy data to client: %v", err)
    }
}

func (s *Server) handleUDP() {
    for {
        buf := bufferPool.Get().([]byte)
        n, remoteAddr, err := s.udpConn.ReadFromUDP(buf)
        if err != nil {
            log.Printf("Error reading UDP: %v", err)
            bufferPool.Put(buf)
            continue
        }

        go func() {
            s.handleUDPPacket(remoteAddr, buf[:n])
            bufferPool.Put(buf)
        }()
    }
}

func (s *Server) handleUDPPacket(remoteAddr *net.UDPAddr, data []byte) {
    if len(data) < 8 { // 4 bytes for nonce, 4 bytes for timestamp
        log.Printf("Invalid UDP packet: too short")
        return
    }

    nonce := binary.BigEndian.Uint32(data[:4])
    timestamp := binary.BigEndian.Uint32(data[4:8])
    
    s.udpSessionMutex.Lock()
    session, exists := s.udpSessions[remoteAddr.String()]
    if !exists {
        session = &UDPSession{Nonce: nonce}
        s.udpSessions[remoteAddr.String()] = session
    }
    s.udpSessionMutex.Unlock()

    // Check for replay attack
    if nonce <= session.Nonce {
        log.Printf("Possible replay attack detected from %s", remoteAddr)
        return
    }

    // Check for timestamp freshness (e.g., within last 5 minutes)
    if time.Now().Unix()-int64(timestamp) > 300 {
        log.Printf("Stale packet detected from %s", remoteAddr)
        return
    }

    session.Nonce = nonce
    session.LastSeen = time.Now()

    decryptedData, err := s.cipher.Decrypt(data[8:])
    if err != nil {
        log.Printf("Error decrypting UDP data: %v", err)
        return
    }

    if len(decryptedData) < 3 {
        log.Printf("Invalid UDP packet")
        return
    }

    // Parse the SOCKS5 UDP request
    addrType := decryptedData[0]
    var dstAddr string
    var dstPort uint16
    var bodyStart int

    switch addrType {
    case 1: // IPv4
        dstAddr = net.IP(decryptedData[1:5]).String()
        dstPort = binary.BigEndian.Uint16(decryptedData[5:7])
        bodyStart = 7
    case 3: // Domain name
        addrLen := int(decryptedData[1])
        dstAddr = string(decryptedData[2 : 2+addrLen])
        dstPort = binary.BigEndian.Uint16(decryptedData[2+addrLen : 4+addrLen])
        bodyStart = 4 + addrLen
    case 4: // IPv6
        dstAddr = net.IP(decryptedData[1:17]).String()
        dstPort = binary.BigEndian.Uint16(decryptedData[17:19])
        bodyStart = 19
    default:
        log.Printf("Unsupported address type: %d", addrType)
        return
    }

    targetAddr := net.JoinHostPort(dstAddr, string(dstPort))
    log.Printf("UDP request from %s to %s", remoteAddr, targetAddr)

    // Create a UDP connection to the target
    targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddr)
    if err != nil {
        log.Printf("Error resolving target address: %v", err)
        return
    }

    targetConn, err := net.DialUDP("udp", nil, targetUDPAddr)
    if err != nil {
        log.Printf("Error connecting to target: %v", err)
        return
    }
    defer targetConn.Close()

    // Send data to target
    _, err = targetConn.Write(decryptedData[bodyStart:])
    if err != nil {
        log.Printf("Error sending data to target: %v", err)
        return
    }

    // Receive response from target
    responseBuf := bufferPool.Get().([]byte)
    defer bufferPool.Put(responseBuf)

    targetConn.SetReadDeadline(time.Now().Add(s.timeout))
    n, _, err := targetConn.ReadFromUDP(responseBuf)
    if err != nil {
        log.Printf("Error receiving response from target: %v", err)
        return
    }

    // Construct SOCKS5 UDP response
    response := make([]byte, n+bodyStart)
    copy(response[:bodyStart], decryptedData[:bodyStart])
    copy(response[bodyStart:], responseBuf[:n])

    // Add nonce and timestamp
    newNonce := make([]byte, 4)
    _, err = rand.Read(newNonce)
    if err != nil {
        log.Printf("Error generating nonce: %v", err)
        return
    }
    binary.BigEndian.PutUint32(response[:4], binary.BigEndian.Uint32(newNonce))
    binary.BigEndian.PutUint32(response[4:8], uint32(time.Now().Unix()))

    // Encrypt and send response back to client
    encryptedResponse, err := s.cipher.Encrypt(response)
    if err != nil {
        log.Printf("Error encrypting response: %v", err)
        return
    }

    s.udpMutex.Lock()
    _, err = s.udpConn.WriteToUDP(encryptedResponse, remoteAddr)
    s.udpMutex.Unlock()
    if err != nil {
        log.Printf("Error sending response to client: %v", err)
    }
}

func (s *Server) cleanupUDPSessions() {
    ticker := time.NewTicker(5 * time.Minute)
    for range ticker.C {
        s.udpSessionMutex.Lock()
        for addr, session := range s.udpSessions {
            if time.Since(session.LastSeen) > 10*time.Minute {
                delete(s.udpSessions, addr)
            }
        }
        s.udpSessionMutex.Unlock()
    }
}
