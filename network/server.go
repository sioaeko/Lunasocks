package network

import (
    "context"
    "crypto/rand"
    "encoding/binary"
    "encoding/json"
    "io"
    "log"
    "net"
    "net/http"
    "sync"
    "time"

    "github.com/go-redis/redis/v8"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "golang.org/x/time/rate"

    "your_project/crypto"
    "your_project/socks"
)

type UDPSession struct {
    LastSeen time.Time
    Nonce    uint32
}

type Server struct {
    addr           string
    password       string
    timeout        time.Duration
    cipher         *crypto.Cipher
    udpConn        *net.UDPConn
    udpMutex       sync.Mutex
    udpSessions    map[string]*UDPSession
    udpSessionMutex sync.Mutex
    redisClient    *redis.Client
    rateLimiter    *RateLimiter
}

type RateLimiter struct {
    limiters map[string]*rate.Limiter
    mu       sync.Mutex
    r        rate.Limit
    b        int
}

var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 64*1024)
    },
}

var (
    udpPacketsReceived = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "udp_packets_received_total",
        Help: "Total number of UDP packets received",
    })
    tcpConnectionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "tcp_connections_total",
        Help: "Total number of TCP connections",
    })
)

func init() {
    prometheus.MustRegister(udpPacketsReceived)
    prometheus.MustRegister(tcpConnectionsTotal)
}

func NewServer(addr, password string, timeout time.Duration, redisAddr string) *Server {
    return &Server{
        addr:        addr,
        password:    password,
        timeout:     timeout,
        udpSessions: make(map[string]*UDPSession),
        redisClient: redis.NewClient(&redis.Options{
            Addr: redisAddr,
        }),
        rateLimiter: NewRateLimiter(10, 30), // 10 requests per second, burst of 30
    }
}

func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
    return &RateLimiter{
        limiters: make(map[string]*rate.Limiter),
        r:        r,
        b:        b,
    }
}

func (l *RateLimiter) Allow(key string) bool {
    l.mu.Lock()
    limiter, exists := l.limiters[key]
    if !exists {
        limiter = rate.NewLimiter(l.r, l.b)
        l.limiters[key] = limiter
    }
    l.mu.Unlock()
    return limiter.Allow()
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
    go s.rotateEncryptionKey()
    go s.StartMetricsServer(":8080")

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
    tcpConnectionsTotal.Inc()

    if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
        log.Printf("Failed to set deadline: %v", err)
        return
    }

    clientAddr := conn.RemoteAddr().String()
    log.Printf("New TCP connection from %s", clientAddr)

    encReader := crypto.NewReader(conn, s.cipher)
    encWriter := crypto.NewWriter(conn, s.cipher)

    header := make([]byte, 3)
    if _, err := io.ReadFull(encReader, header); err != nil {
        log.Printf("Failed to read SOCKS5 header: %v", err)
        return
    }

    if header[0] != socks.Version5 {
        log.Printf("Unsupported SOCKS version: %d", header[0])
        return
    }

    dstAddr, err := socks.ReadAddr(encReader)
    if err != nil {
        log.Printf("Failed to read destination address: %v", err)
        return
    }

    log.Printf("TCP request from %s to %s", clientAddr, dstAddr)

    dstConn, err := net.DialTimeout("tcp", dstAddr.String(), s.timeout)
    if err != nil {
        log.Printf("Failed to connect to destination: %v", err)
        return
    }
    defer dstConn.Close()

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
    udpPacketsReceived.Inc()

    if !s.rateLimiter.Allow(remoteAddr.String()) {
        log.Printf("Rate limit exceeded for %s", remoteAddr)
        return
    }

    if len(data) < 8 {
        log.Printf("Invalid UDP packet: too short")
        return
    }

    nonce := binary.BigEndian.Uint32(data[:4])
    timestamp := binary.BigEndian.Uint32(data[4:8])
    
    sessionKey := remoteAddr.String()
    session, err := s.getSessionFromRedis(sessionKey)
    if err != nil {
        session = &UDPSession{Nonce: nonce}
        if err := s.setSessionToRedis(sessionKey, session); err != nil {
            log.Printf("Failed to set session to Redis: %v", err)
        }
    }

    if nonce <= session.Nonce {
        log.Printf("Possible replay attack detected from %s", remoteAddr)
        return
    }

    if time.Now().Unix()-int64(timestamp) > 300 {
        log.Printf("Stale packet detected from %s", remoteAddr)
        return
    }

    session.Nonce = nonce
    session.LastSeen = time.Now()
    if err := s.setSessionToRedis(sessionKey, session); err != nil {
        log.Printf("Failed to update session in Redis: %v", err)
    }

    decryptedData, err := s.cipher.Decrypt(data[8:])
    if err != nil {
        log.Printf("Error decrypting UDP data: %v", err)
        return
    }

    if len(decryptedData) < 3 {
        log.Printf("Invalid UDP packet")
        return
    }

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

    _, err = targetConn.Write(decryptedData[bodyStart:])
    if err != nil {
        log.Printf("Error sending data to target: %v", err)
        return
    }

    responseBuf := bufferPool.Get().([]byte)
    defer bufferPool.Put(responseBuf)

    targetConn.SetReadDeadline(time.Now().Add(s.timeout))
    n, _, err := targetConn.ReadFromUDP(responseBuf)
    if err != nil {
        log.Printf("Error receiving response from target: %v", err)
        return
    }

    response := make([]byte, n+bodyStart)
    copy(response[:bodyStart], decryptedData[:bodyStart])
    copy(response[bodyStart:], responseBuf[:n])

    newNonce := make([]byte, 4)
    _, err = rand.Read(newNonce)
    if err != nil {
        log.Printf("Error generating nonce: %v", err)
        return
    }
    binary.BigEndian.PutUint32(response[:4], binary.BigEndian.Uint32(newNonce))
    binary.BigEndian.PutUint32(response[4:8], uint32(time.Now().Unix()))

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
        now := time.Now()
        s.udpSessionMutex.Lock()
        for addr, session := range s.udpSessions {
            if now.Sub(session.LastSeen) > 10*time.Minute {
                delete(s.udpSessions, addr)
                s.redisClient.Del(context.Background(), addr)
            }
        }
        s.udpSessionMutex.Unlock()
    }
}

func (s *Server) rotateEncryptionKey() {
    ticker := time.NewTicker(24 * time.Hour) // 매일 키 갱신
    for range ticker.C {
        newKey := make([]byte, 32)
        if _, err := rand.Read(newKey); err != nil {
            log.Printf("Failed to generate new encryption key: %v", err)
            continue
        }

        newCipher, err := crypto.NewCipher(newKey)
        if err != nil {
            log.Printf("Failed to create new cipher: %v", err)
            continue
        }

        s.cipher = newCipher
        log.Println("Encryption key rotated")
    }
}

func (s *Server) StartMetricsServer(addr string) {
    http.Handle("/metrics", promhttp.Handler())
    log.Printf("Metrics server listening on %s", addr)
    if err := http.ListenAndServe(addr, nil); err != nil {
        log.Printf("Metrics server error: %v", err)
    }
}

func (s *Server) getSessionFromRedis(key string) (*UDPSession, error) {
    val, err := s.redisClient.Get(context.Background(), key).Result()
    if err != nil {
        return nil, err
    }
    var session UDPSession
    err = json.Unmarshal([]byte(val), &session)
    if err != nil {
        return nil, err
    }
    return &session, nil
}

func (s *Server) setSessionToRedis(key string, session *UDPSession) error {
    sessionJSON, err := json.Marshal(session)
    if err != nil {
        return err
    }
    return s.redisClient.Set(context.Background(), key, string(sessionJSON), 10*time.Minute).Err()
}
