package network

import (
    "context"
    "crypto/rand"
    "encoding/binary"
    "errors"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "os/signal"
    "sync"
    "syscall"
    "time"

    "github.com/go-redis/redis/v8"
    "golang.org/x/time/rate"

    "your_project/config"
    "your_project/crypto"
    "your_project/socks"
)

type Server struct {
    config         *config.Config
    cipher         *crypto.Cipher
    udpConn        *net.UDPConn
    udpMutex       sync.Mutex
    udpSessions    map[string]*UDPSession
    udpSessionMutex sync.Mutex
    redisClient    *redis.Client
    rateLimiter    *RateLimiter
    listener       net.Listener
    shutdown       chan struct{}
    wg             sync.WaitGroup
}

func NewServer(cfg *config.Config) *Server {
    return &Server{
        config:      cfg,
        udpSessions: make(map[string]*UDPSession),
        redisClient: redis.NewClient(&redis.Options{
            Addr: cfg.RedisAddr,
        }),
        rateLimiter: NewRateLimiter(rate.Limit(cfg.RateLimit), cfg.RateBurst),
        shutdown:    make(chan struct{}),
    }
}

func (s *Server) Start() error {
    var err error
    s.cipher, err = crypto.NewCipher(s.config.Password)
    if err != nil {
        return fmt.Errorf("failed to create cipher: %w", err)
    }

    go s.rotateKey()

    s.listener, err = net.Listen("tcp", s.config.Address)
    if err != nil {
        return fmt.Errorf("failed to listen on %s: %w", s.config.Address, err)
    }

    s.udpConn, err = net.ListenUDP("udp", s.listener.Addr().(*net.TCPAddr))
    if err != nil {
        s.listener.Close()
        return fmt.Errorf("failed to listen UDP on %s: %w", s.config.Address, err)
    }

    go s.handleUDP()

    log.Printf("Server listening on %s", s.config.Address)

    go s.acceptConnections()

    return s.waitForShutdown()
}

func (s *Server) acceptConnections() {
    for {
        conn, err := s.listener.Accept()
        if err != nil {
            select {
            case <-s.shutdown:
                return
            default:
                log.Printf("Failed to accept connection: %v", err)
                continue
            }
        }

        s.wg.Add(1)
        go func() {
            defer s.wg.Done()
            s.handleConnection(conn)
        }()
    }
}

func (s *Server) waitForShutdown() error {
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    <-sigCh
    log.Println("Shutdown signal received")

    close(s.shutdown)

    if err := s.listener.Close(); err != nil {
        log.Printf("Error closing listener: %v", err)
    }

    if err := s.udpConn.Close(); err != nil {
        log.Printf("Error closing UDP connection: %v", err)
    }

    s.wg.Wait()
    log.Println("All connections have been closed")

    return nil
}

func (s *Server) handleConnection(conn net.Conn) {
    defer conn.Close()

    if err := s.authenticate(conn); err != nil {
        log.Printf("Authentication failed: %v", err)
        return
    }

    if !s.rateLimiter.Allow() {
        log.Printf("Rate limit exceeded for %s", conn.RemoteAddr())
        return
    }

    request, err := socks.ReadRequest(conn)
    if err != nil {
        log.Printf("Failed to read SOCKS request: %v", err)
        return
    }

    switch request.Cmd {
    case socks.CmdConnect:
        s.handleTCP(conn, request)
    case socks.CmdUDP:
        s.handleUDPAssociate(conn, request)
    default:
        log.Printf("Unsupported SOCKS command: %v", request.Cmd)
    }
}

func (s *Server) handleTCP(clientConn net.Conn, request *socks.Request) {
    targetConn, err := net.DialTimeout("tcp", request.DestAddr.String(), s.config.Timeout)
    if err != nil {
        log.Printf("Failed to connect to %s: %v", request.DestAddr, err)
        socks.SendReply(clientConn, socks.RepHostUnreachable)
        return
    }
    defer targetConn.Close()

    socks.SendReply(clientConn, socks.RepSuccess)

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    go func() {
        _, err := io.Copy(targetConn, s.cipher.DecryptReader(clientConn))
        if err != nil && err != io.EOF {
            log.Printf("Error in client -> target: %v", err)
        }
        cancel()
    }()

    _, err = io.Copy(s.cipher.EncryptWriter(clientConn), targetConn)
    if err != nil && err != io.EOF {
        log.Printf("Error in target -> client: %v", err)
    }
}

func (s *Server) handleUDPAssociate(clientConn net.Conn, request *socks.Request) {
    clientAddr := clientConn.RemoteAddr().(*net.TCPAddr)
    relayAddr, err := net.ResolveUDPAddr("udp", s.config.Address)
    if err != nil {
        log.Printf("Failed to resolve UDP address: %v", err)
        socks.SendReply(clientConn, socks.RepServerFailure)
        return
    }

    socks.SendReply(clientConn, socks.RepSuccess, relayAddr)

    key := clientAddr.String()
    session := &UDPSession{
        ClientAddr: clientAddr,
        Cipher:     s.cipher,
    }

    s.udpSessionMutex.Lock()
    s.udpSessions[key] = session
    s.udpSessionMutex.Unlock()

    defer func() {
        s.udpSessionMutex.Lock()
        delete(s.udpSessions, key)
        s.udpSessionMutex.Unlock()
    }()

    // Keep the TCP connection alive
    io.Copy(io.Discard, clientConn)
}

func (s *Server) handleUDP() {
    buffer := make([]byte, 64*1024)
    for {
        n, remoteAddr, err := s.udpConn.ReadFromUDP(buffer)
        if err != nil {
            select {
            case <-s.shutdown:
                return
            default:
                log.Printf("Failed to read UDP packet: %v", err)
                continue
            }
        }

        go s.processUDPPacket(remoteAddr, buffer[:n])
    }
}

func (s *Server) processUDPPacket(remoteAddr *net.UDPAddr, data []byte) {
    key := remoteAddr.String()

    s.udpSessionMutex.Lock()
    session, ok := s.udpSessions[key]
    s.udpSessionMutex.Unlock()

    if !ok {
        log.Printf("No UDP session for %s", remoteAddr)
        return
    }

    decrypted, err := session.Cipher.Decrypt(data)
    if err != nil {
        log.Printf("Failed to decrypt UDP packet: %v", err)
        return
    }

    header, err := socks.ParseUDPHeader(decrypted)
    if err != nil {
        log.Printf("Failed to parse UDP header: %v", err)
        return
    }

    targetAddr, err := net.ResolveUDPAddr("udp", header.DestAddr.String())
    if err != nil {
        log.Printf("Failed to resolve target address: %v", err)
        return
    }

    targetConn, err := net.DialUDP("udp", nil, targetAddr)
    if err != nil {
        log.Printf("Failed to connect to target: %v", err)
        return
    }
    defer targetConn.Close()

    _, err = targetConn.Write(decrypted[header.HeaderLength:])
    if err != nil {
        log.Printf("Failed to write to target: %v", err)
        return
    }

    response := make([]byte, 64*1024)
    n, _, err := targetConn.ReadFromUDP(response)
    if err != nil {
        log.Printf("Failed to read from target: %v", err)
        return
    }

    udpResponse := socks.PackUDPHeader(header.DestAddr)
    udpResponse = append(udpResponse, response[:n]...)

    encrypted, err := session.Cipher.Encrypt(udpResponse)
    if err != nil {
        log.Printf("Failed to encrypt UDP response: %v", err)
        return
    }

    _, err = s.udpConn.WriteToUDP(encrypted, remoteAddr)
    if err != nil {
        log.Printf("Failed to write UDP response: %v", err)
    }
}

func (s *Server) authenticate(conn net.Conn) error {
    buf := make([]byte, 2)
    if _, err := io.ReadFull(conn, buf); err != nil {
        return fmt.Errorf("failed to read auth method: %v", err)
    }

    if buf[0] != 0x05 { // SOCKS5
        return errors.New("invalid SOCKS version")
    }

    methods := make([]byte, buf[1])
    if _, err := io.ReadFull(conn, methods); err != nil {
        return fmt.Errorf("failed to read auth methods: %v", err)
    }

    // For simplicity, we're using the NO AUTHENTICATION REQUIRED method
    conn.Write([]byte{0x05, 0x00})

    return nil
}

func (s *Server) rotateKey() {
    ticker := time.NewTicker(time.Duration(s.config.KeyRotationHours) * time.Hour)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            newKey := make([]byte, 32)
            if _, err := rand.Read(newKey); err != nil {
                log.Printf("Failed to generate new key: %v", err)
                continue
            }

            newCipher, err := crypto.NewCipher(string(newKey))
            if err != nil {
                log.Printf("Failed to create new cipher: %v", err)
                continue
            }

            s.cipher = newCipher
            log.Println("Encryption key rotated")
        case <-s.shutdown:
            return
        }
    }
}

type UDPSession struct {
    ClientAddr *net.TCPAddr
    Cipher     *crypto.Cipher
}

type RateLimiter struct {
    limiter *rate.Limiter
}

func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
    return &RateLimiter{
        limiter: rate.NewLimiter(r, b),
    }
}

func (rl *RateLimiter) Allow() bool {
    return rl.limiter.Allow()
}
