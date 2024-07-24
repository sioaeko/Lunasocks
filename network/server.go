package network

import (
    "crypto/tls"
    "encoding/binary"
    "errors"
    "io"
    "log"
    "net"
    "time"
    "your_project/config"
    "your_project/plugin"
)

type Server struct {
    cfg      *config.Config
    listener net.Listener
    plugins  []plugin.Plugin
}

func NewServer(cfg *config.Config) *Server {
    return &Server{
        cfg: cfg,
    }
}

func (s *Server) EnableTLS(certFile, keyFile string) error {
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return err
    }
    s.cfg.UseTLS = true
    s.cfg.TLSCertFile = certFile
    s.cfg.TLSKeyFile = keyFile
    return nil
}

func (s *Server) AddPlugin(p plugin.Plugin) {
    s.plugins = append(s.plugins, p)
}

func (s *Server) Start() error {
    var err error
    if s.cfg.UseTLS {
        cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
        if err != nil {
            return err
        }
        tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
        s.listener, err = tls.Listen("tcp", s.cfg.ServerAddress, tlsConfig)
    } else {
        s.listener, err = net.Listen("tcp", s.cfg.ServerAddress)
    }
    if err != nil {
        return err
    }
    log.Printf("Server started on %s", s.cfg.ServerAddress)
    defer s.listener.Close()

    for {
        conn, err := s.listener.Accept()
        if err != nil {
            log.Printf("Error accepting connection: %v", err)
            continue
        }
        go s.handleConnection(conn)
    }
}

func (s *Server) handleConnection(conn net.Conn) {
    defer conn.Close()
    
    for _, p := range s.plugins {
        p.OnConnect(conn)
    }

    if err := s.authenticate(conn); err != nil {
        log.Printf("Authentication failed: %v", err)
        return
    }

    for {
        cmd, err := s.readCommand(conn)
        if err != nil {
            if err != io.EOF {
                log.Printf("Error reading command: %v", err)
            }
            return
        }

        response := s.processCommand(cmd)

        if err := s.writeResponse(conn, response); err != nil {
            log.Printf("Error writing response: %v", err)
            return
        }
    }
}

func (s *Server) authenticate(conn net.Conn) error {
    conn.SetDeadline(time.Now().Add(10 * time.Second))
    defer conn.SetDeadline(time.Time{})

    var passLen uint16
    if err := binary.Read(conn, binary.BigEndian, &passLen); err != nil {
        return err
    }

    passBuf := make([]byte, passLen)
    if _, err := io.ReadFull(conn, passBuf); err != nil {
        return err
    }

    if string(passBuf) != s.cfg.Password {
        return errors.New("invalid password")
    }

    return nil
}

func (s *Server) readCommand(conn net.Conn) ([]byte, error) {
    var cmdLen uint32
    if err := binary.Read(conn, binary.BigEndian, &cmdLen); err != nil {
        return nil, err
    }

    cmdBuf := make([]byte, cmdLen)
    if _, err := io.ReadFull(conn, cmdBuf); err != nil {
        return nil, err
    }

    for _, p := range s.plugins {
        cmdBuf = p.OnData(cmdBuf)
    }

    return cmdBuf, nil
}

func (s *Server) processCommand(cmd []byte) []byte {
    // 여기에 명령 처리 로직을 구현합니다.
    // 지금은 간단히 에코 서버처럼 동작하도록 하겠습니다.
    return cmd
}

func (s *Server) writeResponse(conn net.Conn, response []byte) error {
    if err := binary.Write(conn, binary.BigEndian, uint32(len(response))); err != nil {
        return err
    }

    _, err := conn.Write(response)
    return err
}
