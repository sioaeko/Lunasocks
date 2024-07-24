package server

import (
    "log"
    "net"
    "time"

    "your_project/crypto"
)

type Server struct {
    address  string
    password string
    timeout  time.Duration
}

func NewServer(addr, password string, timeout time.Duration) *Server {
    return &Server{
        address:  addr,
        password: password,
        timeout:  timeout,
    }
}

func (s *Server) Start() error {
    go s.handleUDP()

    listener, err := net.Listen("tcp", s.address)
    if err != nil {
        return err
    }
    defer listener.Close()

    log.Printf("Server listening on %s", s.address)

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Failed to accept connection: %v", err)
            continue
        }

        go s.handleConnection(conn)
    }
}

// handleConnection 함수는 이전과 동일하게 유지
