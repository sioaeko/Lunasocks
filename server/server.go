package server

import (
    "errors"
    "fmt"
    "io"
    "log"
    "net"
    "time"

    "your_project/crypto"
    "your_project/socks"
)

var (
    ErrInvalidAddress = errors.New("invalid address")
    ErrConnectionClosed = errors.New("connection closed unexpectedly")
    ErrTimeout = errors.New("operation timed out")
)

func (s *Server) handleConnection(conn net.Conn) {
    defer conn.Close()

    cipher, err := crypto.NewCipher([]byte(s.password))
    if err != nil {
        log.Printf("Failed to create cipher: %v", err)
        return
    }

    buf := make([]byte, 256)
    n, err := conn.Read(buf)
    if err != nil {
        if errors.Is(err, io.EOF) {
            log.Printf("Connection closed by client")
        } else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
            log.Printf("Read timed out: %v", ErrTimeout)
        } else {
            log.Printf("Failed to read: %v", err)
        }
        return
    }

    decrypted, err := cipher.Decrypt(buf[:n])
    if err != nil {
        log.Printf("Failed to decrypt: %v", err)
        return
    }

    addr, err := socks.ParseAddress(decrypted)
    if err != nil {
        log.Printf("Failed to parse address: %v", ErrInvalidAddress)
        return
    }

    remote, err := net.DialTimeout("tcp", addr, 5*time.Second)
    if err != nil {
        if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
            log.Printf("Dial timed out: %v", ErrTimeout)
        } else {
            log.Printf("Failed to connect to %s: %v", addr, err)
        }
        return
    }
    defer remote.Close()

    go func() {
        if err := s.pipe(remote, conn, cipher.Decrypt); err != nil && !errors.Is(err, io.EOF) {
            log.Printf("Error in remote to local pipe: %v", err)
        }
    }()

    if err := s.pipe(conn, remote, cipher.Encrypt); err != nil && !errors.Is(err, io.EOF) {
        log.Printf("Error in local to remote pipe: %v", err)
    }
}

func (s *Server) pipe(dst io.Writer, src io.Reader, transform func([]byte) ([]byte, error)) error {
    buf := make([]byte, 1024)
    for {
        n, err := src.Read(buf)
        if n > 0 {
            data, err := transform(buf[:n])
            if err != nil {
                return fmt.Errorf("transform error: %w", err)
            }
            _, err = dst.Write(data)
            if err != nil {
                return fmt.Errorf("write error: %w", err)
            }
        }
        if err != nil {
            if err == io.EOF {
                return nil
            }
            return fmt.Errorf("read error: %w", err)
        }
    }
}
