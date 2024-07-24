package client

import (
    "encoding/binary"
    "errors"
    "io"
    "log"
    "net"
    "time"

    "your_project/crypto"
    "your_project/socks"
)

type Client struct {
    serverAddr string
    localAddr  string
    password   string
    timeout    time.Duration
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
    listener, err := net.Listen("tcp", c.localAddr)
    if err != nil {
        return err
    }
    defer listener.Close()

    log.Printf("Client listening on %s", c.localAddr)

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Failed to accept connection: %v", err)
            continue
        }

        go c.handleConnection(conn)
    }
}

func (c *Client) handleConnection(conn net.Conn) {
    defer conn.Close()

    if err := c.handshake(conn); err != nil {
        log.Printf("Handshake failed: %v", err)
        return
    }

    serverConn, err := net.DialTimeout("tcp", c.serverAddr, c.timeout)
    if err != nil {
        log.Printf("Failed to connect to server: %v", err)
        return
    }
    defer serverConn.Close()

    cipher, err := crypto.NewCipher([]byte(c.password))
    if err != nil {
        log.Printf("Failed to create cipher: %v", err)
        return
    }

    go func() {
        if err := c.pipe(serverConn, conn, cipher.Decrypt); err != nil {
            log.Printf("Error in server to client pipe: %v", err)
        }
    }()

    if err := c.pipe(conn, serverConn, cipher.Encrypt); err != nil {
        log.Printf("Error in client to server pipe: %v", err)
    }
}

func (c *Client) handshake(conn net.Conn) error {
    buf := make([]byte, 257)
    if _, err := io.ReadFull(conn, buf[:2]); err != nil {
        return err
    }

    if buf[0] != 5 {
        return errors.New("invalid SOCKS version")
    }

    nMethods := int(buf[1])
    if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
        return err
    }

    _, err := conn.Write([]byte{5, 0})
    if err != nil {
        return err
    }

    if _, err := io.ReadFull(conn, buf[:4]); err != nil {
        return err
    }

    if buf[0] != 5 {
        return errors.New("invalid SOCKS version")
    }

    if buf[1] != 1 {
        return errors.New("only TCP connect is supported")
    }

    if buf[2] != 0 {
        return errors.New("reserved field must be 0")
    }

    var addr string
    switch buf[3] {
    case 1:
        if _, err := io.ReadFull(conn, buf[:4]); err != nil {
            return err
        }
        addr = net.IP(buf[:4]).String()
    case 3:
        if _, err := io.ReadFull(conn, buf[:1]); err != nil {
            return err
        }
        addrLen := int(buf[0])
        if _, err := io.ReadFull(conn, buf[:addrLen]); err != nil {
            return err
        }
        addr = string(buf[:addrLen])
    case 4:
        if _, err := io.ReadFull(conn, buf[:16]); err != nil {
            return err
        }
        addr = net.IP(buf[:16]).String()
    default:
        return errors.New("invalid address type")
    }

    if _, err := io.ReadFull(conn, buf[:2]); err != nil {
        return err
    }
    port := binary.BigEndian.Uint16(buf[:2])

    address := net.JoinHostPort(addr, string(port))
    reply := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
    _, err = conn.Write(reply)
    return err
}

func (c *Client) pipe(dst io.Writer, src io.Reader, transform func([]byte) ([]byte, error)) error {
    buf := make([]byte, 1024)
    for {
        n, err := src.Read(buf)
        if n > 0 {
            data, err := transform(buf[:n])
            if err != nil {
                return err
            }
            _, err = dst.Write(data)
            if err != nil {
                return err
            }
        }
        if err != nil {
            if err == io.EOF {
                return nil
            }
            return err
        }
    }
}
