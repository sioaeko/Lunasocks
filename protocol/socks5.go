package protocol

import (
    "encoding/binary"
    "errors"
    "io"
    "net"
    "strconv"

    "lunasocks/internal/logging"
)

const (
    Version5       = 0x05
    CmdConnect     = 0x01
    AtypIPv4       = 0x01
    AtypDomainName = 0x03
    AtypIPv6       = 0x04
)

func HandleSocks5(conn net.Conn) (string, error) {
    if err := socks5Handshake(conn); err != nil {
        return "", err
    }

    cmd, addr, err := socks5GetRequest(conn)
    if err != nil {
        return "", err
    }

    if cmd != CmdConnect {
        return "", errors.New("only CONNECT command is supported")
    }

    if err := socks5SendReply(conn, 0x00); err != nil {
        return "", err
    }

    return addr, nil
}

func socks5Handshake(conn net.Conn) error {
    buf := make([]byte, 2)
    if _, err := io.ReadFull(conn, buf); err != nil {
        return err
    }

    if buf[0] != Version5 {
        return errors.New("invalid SOCKS version")
    }

    nmethods := int(buf[1])
    methods := make([]byte, nmethods)
    if _, err := io.ReadFull(conn, methods); err != nil {
        return err
    }

    _, err := conn.Write([]byte{Version5, 0x00})
    return err
}

func socks5GetRequest(conn net.Conn) (byte, string, error) {
    buf := make([]byte, 4)
    if _, err := io.ReadFull(conn, buf); err != nil {
        return 0, "", err
    }

    if buf[0] != Version5 {
        return 0, "", errors.New("invalid SOCKS version")
    }

    cmd := buf[1]
    atyp := buf[3]

    var addr string

    switch atyp {
    case AtypIPv4:
        ipv4 := make(net.IP, 4)
        if _, err := io.ReadFull(conn, ipv4); err != nil {
            return 0, "", err
        }
        addr = ipv4.String()
    case AtypDomainName:
        domainLen := make([]byte, 1)
        if _, err := io.ReadFull(conn, domainLen); err != nil {
            return 0, "", err
        }
        domain := make([]byte, domainLen[0])
        if _, err := io.ReadFull(conn, domain); err != nil {
            return 0, "", err
        }
        addr = string(domain)
    case AtypIPv6:
        ipv6 := make(net.IP, 16)
        if _, err := io.ReadFull(conn, ipv6); err != nil {
            return 0, "", err
        }
        addr = ipv6.String()
    default:
        return 0, "", errors.New("unsupported address type")
    }

    portBuf := make([]byte, 2)
    if _, err := io.ReadFull(conn, portBuf); err != nil {
        return 0, "", err
    }
    port := binary.BigEndian.Uint16(portBuf)

    return cmd, net.JoinHostPort(addr, strconv.Itoa(int(port))), nil
}

func socks5SendReply(conn net.Conn, rep byte) error {
    _, err := conn.Write([]byte{Version5, rep, 0x00, AtypIPv4, 0, 0, 0, 0, 0, 0})
    return err
}
