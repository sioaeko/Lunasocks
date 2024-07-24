package socks

import (
    "encoding/binary"
    "errors"
    "fmt"
    "net"
    "strconv"
)

var (
    ErrAddressTooShort = errors.New("address too short")
    ErrInvalidAddressType = errors.New("invalid address type")
    ErrInvalidIPv4Address = errors.New("invalid IPv4 address")
    ErrInvalidIPv6Address = errors.New("invalid IPv6 address")
    ErrInvalidPort = errors.New("invalid port")
)

func ParseAddress(b []byte) (string, error) {
    if len(b) < 2 {
        return "", ErrAddressTooShort
    }

    var host, port string
    switch b[0] {
    case 1:
        if len(b) < 7 {
            return "", ErrAddressTooShort
        }
        host = net.IP(b[1:5]).String()
    case 4:
        if len(b) < 19 {
            return "", ErrAddressTooShort
        }
        host = net.IP(b[1:17]).String()
    case 3:
        if len(b) < 2 {
            return "", ErrAddressTooShort
        }
        length := b[1]
        if len(b) < int(2+length+2) {
            return "", ErrAddressTooShort
        }
        host = string(b[2 : 2+length])
    default:
        return "", ErrInvalidAddressType
    }

    portNum := binary.BigEndian.Uint16(b[len(b)-2:])
    port = strconv.Itoa(int(portNum))

    return net.JoinHostPort(host, port)
}
