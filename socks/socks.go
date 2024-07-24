package socks

import (
    "encoding/binary"
    "errors"
    "net"
    "strconv"
)

var (
    ErrAddressTooShort    = errors.New("address too short")
    ErrInvalidAddressType = errors.New("invalid address type")
    ErrInvalidIPv4Address = errors.New("invalid IPv4 address")
    ErrInvalidIPv6Address = errors.New("invalid IPv6 address")
    ErrInvalidPort        = errors.New("invalid port")
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

func ParseUDPAddress(b []byte) (string, []byte, error) {
    if len(b) < 4 {
        return "", nil, ErrAddressTooShort
    }

    addrType := b[3]

    var addrLen int
    switch addrType {
    case 1:
        addrLen = 4
    case 4:
        addrLen = 16
    case 3:
        if len(b) < 5 {
            return "", nil, ErrAddressTooShort
        }
        addrLen = int(b[4]) + 1
    default:
        return "", nil, ErrInvalidAddressType
    }

    if len(b) < 4+addrLen+2 {
        return "", nil, ErrAddressTooShort
    }

    addr, err := ParseAddress(b[3:])
    if err != nil {
        return "", nil, err
    }

    return addr, b[4+addrLen:], nil
}
