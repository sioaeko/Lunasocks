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
)

func ParseAddress(b []byte) (string, error) {
	if len(b) < 2 {
		return "", ErrAddressTooShort
	}

	var host string
	var portOffset int

	switch b[0] {
	case 1: // IPv4
		if len(b) < 7 {
			return "", ErrAddressTooShort
		}
		host = net.IP(b[1:5]).String()
		portOffset = 5
	case 4: // IPv6
		if len(b) < 19 {
			return "", ErrAddressTooShort
		}
		host = net.IP(b[1:17]).String()
		portOffset = 17
	case 3: // Domain
		length := int(b[1])
		if len(b) < 2+length+2 {
			return "", ErrAddressTooShort
		}
		host = string(b[2 : 2+length])
		portOffset = 2 + length
	default:
		return "", ErrInvalidAddressType
	}

	if len(b) < portOffset+2 {
		return "", ErrAddressTooShort
	}

	portNum := binary.BigEndian.Uint16(b[portOffset : portOffset+2])
	port := strconv.Itoa(int(portNum))

	return net.JoinHostPort(host, port), nil
}

func ParseUDPAddress(b []byte) (string, []byte, error) {
	if len(b) < 4 {
		return "", nil, ErrAddressTooShort
	}

	addrType := b[3]

	var addrLen int
	switch addrType {
	case 1: // IPv4
		addrLen = 4
	case 4: // IPv6
		addrLen = 16
	case 3: // Domain
		if len(b) < 5 {
			return "", nil, ErrAddressTooShort
		}
		addrLen = int(b[4]) + 1
	default:
		return "", nil, ErrInvalidAddressType
	}

	headerLen := 4 + addrLen + 2
	if len(b) < headerLen {
		return "", nil, ErrAddressTooShort
	}

	addr, err := ParseAddress(b[3:])
	if err != nil {
		return "", nil, err
	}

	return addr, b[headerLen:], nil
}
