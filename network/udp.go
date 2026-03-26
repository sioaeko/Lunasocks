package network

import (
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/sioaeko/Lunasocks/crypto"
	"github.com/sioaeko/Lunasocks/socks"
)

type UDPConn struct {
	conn     *net.UDPConn
	cipher   *crypto.AEADCipher
	timeout  time.Duration
	clientID string
}

func (s *Server) handleUDP() {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.ServerAddress)
	if err != nil {
		log.Printf("Failed to resolve UDP address: %v", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("Failed to listen on UDP: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("Listening for UDP connections on %s", s.cfg.ServerAddress)

	for {
		buf := make([]byte, 64*1024)
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error reading UDP packet: %v", err)
			continue
		}

		go s.handleUDPPacket(conn, remoteAddr, buf[:n])
	}
}

func (s *Server) handleUDPPacket(conn *net.UDPConn, remoteAddr *net.UDPAddr, data []byte) {
	cipher, err := crypto.NewCipher([]byte(s.cfg.Password))
	if err != nil {
		log.Printf("Failed to create cipher: %v", err)
		return
	}

	decrypted, err := cipher.Decrypt(data)
	if err != nil {
		log.Printf("Failed to decrypt UDP packet: %v", err)
		return
	}

	destAddr, err := socks.ParseAddress(decrypted)
	if err != nil {
		log.Printf("Failed to parse destination address: %v", err)
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		log.Printf("Failed to resolve destination UDP address: %v", err)
		return
	}

	// Calculate address header length to extract payload
	var addrLen int
	switch decrypted[0] {
	case 1: // IPv4
		addrLen = 1 + 4 + 2
	case 3: // Domain
		addrLen = 1 + 1 + int(decrypted[1]) + 2
	case 4: // IPv6
		addrLen = 1 + 16 + 2
	default:
		log.Printf("Unknown address type: %d", decrypted[0])
		return
	}

	if len(decrypted) < addrLen {
		log.Printf("Decrypted data too short for address")
		return
	}

	payload := decrypted[addrLen:]

	targetConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Printf("Failed to connect to target: %v", err)
		return
	}
	defer targetConn.Close()

	targetConn.SetDeadline(time.Now().Add(s.cfg.GetTimeout()))

	_, err = targetConn.Write(payload)
	if err != nil {
		log.Printf("Failed to send data to target: %v", err)
		return
	}

	responseBuf := make([]byte, 64*1024)
	n, _, err := targetConn.ReadFromUDP(responseBuf)
	if err != nil {
		log.Printf("Failed to receive response from target: %v", err)
		return
	}

	responseAddr := make([]byte, 0, 300)
	ip4 := udpAddr.IP.To4()
	if ip4 != nil {
		responseAddr = append(responseAddr, 0x01) // IPv4
		responseAddr = append(responseAddr, ip4...)
	} else {
		responseAddr = append(responseAddr, 0x04) // IPv6
		responseAddr = append(responseAddr, udpAddr.IP.To16()...)
	}
	responseAddr = binary.BigEndian.AppendUint16(responseAddr, uint16(udpAddr.Port))

	response := append(responseAddr, responseBuf[:n]...)
	encrypted, err := cipher.Encrypt(response)
	if err != nil {
		log.Printf("Failed to encrypt response: %v", err)
		return
	}

	_, err = conn.WriteToUDP(encrypted, remoteAddr)
	if err != nil {
		log.Printf("Failed to send response: %v", err)
		return
	}
}
