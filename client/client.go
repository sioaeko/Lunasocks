package client

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"

	"github.com/sioaeko/Lunasocks/crypto"
	"github.com/sioaeko/Lunasocks/protocol"
	"github.com/sioaeko/Lunasocks/socks"
)

type Client struct {
	serverAddr string
	localAddr  string
	password   string
	timeout    time.Duration
	udpAddr    *net.UDPAddr
	udpConn    *net.UDPConn
	cipher     *crypto.AEADCipher
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
	var err error
	c.cipher, err = crypto.NewCipher([]byte(c.password))
	if err != nil {
		return err
	}

	tcpListener, err := net.Listen("tcp", c.localAddr)
	if err != nil {
		return err
	}
	defer tcpListener.Close()

	c.udpAddr, err = net.ResolveUDPAddr("udp", c.localAddr)
	if err != nil {
		return err
	}

	c.udpConn, err = net.ListenUDP("udp", c.udpAddr)
	if err != nil {
		return err
	}
	defer c.udpConn.Close()

	log.Printf("Client listening on TCP %s and UDP %s", c.localAddr, c.udpAddr)

	go c.handleUDP()

	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go c.handleTCPConnection(conn)
	}
}

func (c *Client) handleTCPConnection(conn net.Conn) {
	defer conn.Close()

	// Perform local SOCKS5 handshake
	destAddr, err := protocol.HandleSocks5(conn)
	if err != nil {
		log.Printf("SOCKS5 handshake failed: %v", err)
		return
	}

	// Connect to remote server
	serverConn, err := net.DialTimeout("tcp", c.serverAddr, c.timeout)
	if err != nil {
		log.Printf("Failed to connect to server: %v", err)
		return
	}
	defer serverConn.Close()

	// Send password
	passBytes := []byte(c.password)
	if err := binary.Write(serverConn, binary.BigEndian, uint16(len(passBytes))); err != nil {
		log.Printf("Failed to send password: %v", err)
		return
	}
	if _, err := serverConn.Write(passBytes); err != nil {
		log.Printf("Failed to send password: %v", err)
		return
	}

	// Encrypt and send destination address
	encAddr, err := c.cipher.Encrypt([]byte(destAddr))
	if err != nil {
		log.Printf("Failed to encrypt address: %v", err)
		return
	}
	if err := binary.Write(serverConn, binary.BigEndian, uint16(len(encAddr))); err != nil {
		log.Printf("Failed to send address length: %v", err)
		return
	}
	if _, err := serverConn.Write(encAddr); err != nil {
		log.Printf("Failed to send address: %v", err)
		return
	}

	// Bidirectional proxy
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(serverConn, conn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(conn, serverConn)
		errChan <- err
	}()

	<-errChan
}

func (c *Client) handleUDP() {
	buf := make([]byte, 64*1024)
	for {
		n, remoteAddr, err := c.udpConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error reading UDP: %v", err)
			continue
		}

		go c.handleUDPPacket(remoteAddr, buf[:n])
	}
}

func (c *Client) handleUDPPacket(remoteAddr *net.UDPAddr, data []byte) {
	if len(data) < 4 {
		log.Printf("Invalid UDP packet: too short")
		return
	}

	// SOCKS5 UDP request format:
	// +----+------+------+----------+----------+----------+
	// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	// +----+------+------+----------+----------+----------+
	// | 2  |  1   |  1   | Variable |    2     | Variable |
	// +----+------+------+----------+----------+----------+

	if data[2] != 0 {
		log.Printf("Fragmented UDP packets not supported")
		return
	}

	addr, payload, err := socks.ParseUDPAddress(data)
	if err != nil {
		log.Printf("Failed to parse UDP address: %v", err)
		return
	}
	_ = addr

	// Encrypt and send to server
	encryptedData, err := c.cipher.Encrypt(payload)
	if err != nil {
		log.Printf("Error encrypting UDP data: %v", err)
		return
	}

	serverUDPAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
	if err != nil {
		log.Printf("Error resolving server address: %v", err)
		return
	}

	_, err = c.udpConn.WriteToUDP(encryptedData, serverUDPAddr)
	if err != nil {
		log.Printf("Error sending UDP data to server: %v", err)
		return
	}

	// Wait for response
	responseBuf := make([]byte, 64*1024)
	c.udpConn.SetReadDeadline(time.Now().Add(c.timeout))
	n, _, err := c.udpConn.ReadFromUDP(responseBuf)
	if err != nil {
		log.Printf("Error receiving UDP response: %v", err)
		return
	}

	// Decrypt response
	decryptedData, err := c.cipher.Decrypt(responseBuf[:n])
	if err != nil {
		log.Printf("Error decrypting UDP response: %v", err)
		return
	}

	// Parse destination for SOCKS5 header reconstruction
	dstAddr, dstPayload, err := socks.ParseUDPAddress(data)
	if err != nil {
		log.Printf("Error re-parsing address: %v", err)
		return
	}
	_ = dstAddr
	headerLen := len(data) - len(dstPayload)

	// Construct SOCKS5 UDP response
	response := make([]byte, headerLen+len(decryptedData))
	copy(response[:headerLen], data[:headerLen])
	copy(response[headerLen:], decryptedData)

	_, err = c.udpConn.WriteToUDP(response, remoteAddr)
	if err != nil {
		log.Printf("Error sending UDP response to client: %v", err)
	}
}
