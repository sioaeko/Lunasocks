package network

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/sioaeko/Lunasocks/config"
	"github.com/sioaeko/Lunasocks/plugin"
)

type Server struct {
	cfg      *config.Config
	listener net.Listener
	plugins  []plugin.Plugin
	mu       sync.RWMutex
	running  bool
}

func NewServer(cfg *config.Config) *Server {
	return &Server{
		cfg: cfg,
	}
}

func (s *Server) EnableTLS(certFile, keyFile string) error {
	_, err := tls.LoadX509KeyPair(certFile, keyFile)
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
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		s.listener, err = tls.Listen("tcp", s.cfg.ServerAddress, tlsConfig)
	} else {
		s.listener, err = net.Listen("tcp", s.cfg.ServerAddress)
	}
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	log.Printf("Server started on %s (TLS: %v)", s.cfg.ServerAddress, s.cfg.UseTLS)
	defer func() {
		s.listener.Close()
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	// Start UDP handler
	go s.handleUDP()

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
		log.Printf("Authentication failed from %s: %v", conn.RemoteAddr(), err)
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

	if passLen > 1024 {
		return errors.New("password too long")
	}

	passBuf := make([]byte, passLen)
	if _, err := io.ReadFull(conn, passBuf); err != nil {
		return err
	}

	expected := []byte(s.cfg.Password)
	if subtle.ConstantTimeCompare(passBuf, expected) != 1 {
		return errors.New("invalid password")
	}

	return nil
}

func (s *Server) readCommand(conn net.Conn) ([]byte, error) {
	var cmdLen uint32
	if err := binary.Read(conn, binary.BigEndian, &cmdLen); err != nil {
		return nil, err
	}

	if cmdLen > 16*1024*1024 {
		return nil, errors.New("command too large")
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
	return cmd
}

func (s *Server) writeResponse(conn net.Conn, response []byte) error {
	if err := binary.Write(conn, binary.BigEndian, uint32(len(response))); err != nil {
		return err
	}

	_, err := conn.Write(response)
	return err
}

func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

func (s *Server) GetConfig() *config.Config {
	return s.cfg
}
