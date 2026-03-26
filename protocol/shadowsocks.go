package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/sioaeko/Lunasocks/crypto"
	"github.com/sioaeko/Lunasocks/logging"
	"github.com/sioaeko/Lunasocks/pkg/pool"
)

type Shadowsocks struct {
	cipher  *crypto.AEADCipher
	timeout time.Duration
	pool    *pool.Pool
}

func NewShadowsocks(password, method string, timeout time.Duration) (*Shadowsocks, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key, err := crypto.DeriveKey(password, salt, 32)
	if err != nil {
		return nil, err
	}

	cipher, err := crypto.NewAEADCipher(key, method)
	if err != nil {
		return nil, err
	}

	return &Shadowsocks{
		cipher:  cipher,
		timeout: timeout,
		pool:    pool.New(4096),
	}, nil
}

func (s *Shadowsocks) HandleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	encryptedAddr, err := s.ReadEncrypted(clientConn)
	if err != nil {
		logging.Error("Failed to read encrypted address: %v", err)
		return
	}

	addr, err := s.cipher.Decrypt(encryptedAddr)
	if err != nil {
		logging.Error("Failed to decrypt address: %v", err)
		return
	}

	destConn, err := net.DialTimeout("tcp", string(addr), s.timeout)
	if err != nil {
		logging.Error("Failed to connect to destination: %v", err)
		return
	}
	defer destConn.Close()

	errChan := make(chan error, 2)
	go s.proxyData(clientConn, destConn, errChan)
	go s.proxyData(destConn, clientConn, errChan)

	err = <-errChan
	logging.Info("Connection closed: %v", err)
}

func (s *Shadowsocks) proxyData(src, dst net.Conn, errChan chan<- error) {
	buf := s.pool.Get()
	defer s.pool.Put(buf)

	for {
		src.SetReadDeadline(time.Now().Add(s.timeout))
		n, err := src.Read(buf)
		if err != nil {
			errChan <- err
			return
		}

		data, err := s.cipher.Encrypt(buf[:n])
		if err != nil {
			errChan <- err
			return
		}

		dst.SetWriteDeadline(time.Now().Add(s.timeout))
		_, err = dst.Write(data)
		if err != nil {
			errChan <- err
			return
		}
	}
}

func (s *Shadowsocks) ReadEncrypted(conn net.Conn) ([]byte, error) {
	sizeBuf := make([]byte, 2)
	_, err := io.ReadFull(conn, sizeBuf)
	if err != nil {
		return nil, err
	}

	size := binary.BigEndian.Uint16(sizeBuf)
	if size > 16384 {
		return nil, io.ErrUnexpectedEOF
	}

	buf := make([]byte, size)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
