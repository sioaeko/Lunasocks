package network

import (
	"net"

	"github.com/sioaeko/Lunasocks/logging"
	"github.com/sioaeko/Lunasocks/protocol"
)

func StartTCPServer(addr string, ss *protocol.Shadowsocks) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	logging.Info("TCP Server listening on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logging.Error("Failed to accept connection: %v", err)
			continue
		}

		go ss.HandleConnection(conn)
	}
}
