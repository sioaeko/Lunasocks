package plugin

import (
	"log"
	"net"
)

type Plugin interface {
	Name() string
	OnConnect(conn net.Conn)
	OnData(data []byte) []byte
}

type LoggingPlugin struct{}

func (p *LoggingPlugin) Name() string {
	return "LoggingPlugin"
}

func (p *LoggingPlugin) OnConnect(conn net.Conn) {
	log.Printf("[plugin] New connection from: %s", conn.RemoteAddr())
}

func (p *LoggingPlugin) OnData(data []byte) []byte {
	log.Printf("[plugin] Data received: %d bytes", len(data))
	return data
}
