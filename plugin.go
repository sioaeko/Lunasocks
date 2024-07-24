package plugin

import "net"

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
    log.Printf("New connection from: %s", conn.RemoteAddr())
}

func (p *LoggingPlugin) OnData(data []byte) []byte {
    log.Printf("Data received: %d bytes", len(data))
    return data
}
