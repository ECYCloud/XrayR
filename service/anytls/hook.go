package anytls

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

type connCounter struct {
	net.Conn
	svc  *AnyTLSService
	user string
}

func (c *connCounter) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.svc != nil {
		c.svc.addTraffic(c.user, int64(n), 0)
	}
	return n, err
}

func (c *connCounter) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 && c.svc != nil {
		c.svc.addTraffic(c.user, 0, int64(n))
	}
	return n, err
}

type anyTLSTracker struct {
	svc *AnyTLSService
}

var _ adapter.ConnectionTracker = (*anyTLSTracker)(nil)

func (t *anyTLSTracker) ModeList() []string { return nil }

func (t *anyTLSTracker) RoutedConnection(_ context.Context, conn net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	if t.svc == nil {
		return conn
	}
	if m.User == "" {
		return conn
	}
	remote := ""
	if m.Source.Addr.IsValid() {
		remote = m.Source.Addr.String()
	}
	if !t.svc.allowConnection(m.User, remote) {
		conn.Close()
		return conn
	}
	return &connCounter{Conn: conn, svc: t.svc, user: m.User}
}

func (t *anyTLSTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	return conn
}
