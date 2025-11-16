package anytls

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

type connCounter struct {
	net.Conn
	svc     *AnyTLSService
	user    string
	blocked bool
	limiter *rate.Limiter
}

func (c *connCounter) Read(p []byte) (int, error) {
	if c.blocked {
		return 0, io.EOF
	}
	n, err := c.Conn.Read(p)
	if n > 0 && c.svc != nil {
		c.svc.addTraffic(c.user, int64(n), 0)
		if c.limiter != nil {
			_ = c.limiter.WaitN(context.Background(), n)
		}
	}
	return n, err
}

func (c *connCounter) Write(p []byte) (int, error) {
	if c.blocked {
		return 0, io.EOF
	}
	n, err := c.Conn.Write(p)
	if n > 0 && c.svc != nil {
		c.svc.addTraffic(c.user, 0, int64(n))
		if c.limiter != nil {
			_ = c.limiter.WaitN(context.Background(), n)
		}
	}
	return n, err
}

func (c *connCounter) Close() error {
	if c.svc != nil && c.user != "" {
		remote := ""
		if addr := c.Conn.RemoteAddr(); addr != nil {
			remote = addr.String()
		}
		host := remote
		if host != "" {
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}

		c.svc.mu.Lock()
		if ips, ok := c.svc.onlineIPs[c.user]; ok && host != "" {
			delete(ips, host)
			if len(ips) == 0 {
				delete(c.svc.onlineIPs, c.user)
			}
		}
		c.svc.mu.Unlock()
	}
	return c.Conn.Close()
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

	var (
		userRec userRecord
		ok      bool
	)
	t.svc.mu.RLock()
	userRec, ok = t.svc.users[m.User]
	t.svc.mu.RUnlock()

	dest := m.Domain
	if dest == "" && m.Destination.Addr.IsValid() {
		dest = m.Destination.Addr.String()
	}

	fields := log.Fields{
		"remote": remote,
	}
	if dest != "" {
		fields["dest"] = dest
	}
	if ok {
		fields["uid"] = userRec.UID
		if userRec.Email != "" {
			fields["email"] = userRec.Email
		}
	}

	// Match XrayR controller-style access log format:
	// from <ip:port> accepted tcp:<dest> [<tag>] email: <tag|email|uid>
	nodeTag := t.svc.tag
	if ok {
		emailStr := fmt.Sprintf("%s|%s|%d", nodeTag, userRec.Email, userRec.UID)
		t.svc.logger.Infof("from %s accepted tcp:%s [%s] email: %s",
			remote, dest, nodeTag, emailStr)
	} else {
		t.svc.logger.Infof("from %s accepted tcp:%s [%s]",
			remote, dest, nodeTag)
	}

	blocked := false

	// Audit check: if a rule hits, mark this connection as blocked and close it.
	if ok && dest != "" && t.svc.rules != nil {
		email := fmt.Sprintf("%s|%s|%d", t.svc.tag, userRec.Email, userRec.UID)
		if t.svc.rules.Detect(t.svc.tag, dest, email, remote) {
			t.svc.logger.WithFields(fields).Warn("AnyTLS audit rule hit, closing connection")
			blocked = true
		}
	}

	// Device limit check (only if not already blocked by audit).
	if !blocked && !t.svc.allowConnection(m.User, remote) {
		// allowConnection already logs a warning when device limit is exceeded.
		blocked = true
	}

	if blocked {
		_ = conn.Close()
		return &connCounter{Conn: conn, svc: t.svc, user: m.User, blocked: true}
	}

	return &connCounter{Conn: conn, svc: t.svc, user: m.User}
}

func (t *anyTLSTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
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

	var (
		userRec userRecord
		ok      bool
	)
	t.svc.mu.RLock()
	userRec, ok = t.svc.users[m.User]
	t.svc.mu.RUnlock()

	dest := m.Domain
	if dest == "" && m.Destination.Addr.IsValid() {
		dest = m.Destination.Addr.String()
	}

	fields := log.Fields{
		"remote": remote,
	}
	if dest != "" {
		fields["dest"] = dest
	}
	if ok {
		fields["uid"] = userRec.UID
		if userRec.Email != "" {
			fields["email"] = userRec.Email
		}
	}

	nodeTag := t.svc.tag
	if ok {
		emailStr := fmt.Sprintf("%s|%s|%d", nodeTag, userRec.Email, userRec.UID)
		t.svc.logger.Infof("from %s accepted udp:%s [%s] email: %s",
			remote, dest, nodeTag, emailStr)
	} else {
		t.svc.logger.Infof("from %s accepted udp:%s [%s]",
			remote, dest, nodeTag)
	}

	// Audit check for UDP. We cannot directly close the logical session here,
	// but we still record violations for panel-side auditing.
	if ok && dest != "" && t.svc.rules != nil {
		email := fmt.Sprintf("%s|%s|%d", t.svc.tag, userRec.Email, userRec.UID)
		if t.svc.rules.Detect(t.svc.tag, dest, email, remote) {
			t.svc.logger.WithFields(fields).Warn("AnyTLS audit rule hit on UDP")
		}
	}

	return conn
}
