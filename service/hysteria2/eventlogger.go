package hysteria2

import (
	"net"

	log "github.com/sirupsen/logrus"
)

// hyEventLogger implements server.EventLogger and prints useful
// diagnostics so that connection and handshake issues can be
// investigated from XrayR's log output.
type hyEventLogger struct {
	svc *Hysteria2Service
}

func (l *hyEventLogger) logger() *log.Entry {
	if l == nil || l.svc == nil || l.svc.logger == nil {
		return log.NewEntry(log.StandardLogger())
	}
	return l.svc.logger
}

// userFields resolves the given Hysteria2 connection ID (which is the
// auth string returned by the Authenticator) to a stable, non-sensitive
// user identity such as UID / email for logging purposes.
func (l *hyEventLogger) userFields(id string) log.Fields {
	fields := log.Fields{}
	if l == nil || l.svc == nil {
		return fields
	}

	l.svc.mu.RLock()
	defer l.svc.mu.RUnlock()

	if user, ok := l.svc.users[id]; ok {
		fields["uid"] = user.UID
		if user.Email != "" {
			fields["email"] = user.Email
		}
	}
	return fields
}

func (l *hyEventLogger) Connect(addr net.Addr, id string, tx uint64) {
	fields := log.Fields{
		"remote": addr.String(),
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	l.logger().WithFields(fields).Info("Hysteria2 client connected")
}

func (l *hyEventLogger) Disconnect(addr net.Addr, id string, err error) {
	fields := log.Fields{
		"remote": addr.String(),
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	if err != nil {
		fields["err"] = err
		l.logger().WithFields(fields).Warn("Hysteria2 client disconnected with error")
	} else {
		l.logger().WithFields(fields).Info("Hysteria2 client disconnected")
	}
}

func (l *hyEventLogger) TCPRequest(addr net.Addr, id, reqAddr string) {
	fields := log.Fields{
		"remote":  addr.String(),
		"reqAddr": reqAddr,
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	l.logger().WithFields(fields).Debug("Hysteria2 TCP request")
}

func (l *hyEventLogger) TCPError(addr net.Addr, id, reqAddr string, err error) {
	fields := log.Fields{
		"remote":  addr.String(),
		"reqAddr": reqAddr,
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	if err != nil {
		fields["err"] = err
		l.logger().WithFields(fields).Warn("Hysteria2 TCP error")
	} else {
		l.logger().WithFields(fields).Debug("Hysteria2 TCP error")
	}
}

func (l *hyEventLogger) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {
	fields := log.Fields{
		"remote":    addr.String(),
		"sessionID": sessionID,
		"reqAddr":   reqAddr,
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	l.logger().WithFields(fields).Debug("Hysteria2 UDP request")
}

func (l *hyEventLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {
	fields := log.Fields{
		"remote":    addr.String(),
		"sessionID": sessionID,
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	if err != nil {
		fields["err"] = err
		l.logger().WithFields(fields).Warn("Hysteria2 UDP error")
	} else {
		l.logger().WithFields(fields).Debug("Hysteria2 UDP error")
	}
}
