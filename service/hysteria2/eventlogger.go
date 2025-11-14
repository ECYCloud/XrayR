package hysteria2

import (
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/apernet/hysteria/core/v2/server"
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

func (l *hyEventLogger) Connect(addr net.Addr, id string, tx uint64) {
	l.logger().WithFields(log.Fields{
		"remote": addr.String(),
		"id":     id,
	}).Info("Hysteria2 client connected")
}

func (l *hyEventLogger) Disconnect(addr net.Addr, id string, err error) {
	if err != nil {
		l.logger().WithFields(log.Fields{
			"remote": addr.String(),
			"id":     id,
			"err":    err,
		}).Warn("Hysteria2 client disconnected with error")
	} else {
		l.logger().WithFields(log.Fields{
			"remote": addr.String(),
			"id":     id,
		}).Info("Hysteria2 client disconnected")
	}
}

func (l *hyEventLogger) TCPRequest(addr net.Addr, id, reqAddr string) {
	l.logger().WithFields(log.Fields{
		"remote":  addr.String(),
		"id":      id,
		"reqAddr": reqAddr,
	}).Debug("Hysteria2 TCP request")
}

func (l *hyEventLogger) TCPError(addr net.Addr, id, reqAddr string, err error) {
	l.logger().WithFields(log.Fields{
		"remote":  addr.String(),
		"id":      id,
		"reqAddr": reqAddr,
		"err":     err,
	}).Warn("Hysteria2 TCP error")
}

func (l *hyEventLogger) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {
	l.logger().WithFields(log.Fields{
		"remote":    addr.String(),
		"id":        id,
		"sessionID": sessionID,
		"reqAddr":   reqAddr,
	}).Debug("Hysteria2 UDP request")
}

func (l *hyEventLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {
	l.logger().WithFields(log.Fields{
		"remote":    addr.String(),
		"id":        id,
		"sessionID": sessionID,
		"err":       err,
	}).Warn("Hysteria2 UDP error")
}

