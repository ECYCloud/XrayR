package hysteria2

import (
	"net"
)

// hyAuthenticator implements server.Authenticator and performs user lookup
// and local device limit enforcement based on SSPanel's UUID.
type hyAuthenticator struct {
	svc *Hysteria2Service
}

func (a *hyAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string) {
	if auth == "" {
		return false, ""
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}

	a.svc.mu.Lock()
	defer a.svc.mu.Unlock()

	user, ok := a.svc.users[auth]
	if !ok {
		return false, ""
	}

	ipSet, ok := a.svc.onlineIPs[auth]
	if !ok {
		ipSet = make(map[string]struct{})
		a.svc.onlineIPs[auth] = ipSet
	}

	if _, exists := ipSet[host]; !exists {
		// New device
		if user.DeviceLimit > 0 && len(ipSet) >= user.DeviceLimit {
			a.svc.logger.Warnf("Hysteria2 user %s (UID=%d) exceeded device limit %d from %s", user.Email, user.UID, user.DeviceLimit, host)
			return false, ""
		}
		ipSet[host] = struct{}{}
	}

	return true, auth
}

