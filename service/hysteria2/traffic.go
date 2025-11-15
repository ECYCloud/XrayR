package hysteria2

import (
	"time"

	"github.com/apernet/hysteria/core/v2/server"

	"github.com/ECYCloud/XrayR/api"
	"github.com/ECYCloud/XrayR/common/serverstatus"
)

// hyTrafficLogger implements server.TrafficLogger and records user traffic
// into the service's in-memory counters.
type hyTrafficLogger struct {
	svc *Hysteria2Service
}

func (t *hyTrafficLogger) LogTraffic(id string, tx, rx uint64) bool {
	if id == "" {
		return true
	}

	t.svc.mu.Lock()
	defer t.svc.mu.Unlock()

	if _, ok := t.svc.users[id]; !ok {
		return true
	}
	counter, ok := t.svc.traffic[id]
	if !ok {
		counter = &userTraffic{}
		t.svc.traffic[id] = counter
	}
	counter.Upload += int64(tx)
	counter.Download += int64(rx)
	return true
}

func (t *hyTrafficLogger) LogOnlineState(id string, online bool) {
	// Online state is tracked via Authenticator using the onlineIPs map.
}

func (t *hyTrafficLogger) TraceStream(stream server.HyStream, stats *server.StreamStats) {}

func (t *hyTrafficLogger) UntraceStream(stream server.HyStream) {}

// syncUsers syncs the internal user map from the panel provided user list.
func (h *Hysteria2Service) syncUsers(userInfo *[]api.UserInfo) {
	if userInfo == nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	newUsers := make(map[string]userRecord, len(*userInfo))
	for _, u := range *userInfo {
		// Primary auth key is UUID; fallback to Passwd for panels that
		// use the password field for Hysteria2 authentication.
		keys := []string{u.UUID, u.Passwd}
		rec := userRecord{
			UID:         u.UID,
			Email:       u.Email,
			DeviceLimit: u.DeviceLimit,
		}
		for _, k := range keys {
			if k == "" {
				continue
			}
			if _, ok := newUsers[k]; !ok {
				newUsers[k] = rec
			}
			if _, ok := h.traffic[k]; !ok {
				h.traffic[k] = &userTraffic{}
			}
		}
	}

	h.users = newUsers

	// Clean online IP records for removed users
	for uuid := range h.onlineIPs {
		if _, ok := newUsers[uuid]; !ok {
			delete(h.onlineIPs, uuid)
		}
	}
}

// collectUsage builds traffic and online user reports and resets the
// corresponding in-memory counters.
func (h *Hysteria2Service) collectUsage() ([]api.UserTraffic, []api.OnlineUser) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var userTraffic []api.UserTraffic
	for uuid, t := range h.traffic {
		user, ok := h.users[uuid]
		if !ok {
			continue
		}
		if t.Upload == 0 && t.Download == 0 {
			continue
		}
		userTraffic = append(userTraffic, api.UserTraffic{
			UID:      user.UID,
			Email:    user.Email,
			Upload:   t.Upload,
			Download: t.Download,
		})
		// reset counters after reporting
		t.Upload = 0
		t.Download = 0
	}

	var onlineUsers []api.OnlineUser
	for uuid, ipSet := range h.onlineIPs {
		user, ok := h.users[uuid]
		if !ok {
			continue
		}
		for ip := range ipSet {
			onlineUsers = append(onlineUsers, api.OnlineUser{UID: user.UID, IP: ip})
		}
		// reset for next round
		delete(h.onlineIPs, uuid)
	}

	return userTraffic, onlineUsers
}

// userMonitor is the periodic task used by Hysteria2Service to
// - report node status
// - refresh user list
// - report user traffic and online users.
func (h *Hysteria2Service) userMonitor() error {
	// delay to start
	if time.Since(h.startAt) < time.Duration(h.config.UpdatePeriodic)*time.Second {
		return nil
	}

	// Get server status
	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		h.logger.Print(err)
	} else {
		if err = h.apiClient.ReportNodeStatus(&api.NodeStatus{CPU: CPU, Mem: Mem, Disk: Disk, Uptime: Uptime}); err != nil {
			h.logger.Print(err)
		}
	}

	// Update User
	usersChanged := true
	newUserInfo, err := h.apiClient.GetUserList()
	if err != nil {
		if err.Error() == api.UserNotModified {
			usersChanged = false
		} else {
			h.logger.Print(err)
			return nil
		}
	}
	if usersChanged {
		h.syncUsers(newUserInfo)
	}

	// Collect traffic & online users
	userTraffic, onlineUsers := h.collectUsage()
	if len(userTraffic) > 0 {
		var reportErr error
		if !h.config.DisableUploadTraffic {
			reportErr = h.apiClient.ReportUserTraffic(&userTraffic)
		}
		if reportErr != nil {
			h.logger.Print(reportErr)
		}
	}
	if len(onlineUsers) > 0 {
		if err = h.apiClient.ReportNodeOnlineUsers(&onlineUsers); err != nil {
			h.logger.Print(err)
		}
	}

	return nil
}
