package hysteria2

import (
	"context"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"golang.org/x/time/rate"

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

	var limiter *rate.Limiter

	t.svc.mu.Lock()

	// If this connection has been marked as violating an audit rule, signal
	// the core to disconnect it by returning false.
	if t.svc.blockedIDs != nil {
		if blocked := t.svc.blockedIDs[id]; blocked {
			delete(t.svc.blockedIDs, id)
			if t.svc.logger != nil {
				t.svc.logger.WithField("id", id).Warn("Hysteria2 closing connection due to audit rule")
			}
			t.svc.mu.Unlock()
			return false
		}
	}

	if _, ok := t.svc.users[id]; !ok {
		t.svc.mu.Unlock()
		return true
	}
	counter, ok := t.svc.traffic[id]
	if !ok {
		counter = &userTraffic{}
		t.svc.traffic[id] = counter
	}
	counter.Upload += int64(tx)
	counter.Download += int64(rx)

	if t.svc.rateLimiters != nil {
		limiter = t.svc.rateLimiters[id]
	}

	t.svc.mu.Unlock()

	if limiter != nil {
		total := int(tx + rx)
		if total > 0 {
			_ = limiter.WaitN(context.Background(), total)
		}
	}

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
	newRateLimiters := make(map[string]*rate.Limiter)

	var nodeLimit uint64
	if h.nodeInfo != nil {
		nodeLimit = h.nodeInfo.SpeedLimit
	}

	for _, u := range *userInfo {
		// Primary auth key is UUID; fallback to Passwd for panels that
		// use the password field for Hysteria2 authentication.
		keys := []string{u.UUID, u.Passwd}
		rec := userRecord{
			UID:         u.UID,
			Email:       u.Email,
			DeviceLimit: u.DeviceLimit,
			SpeedLimit:  u.SpeedLimit,
		}

		limit := determineRate(nodeLimit, u.SpeedLimit)
		var limiter *rate.Limiter
		if limit > 0 {
			// Try to reuse an existing limiter if present.
			for _, k := range keys {
				if k == "" {
					continue
				}
				if old, ok := h.rateLimiters[k]; ok && old != nil {
					old.SetLimit(rate.Limit(limit))
					old.SetBurst(int(limit))
					limiter = old
					break
				}
			}
			if limiter == nil {
				limiter = rate.NewLimiter(rate.Limit(limit), int(limit))
			}
		}

		for _, k := range keys {
			if k == "" {
				continue
			}
			if _, ok := newUsers[k]; !ok {
				newUsers[k] = rec
			}
			if limiter != nil {
				newRateLimiters[k] = limiter
			}
			if _, ok := h.traffic[k]; !ok {
				h.traffic[k] = &userTraffic{}
			}
		}
	}

	h.users = newUsers
	h.rateLimiters = newRateLimiters

	// Clean online IP records for removed users
	for uuid := range h.onlineIPs {
		if _, ok := newUsers[uuid]; !ok {
			delete(h.onlineIPs, uuid)
		}
	}
}

func determineRate(nodeLimit, userLimit uint64) (limit uint64) {
	if nodeLimit == 0 || userLimit == 0 {
		if nodeLimit > userLimit {
			return nodeLimit
		} else if nodeLimit < userLimit {
			return userLimit
		}
		return 0
	}

	if nodeLimit > userLimit {
		return userLimit
	} else if nodeLimit < userLimit {
		return nodeLimit
	}
	return nodeLimit
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

	// Check Rule
	if !h.config.DisableGetRule && h.rules != nil {
		if ruleList, err := h.apiClient.GetNodeRule(); err != nil {
			if err.Error() != api.RuleNotModified {
				h.logger.Printf("Get rule list filed: %s", err)
			}
		} else if len(*ruleList) > 0 {
			if err := h.rules.UpdateRule(h.tag, *ruleList); err != nil {
				h.logger.Print(err)
			}
		}
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

	// Report Illegal user
	if h.rules != nil {
		if detectResult, err := h.rules.GetDetectResult(h.tag); err != nil {
			h.logger.Print(err)
		} else if len(*detectResult) > 0 {
			if err = h.apiClient.ReportIllegal(detectResult); err != nil {
				h.logger.Print(err)
			} else {
				h.logger.Printf("Report %d illegal behaviors", len(*detectResult))
			}
		}
	}

	return nil
}

// nodeMonitor watches for node-level configuration changes from the panel
// (including port, TLS/SNI and speed limits) and hot-reloads the underlying
// Hysteria2 server when needed. This avoids having to restart the whole
// XrayR process when you edit the node on the panel.
func (h *Hysteria2Service) nodeMonitor() error {
	// delay to start, keep in sync with userMonitor behaviour
	if time.Since(h.startAt) < time.Duration(h.config.UpdatePeriodic)*time.Second {
		return nil
	}

	nodeInfo, err := h.apiClient.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			return nil
		}
		h.logger.Print(err)
		return nil
	}

	if nodeInfo == nil || nodeInfo.NodeType != "Hysteria2" {
		if h.logger != nil {
			h.logger.Warnf("Hysteria2 node monitor: unexpected node info: %v", nodeInfo)
		}
		return nil
	}

	if err := h.reloadNode(nodeInfo); err != nil {
		h.logger.Printf("Hysteria2 node reload failed: %v", err)
	}

	return nil
}
