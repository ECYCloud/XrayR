package tuic

import (
	"net"
	"time"

	"github.com/sagernet/sing-box/option"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/ECYCloud/XrayR/api"
	"github.com/ECYCloud/XrayR/common/serverstatus"
)

func (s *TuicService) syncUsers(userInfo *[]api.UserInfo) {
	if userInfo == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	newUsers := make(map[string]userRecord, len(*userInfo))
	authUsers := make([]option.TUICUser, 0, len(*userInfo))
	newRateLimiters := make(map[string]*rate.Limiter)

	var nodeLimit uint64
	if s.nodeInfo != nil {
		nodeLimit = s.nodeInfo.SpeedLimit
	}

	for _, u := range *userInfo {
		// TUIC uses UUID as the primary authentication key
		key := u.UUID
		if key == "" {
			continue
		}

		rec := userRecord{
			UID:         u.UID,
			Email:       u.Email,
			DeviceLimit: u.DeviceLimit,
			SpeedLimit:  u.SpeedLimit,
		}

		limit := determineRate(nodeLimit, u.SpeedLimit)
		var limiter *rate.Limiter
		if limit > 0 {
			if old, ok := s.rateLimiters[key]; ok && old != nil {
				old.SetLimit(rate.Limit(limit))
				old.SetBurst(int(limit))
				limiter = old
			}
			if limiter == nil {
				limiter = rate.NewLimiter(rate.Limit(limit), int(limit))
			}
		}

		if _, ok := newUsers[key]; !ok {
			newUsers[key] = rec
		}
		if limiter != nil {
			newRateLimiters[key] = limiter
		}
		if _, ok := s.traffic[key]; !ok {
			s.traffic[key] = &userTraffic{}
		}

		// TUIC user with UUID and password (using Passwd as primary password)
		password := u.Passwd
		if password == "" {
			// Fallback: if panel did not return passwd, fall back to UUID,
			// and log a warning so the operator can fix the panel side.
			if s.logger != nil {
				preview := u.UUID
				if len(preview) > 8 {
					preview = preview[:8] + "..."
				}
				s.logger.Warnf("TUIC user UID=%d UUID=%s has empty passwd from panel; using UUID as password fallback", u.UID, preview)
			}
			password = u.UUID
		}
		authUsers = append(authUsers, option.TUICUser{
			Name:     u.UUID,
			UUID:     u.UUID,
			Password: password,
		})
	}

	s.users = newUsers
	s.authUsers = authUsers
	s.rateLimiters = newRateLimiters

	// Log user sync result (Info level so it shows up in default logs)
	if s.logger != nil {
		preview := ""
		if len(authUsers) > 0 {
			preview = authUsers[0].UUID
			if len(preview) > 8 {
				preview = preview[:8] + "..."
			}
		}
		s.logger.Infof("TUIC user sync complete: %d auth users configured (first UUID prefix: %s)", len(authUsers), preview)
	}

	for uuid := range s.onlineIPs {
		if _, ok := newUsers[uuid]; !ok {
			delete(s.onlineIPs, uuid)
		}
	}
}

func (s *TuicService) addTraffic(uuid string, up, down int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.traffic[uuid]
	if !ok {
		t = &userTraffic{}
		s.traffic[uuid] = t
	}
	t.Upload += up
	t.Download += down
}

func (s *TuicService) allowConnection(uuid, ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[uuid]
	if !ok {
		return false
	}

	host := ip
	if host != "" {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	if host == "" {
		host = "unknown"
	}

	ips, ok := s.onlineIPs[uuid]
	if !ok {
		ips = make(map[string]struct{})
		s.onlineIPs[uuid] = ips
	}
	if _, exists := ips[host]; !exists {
		if user.DeviceLimit > 0 && len(ips) >= user.DeviceLimit {
			s.logger.WithFields(log.Fields{
				"uid":         user.UID,
				"deviceLimit": user.DeviceLimit,
				"remote":      ip,
			}).Warn("TUIC user exceeded device limit")
			return false
		}
		ips[host] = struct{}{}
	}
	return true
}

func (s *TuicService) collectUsage() ([]api.UserTraffic, []api.OnlineUser) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var uts []api.UserTraffic
	for uuid, t := range s.traffic {
		user, ok := s.users[uuid]
		if !ok {
			continue
		}
		if t.Upload == 0 && t.Download == 0 {
			continue
		}
		uts = append(uts, api.UserTraffic{
			UID:      user.UID,
			Email:    user.Email,
			Upload:   t.Upload,
			Download: t.Download,
		})
		t.Upload = 0
		t.Download = 0
	}

	var online []api.OnlineUser
	for uuid, ipSet := range s.onlineIPs {
		user, ok := s.users[uuid]
		if !ok {
			continue
		}
		for ip := range ipSet {
			online = append(online, api.OnlineUser{UID: user.UID, IP: ip})
		}
	}

	return uts, online
}

func (s *TuicService) userMonitor() error {
	if time.Since(s.startAt) < time.Duration(s.config.UpdatePeriodic)*time.Second {
		return nil
	}

	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		s.logger.Print(err)
	} else {
		if err = s.apiClient.ReportNodeStatus(&api.NodeStatus{CPU: CPU, Mem: Mem, Disk: Disk, Uptime: Uptime}); err != nil {
			s.logger.Print(err)
		}
	}

	usersChanged := true
	newUserInfo, err := s.apiClient.GetUserList()
	if err != nil {
		if err.Error() == api.UserNotModified {
			usersChanged = false
		} else {
			s.logger.Print(err)
			return nil
		}
	}
	if usersChanged {
		s.syncUsers(newUserInfo)
	}

	// Check Rule
	if !s.config.DisableGetRule && s.rules != nil {
		if ruleList, err := s.apiClient.GetNodeRule(); err != nil {
			if err.Error() != api.RuleNotModified {
				s.logger.Printf("Get rule list filed: %s", err)
			}
		} else if len(*ruleList) > 0 {
			if err := s.rules.UpdateRule(s.tag, *ruleList); err != nil {
				s.logger.Print(err)
			}
		}
	}

	userTraffic, onlineUsers := s.collectUsage()
	if len(userTraffic) > 0 && !s.config.DisableUploadTraffic {
		if err = s.apiClient.ReportUserTraffic(&userTraffic); err != nil {
			s.logger.Print(err)
		}
	}
	if len(onlineUsers) > 0 {
		if err = s.apiClient.ReportNodeOnlineUsers(&onlineUsers); err != nil {
			s.logger.Print(err)
		}
	}

	// Report Illegal user
	if s.rules != nil {
		if detectResult, err := s.rules.GetDetectResult(s.tag); err != nil {
			s.logger.Print(err)
		} else if len(*detectResult) > 0 {
			if err = s.apiClient.ReportIllegal(detectResult); err != nil {
				s.logger.Print(err)
			} else {
				s.logger.Printf("Report %d illegal behaviors", len(*detectResult))
			}
		}
	}

	return nil
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
