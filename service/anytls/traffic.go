package anytls

import (
	"time"

	"github.com/sagernet/sing-box/option"
	log "github.com/sirupsen/logrus"

	"github.com/ECYCloud/XrayR/api"
	"github.com/ECYCloud/XrayR/common/serverstatus"
)

func (s *AnyTLSService) syncUsers(userInfo *[]api.UserInfo) {
	if userInfo == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	newUsers := make(map[string]userRecord, len(*userInfo))
	authUsers := make([]option.AnyTLSUser, 0, len(*userInfo)*2)

	for _, u := range *userInfo {
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
			if _, ok := s.traffic[k]; !ok {
				s.traffic[k] = &userTraffic{}
			}
		}

		if u.UUID != "" {
			authUsers = append(authUsers, option.AnyTLSUser{
				Name:     u.UUID,
				Password: u.UUID,
			})
		}
		if u.Passwd != "" && u.Passwd != u.UUID {
			authUsers = append(authUsers, option.AnyTLSUser{
				Name:     u.Passwd,
				Password: u.Passwd,
			})
		}
	}

	s.users = newUsers
	s.authUsers = authUsers

	for uuid := range s.onlineIPs {
		if _, ok := newUsers[uuid]; !ok {
			delete(s.onlineIPs, uuid)
		}
	}
}

func (s *AnyTLSService) addTraffic(uuid string, up, down int64) {
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

func (s *AnyTLSService) allowConnection(uuid, ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[uuid]
	if !ok {
		return false
	}
	if ip == "" {
		ip = "unknown"
	}

	ips, ok := s.onlineIPs[uuid]
	if !ok {
		ips = make(map[string]struct{})
		s.onlineIPs[uuid] = ips
	}
	if _, exists := ips[ip]; !exists {
		if user.DeviceLimit > 0 && len(ips) >= user.DeviceLimit {
			s.logger.WithFields(log.Fields{
				"uid":         user.UID,
				"email":       user.Email,
				"deviceLimit": user.DeviceLimit,
				"remote":      ip,
			}).Warn("AnyTLS user exceeded device limit")
			return false
		}
		ips[ip] = struct{}{}
	}
	return true
}

func (s *AnyTLSService) collectUsage() ([]api.UserTraffic, []api.OnlineUser) {
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
		delete(s.onlineIPs, uuid)
	}

	return uts, online
}

func (s *AnyTLSService) userMonitor() error {
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

	return nil
}
