package hysteria2

import (
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"

	"github.com/ECYCloud/XrayR/api"
	"github.com/ECYCloud/XrayR/common/rule"
	"github.com/ECYCloud/XrayR/service"
	"github.com/ECYCloud/XrayR/service/controller"
)

var _ service.Service = (*Hysteria2Service)(nil)

// New creates a new Hysteria2 service bound to a SSPanel node.
func New(apiClient api.API, cfg *controller.Config) *Hysteria2Service {
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": apiClient.Describe().APIHost,
		"Type": apiClient.Describe().NodeType,
		"ID":   apiClient.Describe().NodeID,
	})
	return &Hysteria2Service{
		apiClient:  apiClient,
		config:     cfg,
		logger:     logger,
		rules:      rule.New(),
		users:      make(map[string]userRecord),
		traffic:    make(map[string]*userTraffic),
		overLimit:  make(map[string]bool),
		onlineIPs:  make(map[string]map[string]struct{}),
		blockedIDs: make(map[string]bool),
	}
}

// Start implements service.Service.Start.
func (h *Hysteria2Service) Start() error {
	h.clientInfo = h.apiClient.Describe()

	// Fetch node info.
	nodeInfo, err := h.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	if nodeInfo.NodeType != "Hysteria2" {
		return fmt.Errorf("Hysteria2Service can only be used with Hysteria2 node, got %s", nodeInfo.NodeType)
	}
	if nodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	if nodeInfo.Hysteria2Config == nil {
		return errors.New("Hysteria2Config is nil in node info")
	}
	if h.config == nil || h.config.CertConfig == nil {
		return errors.New("CertConfig is required for Hysteria2")
	}

	h.nodeInfo = nodeInfo
	// Tag must be unique per logical node, even if multiple nodes share
	// the same listen IP and port. Include NodeID to keep limiter and
	// audit rule state isolated.
	h.tag = fmt.Sprintf("%s_%s_%d_%d", h.nodeInfo.NodeType, h.config.ListenIP, h.nodeInfo.Port, h.nodeInfo.NodeID)
	h.startAt = time.Now()

	// Initial user list.
	userInfo, err := h.apiClient.GetUserList()
	if err != nil {
		return err
	}
	h.syncUsers(userInfo)

	// Initial rule list.
	if !h.config.DisableGetRule && h.rules != nil {
		if ruleList, err := h.apiClient.GetNodeRule(); err != nil {
			h.logger.Printf("Get rule list filed: %s", err)
		} else if len(*ruleList) > 0 {
			if err := h.rules.UpdateRule(h.tag, *ruleList); err != nil {
				h.logger.Print(err)
			}
		}
	}

	// Build Hysteria2 server.
	cfg, err := h.buildServerConfig()
	if err != nil {
		return err
	}
	srv, err := server.NewServer(cfg)
	if err != nil {
		return err
	}
	h.server = srv

	go func() {
		if err := h.server.Serve(); err != nil {
			h.logger.Errorf("Hysteria2 Serve error: %v", err)
		}
	}()

	// Periodic tasks: user/traffic monitor plus optional cert monitor.
	interval := time.Duration(h.config.UpdatePeriodic) * time.Second
	h.tasks = []periodicTask{
		{
			tag: h.tag,
			Periodic: &task.Periodic{
				Interval: interval,
				Execute:  h.userMonitor,
			},
		},
	}

	// Check cert service in need
	if h.nodeInfo.EnableTLS {
		h.tasks = append(h.tasks, periodicTask{
			tag: "cert monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(h.config.UpdatePeriodic) * time.Second * 60,
				Execute:  h.certMonitor,
			},
		})
	}

	for _, t := range h.tasks {
		go t.Start()
	}

	h.logger.Infof("Hysteria2 node started on %s:%d (hysteria core %s)", h.config.ListenIP, h.nodeInfo.Port, getHysteriaCoreVersion())
	return nil
}

// Close implements service.Service.Close.
func (h *Hysteria2Service) Close() error {
	for _, t := range h.tasks {
		if t.Periodic != nil {
			t.Periodic.Close()
		}
	}
	h.tasks = nil
	if h.server != nil {
		return h.server.Close()
	}
	return nil
}

func getHysteriaCoreVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/apernet/hysteria/core/v2" {
			if dep.Version != "" {
				return dep.Version
			}
			if dep.Replace != nil && dep.Replace.Version != "" {
				return dep.Replace.Version
			}
			break
		}
	}
	return "unknown"
}
