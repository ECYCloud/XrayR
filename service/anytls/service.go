package anytls

import (
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"

	"github.com/ECYCloud/XrayR/api"
	"github.com/ECYCloud/XrayR/service"
	"github.com/ECYCloud/XrayR/service/controller"
)

var _ service.Service = (*AnyTLSService)(nil)

func New(apiClient api.API, cfg *controller.Config) *AnyTLSService {
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": apiClient.Describe().APIHost,
		"Type": apiClient.Describe().NodeType,
		"ID":   apiClient.Describe().NodeID,
	})
	return &AnyTLSService{
		apiClient: apiClient,
		config:    cfg,
		logger:    logger,
		users:     make(map[string]userRecord),
		traffic:   make(map[string]*userTraffic),
		onlineIPs: make(map[string]map[string]struct{}),
	}
}

func (s *AnyTLSService) Start() error {
	s.clientInfo = s.apiClient.Describe()

	nodeInfo, err := s.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	if nodeInfo == nil || nodeInfo.NodeType != "AnyTLS" {
		return fmt.Errorf("AnyTLSService can only be used with AnyTLS node, got %v", nodeInfo)
	}
	if nodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	if s.config == nil || s.config.CertConfig == nil {
		return errors.New("CertConfig is required for AnyTLS")
	}
	if nodeInfo.AnyTLSConfig == nil {
		nodeInfo.AnyTLSConfig = &api.AnyTLSConfig{}
	}

	s.nodeInfo = nodeInfo
	s.tag = fmt.Sprintf("%s_%s_%d", s.nodeInfo.NodeType, s.config.ListenIP, s.nodeInfo.Port)
	s.startAt = time.Now()
	s.inboundTag = s.tag

	userInfo, err := s.apiClient.GetUserList()
	if err != nil {
		return err
	}
	s.syncUsers(userInfo)

	boxInstance, _, err := s.buildSingBox()
	if err != nil {
		return err
	}
	s.box = boxInstance

	go func() {
		if err := s.box.Start(); err != nil {
			s.logger.Errorf("AnyTLS sing-box start error: %v", err)
		}
	}()

	interval := time.Duration(s.config.UpdatePeriodic) * time.Second
	s.tasks = []periodicTask{
		{
			tag: s.tag,
			Periodic: &task.Periodic{
				Interval: interval,
				Execute:  s.userMonitor,
			},
		},
	}

	for _, t := range s.tasks {
		go t.Start()
	}

	s.logger.Infof("AnyTLS node started on %s:%d (sing-box %s)", s.config.ListenIP, s.nodeInfo.Port, getSingBoxVersion())
	return nil
}

func (s *AnyTLSService) Close() error {
	for _, t := range s.tasks {
		if t.Periodic != nil {
			t.Periodic.Close()
		}
	}
	s.tasks = nil
	if s.box != nil {
		return s.box.Close()
	}
	return nil
}

func getSingBoxVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/sagernet/sing-box" {
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
