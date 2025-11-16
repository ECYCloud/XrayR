package hysteria2

import (
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"
	"golang.org/x/time/rate"

	"github.com/ECYCloud/XrayR/api"
	"github.com/ECYCloud/XrayR/common/rule"
	"github.com/ECYCloud/XrayR/service/controller"
)

type Hysteria2Service struct {
	apiClient api.API
	config    *controller.Config

	clientInfo api.ClientInfo
	nodeInfo   *api.NodeInfo

	server server.Server

	tag     string
	startAt time.Time
	tasks   []periodicTask
	logger  *log.Entry

	rules *rule.Manager

	mu           sync.RWMutex
	users        map[string]userRecord          // uuid -> user
	traffic      map[string]*userTraffic        // uuid -> counters
	overLimit    map[string]bool                // uuid -> over device limit
	onlineIPs    map[string]map[string]struct{} // uuid -> set of IPs
	blockedIDs   map[string]bool                // connection id -> blocked by audit
	rateLimiters map[string]*rate.Limiter       // uuid -> per-user speed limiter
}

type userRecord struct {
	UID         int
	Email       string
	DeviceLimit int
	SpeedLimit  uint64
}

type userTraffic struct {
	Upload   int64
	Download int64
}

type periodicTask struct {
	tag string
	*task.Periodic
}
