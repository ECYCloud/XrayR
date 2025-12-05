package tuic

import (
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"
	"golang.org/x/time/rate"

	"github.com/ECYCloud/XrayR/api"
	"github.com/ECYCloud/XrayR/common/rule"
	"github.com/ECYCloud/XrayR/service/controller"
)

type TuicService struct {
	apiClient api.API
	config    *controller.Config

	clientInfo api.ClientInfo
	nodeInfo   *api.NodeInfo

	box        *box.Box
	inboundTag string

	tag     string
	startAt time.Time
	tasks   []periodicTask
	logger  *log.Entry

	rules *rule.Manager

	mu           sync.RWMutex
	users        map[string]userRecord          // authKey -> user
	traffic      map[string]*userTraffic        // authKey -> counters
	onlineIPs    map[string]map[string]struct{} // authKey -> set of IPs
	authUsers    []option.TUICUser              // users for sing-box TUIC authentication
	rateLimiters map[string]*rate.Limiter       // authKey -> per-user speed limiter
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

