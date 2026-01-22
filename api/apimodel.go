package api

import (
	"encoding/json"
	"regexp"

	"github.com/xtls/xray-core/infra/conf"
)

const (
	UserNotModified = "users not modified"
	NodeNotModified = "node not modified"
	RuleNotModified = "rules not modified"
)

// Config API config
//
// VLESS 相关配置（是否启用 VLESS、flow 等）不再从本地配置文件读取，
// 而是完全由面板的 custom_config / NodeType 决定。这样可以避免面板与
// XrayR 配置不一致带来的混乱，因此这里不再包含任何与 VLESS 开关相关
// 的字段。
type Config struct {
	APIHost string `mapstructure:"ApiHost"`
	// NodeID 支持单个或多个节点 ID：
	//   NodeID: 41
	//   NodeID: "41,42,43"
	//
	// 当 NodeID 为空字符串时，视为未配置；
	// 当仅为数字时表示单个节点；当包含逗号时会在 Panel.expandNodesConfig
	// 中被拆分为多个逻辑节点，每个逻辑节点拥有独立的 NodeID。
	NodeID              string  `mapstructure:"NodeID"`
	Key                 string  `mapstructure:"ApiKey"`
	Timeout             int     `mapstructure:"Timeout"`
	SpeedLimit          float64 `mapstructure:"SpeedLimit"`
	DeviceLimit         int     `mapstructure:"DeviceLimit"`
	RuleListPath        string  `mapstructure:"RuleListPath"`
	DisableCustomConfig bool    `mapstructure:"DisableCustomConfig"`
}

// NodeStatus Node status
type NodeStatus struct {
	CPU    float64
	Mem    float64
	Disk   float64
	Uptime uint64
}

type NodeInfo struct {
	AcceptProxyProtocol bool
	Authority           string
	NodeType            string // Must be Vmess, VLESS, Trojan, Shadowsocks, Hysteria2, AnyTLS, Tuic
	NodeID              int
	Port                uint32
	SpeedLimit          uint64 // Bps
	AlterID             uint16
	TransportProtocol   string
	FakeType            string
	Host                string
	Path                string
	// SNI is the Server Name Indication derived from panel configuration.
	// For custom_config nodes it prefers `sni` / `server_name`; for legacy
	// nodes it falls back to the parsed Host when available.
	SNI              string
	EnableTLS        bool
	EnableSniffing   bool
	RouteOnly        bool
	VlessFlow        string
	CypherMethod     string
	ServerKey        string
	ServiceName      string
	Method           string
	Header           json.RawMessage
	HttpHeaders      map[string]*conf.StringList
	Headers          map[string]string
	NameServerConfig []*conf.NameServerConfig
	EnableREALITY    bool
	REALITYConfig    *REALITYConfig
	Show             bool
	EnableTFO        bool
	Dest             string
	ProxyProtocolVer uint64
	ServerNames      []string
	PrivateKey       string
	MinClientVer     string
	MaxClientVer     string
	MaxTimeDiff      uint64
	ShortIds         []string
	Xver             uint64
	Flow             string
	Security         string
	Key              string
	RejectUnknownSni bool
	Hysteria2Config  *Hysteria2Config
	AnyTLSConfig     *AnyTLSConfig
	TuicConfig       *TuicConfig
}

// XrayRCertConfig describes the certificate-related configuration
// that XrayR can load from the panel (e.g. Cloudflare DNS provider
// and its environment variables for lego/ACME).
type XrayRCertConfig struct {
	Provider string            `json:"provider"`
	Email    string            `json:"email"`
	DNSEnv   map[string]string `json:"dns_env"`
}

type Hysteria2Config struct {
	Obfs                  string
	ObfsPassword          string
	UpMbps                int
	DownMbps              int
	IgnoreClientBandwidth bool

	// Port hopping configuration for Hysteria2. These fields are populated
	// from the panel custom_config when the node type is Hysteria2.
	//
	// PortHopPorts is a canonical, comma-separated expression such as
	// "30000-50000,60000" mirroring the panel-side representation.
	PortHopEnabled bool
	PortHopPorts   string
}

type AnyTLSConfig struct {
	PaddingScheme []string
}

type TuicConfig struct {
	CongestionControl string
	UDPRelayMode      string
	ZeroRTTHandshake  bool
	Heartbeat         int
	ALPN              []string
}

type UserInfo struct {
	UID         int
	Email       string
	UUID        string
	Passwd      string
	Port        uint32
	AlterID     uint16
	Method      string
	SpeedLimit  uint64 // Bps
	DeviceLimit int
}

type OnlineUser struct {
	UID int
	IP  string
}

type UserTraffic struct {
	UID      int
	Email    string
	Upload   int64
	Download int64
}

type ClientInfo struct {
	APIHost string
	NodeID  int
	Key     string
}

type DetectRule struct {
	ID      int
	Pattern *regexp.Regexp
}

type DetectResult struct {
	UID    int
	RuleID int
	IP     string
}

type REALITYConfig struct {
	Dest             string
	ProxyProtocolVer uint64
	ServerNames      []string
	PrivateKey       string
	MinClientVer     string
	MaxClientVer     string
	MaxTimeDiff      uint64
	ShortIds         []string
}

// MediaCheckConfig represents the streaming media check configuration
// retrieved from the panel.
type MediaCheckConfig struct {
	// Enabled indicates whether media check is enabled
	Enabled bool `json:"enabled"`
	// CheckInterval is the interval between checks in minutes
	CheckInterval int `json:"check_interval"`
}
