package controller

import (
	"github.com/ECYCloud/XrayR/common/limiter"
	"github.com/ECYCloud/XrayR/common/mylego"
)

type Config struct {
	ListenIP                string                           `mapstructure:"ListenIP"`
	SendIP                  string                           `mapstructure:"SendIP"`
	UpdatePeriodic          int                              `mapstructure:"UpdatePeriodic"`
	CertConfig              *mylego.CertConfig               `mapstructure:"CertConfig"`
	EnableDNS               bool                             `mapstructure:"EnableDNS"`
	DNSType                 string                           `mapstructure:"DNSType"`
	DisableUploadTraffic    bool                             `mapstructure:"DisableUploadTraffic"`
	DisableGetRule          bool                             `mapstructure:"DisableGetRule"`
	EnableFallback          bool                             `mapstructure:"EnableFallback"`
	DisableIVCheck          bool                             `mapstructure:"DisableIVCheck"`
	DisableSniffing         bool                             `mapstructure:"DisableSniffing"`
	AutoSpeedLimitConfig    *AutoSpeedLimitConfig            `mapstructure:"AutoSpeedLimitConfig"`
	GlobalDeviceLimitConfig *limiter.GlobalDeviceLimitConfig `mapstructure:"GlobalDeviceLimitConfig"`
	FallBackConfigs         []*FallBackConfig                `mapstructure:"FallBackConfigs"`
	// ConnIdle is the connection idle timeout in seconds.
	// When a connection has no activity for this duration, it will be closed.
	// This is mainly used by sing-box based services (AnyTLS, TUIC) to match
	// the behavior of Xray-core's ConnectionIdle policy.
	// Default: 30 seconds.
	ConnIdle uint32 `mapstructure:"ConnIdle"`
}

type AutoSpeedLimitConfig struct {
	Limit         int `mapstructure:"Limit"` // mbps
	WarnTimes     int `mapstructure:"WarnTimes"`
	LimitSpeed    int `mapstructure:"LimitSpeed"`    // mbps
	LimitDuration int `mapstructure:"LimitDuration"` // minute
}

type FallBackConfig struct {
	SNI              string `mapstructure:"SNI"`
	Alpn             string `mapstructure:"Alpn"`
	Path             string `mapstructure:"Path"`
	Dest             string `mapstructure:"Dest"`
	ProxyProtocolVer uint64 `mapstructure:"ProxyProtocolVer"`
}
