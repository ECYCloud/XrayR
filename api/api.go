// Package api contains all the api used by XrayR
// To implement an api , one needs to implement the interface below.

package api

// API is the interface for different panel's api.
type API interface {
	GetNodeInfo() (nodeInfo *NodeInfo, err error)
	// GetXrayRCertConfig returns optional global XrayR certificate
	// configuration provided by the panel (for example, Cloudflare
	// DNS provider and its DNS-01 environment variables).
	GetXrayRCertConfig() (certConfig *XrayRCertConfig, err error)
	GetUserList() (userList *[]UserInfo, err error)
	ReportNodeStatus(nodeStatus *NodeStatus) (err error)
	ReportNodeOnlineUsers(onlineUser *[]OnlineUser) (err error)
	ReportUserTraffic(userTraffic *[]UserTraffic) (err error)
	Describe() ClientInfo
	GetNodeRule() (ruleList *[]DetectRule, err error)
	ReportIllegal(detectResultList *[]DetectResult) (err error)
	Debug()
	// GetMediaCheckConfig returns the streaming media check configuration
	// from the panel, including the check interval in minutes.
	GetMediaCheckConfig() (config *MediaCheckConfig, err error)
	// ReportMediaCheckResult reports the streaming media unlock check results
	// to the panel for the current node.
	ReportMediaCheckResult(result string) error
}
