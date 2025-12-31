// Package mydispatcher Package dispatcher implement the rate limiter and the online device counter
package mydispatcher

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import "github.com/xtls/xray-core/features/routing"

// Type returns the standard routing.Dispatcher type token so that XrayR's
// custom dispatcher becomes the global dispatcher used by xray-core. This
// allows us to enforce per-node outbound selection for all inbounds.
func Type() interface{} {
	return routing.DispatcherType()
}
