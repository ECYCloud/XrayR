// Package mydispatcher Package dispatcher implement the rate limiter and the online device counter
package mydispatcher

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import "github.com/xtls/xray-core/features/routing"

// Type returns the feature type token and intentionally overrides the core
// dispatcher so that XrayR's custom dispatcher participates in the data path.
// This is required for device counting and speed limiting to work.
func Type() interface{} {
	return routing.DispatcherType()
}
