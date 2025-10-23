// Package mydispatcher Package dispatcher implement the rate limiter and the online device counter
package mydispatcher

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import "github.com/xtls/xray-core/features/routing"

// Type returns the feature type token so this custom dispatcher REPLACES
// the core routing.Dispatcher. This ensures our rate limiting, device limit,
// audit detection and stats wrapping are actually applied on data path.
func Type() interface{} {
	return routing.DispatcherType()
}
