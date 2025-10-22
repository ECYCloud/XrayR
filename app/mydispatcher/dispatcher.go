// Package mydispatcher Package dispatcher implement the rate limiter and the online device counter
package mydispatcher

import "github.com/xtls/xray-core/features/routing"

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

// Type returns the feature type token for the dispatcher feature.
// It must be routing.DispatcherType() so our dispatcher replaces core's.
func Type() interface{} {
	return routing.DispatcherType()
}
