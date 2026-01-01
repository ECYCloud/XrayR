// Package mydispatcher implements a custom dispatcher with rate limiting,
// online device counting, and per-node outbound enforcement on top of the
// core Xray dispatcher.
package mydispatcher

import "github.com/xtls/xray-core/features/routing"

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

// Type returns routing.DispatcherType() so that mydispatcher replaces the
// core dispatcher (github.com/xtls/xray-core/app/dispatcher). This ensures
// that per-node outbound enforcement (same-node routing) is applied to all
// inbound connections.
//
// The controller can still access mydispatcher.DefaultDispatcher via
// server.GetFeature(routing.DispatcherType()) and type assertion.
func Type() interface{} {
	return routing.DispatcherType()
}
