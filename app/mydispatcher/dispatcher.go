// Package mydispatcher implements a custom dispatcher with rate limiting and
// online device counting on top of the core Xray dispatcher.
package mydispatcher

import "github.com/xtls/xray-core/features/routing"

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

// Type returns routing.DispatcherType() so that mydispatcher is registered as
// the primary routing.Dispatcher. This ensures inbound handlers use our custom
// dispatcher with VLESS same-node routing enforcement, rate limiting, and
// rule management.
func Type() interface{} {
	return routing.DispatcherType()
}
