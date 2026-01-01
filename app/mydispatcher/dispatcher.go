// Package mydispatcher implements a custom dispatcher with rate limiting and
// online device counting on top of the core Xray dispatcher.
package mydispatcher

import "github.com/xtls/xray-core/features/routing"

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

// Type returns the standard routing.Dispatcher type so that this dispatcher
// becomes the primary Dispatcher feature for the Xray instance. The core
// dispatcher is still registered (see panel.loadCore), but our implementation
// is returned first from GetFeature(routing.DispatcherType()).
func Type() interface{} {
	return routing.DispatcherType()
}
