// Package mydispatcher Package dispatcher implement the rate limiter and the online device counter
package mydispatcher

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

// Type returns a unique feature type token so this custom dispatcher is
// registered alongside the core dispatcher (does NOT override it). This avoids
// panics from xray-core inbounds that expect the concrete *dispatcher.DefaultDispatcher.
func Type() interface{} {
	return (*DefaultDispatcher)(nil)
}
