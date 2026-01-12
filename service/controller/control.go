package controller

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"

	"github.com/ECYCloud/XrayR/api"
	"github.com/ECYCloud/XrayR/common/limiter"
)

func (c *Controller) removeInbound(tag string) error {
	err := c.ibm.RemoveHandler(context.Background(), tag)
	return err
}

// xrayRManagedPrefixes defines all protocol prefixes that XrayR manages.
// Tags with these prefixes follow the format: {Protocol}_{IP}_{Port}_{NodeID}
var xrayRManagedPrefixes = []string{
	"VLESS_",
	"Trojan_",
	"Vmess_",
	"Shadowsocks_",
}

// isXrayRManagedTag checks if a tag is managed by XrayR (i.e., it belongs to a specific node).
// XrayR-managed tags have the format: {Protocol}_{IP}_{Port}_{NodeID}
func isXrayRManagedTag(tag string) bool {
	for _, prefix := range xrayRManagedPrefixes {
		if strings.HasPrefix(tag, prefix) {
			return true
		}
	}
	return false
}

// dataPathWrapper wraps outbound.Handler to enforce audit rules and ensure
// userland path is used for stats. Rate limiting and device limit are handled
// in mydispatcher/default.go:getLink() to avoid double-application of limits.
type dataPathWrapper struct {
	outbound.Handler
	pm policy.Manager
	sm stats.Manager
	// ruleMgr provides audit detection
	ruleMgr interface {
		Detect(tag string, destination string, email string, srcIP string) bool
	}
	// tag identifies this node/inbound tag for audit rules
	tag string
	// obm allows us to look up the correct outbound handler by tag, so we can
	// enforce "same node in, same node out" routing without touching xray-core
	// dispatcher internals.
	obm outbound.Manager
}

// Tag returns the outbound tag. This MUST match the inbound tag to ensure
// correct routing (same NodeID in, same NodeID out).
func (w *dataPathWrapper) Tag() string {
	return w.tag
}

func (w *dataPathWrapper) Dispatch(ctx context.Context, link *transport.Link) {
	// Force userland path to keep stats/limit in effect
	if sess := session.InboundFromContext(ctx); sess != nil {
		sess.CanSpliceCopy = 3
	}

	// --- FIRST: Enforce "same node in, same node out" semantics -------------
	// 对所有 XrayR 管理的节点做强制校验：入站 tag 必须和出站 tag 完全一致，
	// 防止流量串到其他节点或协议上。
	// 支持的协议: VLESS, Trojan, Vmess, Shadowsocks
	if sess := session.InboundFromContext(ctx); sess != nil {
		inTag := sess.Tag
		if isXrayRManagedTag(inTag) && inTag != "" && inTag != w.tag {
			// Try to find the correct outbound for this XrayR inbound tag.
			if w.obm != nil {
				if h := w.obm.GetHandler(inTag); h != nil {
					// Avoid infinite recursion if, for some reason, the manager returns
					// the same wrapper instance.
					if h == w {
						log.WithFields(log.Fields{
							"inbound_tag":  inTag,
							"outbound_tag": w.tag,
						}).Warn("same-node routing: manager returned current outbound; using it directly")
						// Fall through to process in this wrapper
					} else {
						// Update access log detour to reflect the actual same-node outbound
						// selection (e.g., Trojan_x => Trojan_x) instead of the originally chosen
						// different outbound recorded by core dispatcher.
						if am := xlog.AccessMessageFromContext(ctx); am != nil {
							am.Detour = inTag + " => " + h.Tag()
						}
						log.WithFields(log.Fields{
							"inbound_tag":       inTag,
							"selected_outbound": w.tag,
							"reroute_outbound":  h.Tag(),
						}).Info("same-node routing: rerouting to outbound with matching tag")
						// Delegate to the correct handler and stop processing in current wrapper.
						// The correct wrapper will handle audit rules with the right node tag.
						h.Dispatch(ctx, link)
						return
					}
				} else {
					log.WithFields(log.Fields{
						"inbound_tag":  inTag,
						"outbound_tag": w.tag,
					}).Error("same-node routing: no outbound handler found for inbound tag; rejecting connection")
					common.Close(link.Writer)
					common.Interrupt(link.Reader)
					return
				}
			} else {
				log.WithFields(log.Fields{
					"inbound_tag":  inTag,
					"outbound_tag": w.tag,
				}).Error("same-node routing: outbound manager is nil; rejecting connection")
				common.Close(link.Writer)
				common.Interrupt(link.Reader)
				return
			}
		}
	}

	// --- Now we're in the correct wrapper (inTag matches w.tag) -------------
	// Perform audit check with the correct node tag.
	// NOTE: Rate limiting and device limit are handled in mydispatcher/default.go:getLink()
	// to avoid double-application of limits. We only perform audit rule check here.
	if sess := session.InboundFromContext(ctx); sess != nil && sess.User != nil {
		email := sess.User.Email
		srcIP := sess.Source.Address.IP().String()
		// Resolve destination from session
		var destStr string
		if outs := session.OutboundsFromContext(ctx); len(outs) > 0 {
			ob := outs[len(outs)-1]
			destStr = ob.Target.String()
		}

		// Use the wrapper's tag as node identifier; email is formatted as Tag|UID.
		nodeTag := w.tag

		// Audit check: reject immediately on hit
		if w.ruleMgr != nil && email != "" && destStr != "" {
			if w.ruleMgr.Detect(nodeTag, destStr, email, srcIP) {
				// Log audit rule hit with destination and user info for all protocols.
				log.WithFields(log.Fields{
					"tag":   nodeTag,
					"user":  email,
					"srcIP": srcIP,
					"dest":  destStr,
				}).Warn("audit rule hit, closing connection")
				// close link
				common.Close(link.Writer)
				common.Interrupt(link.Reader)
				return
			}
		}
	}

	// Normal path: inbound tag matches this node's tag, dispatch to actual handler.
	w.Handler.Dispatch(ctx, link)
}

func (c *Controller) removeOutbound(tag string) error {
	err := c.obm.RemoveHandler(context.Background(), tag)
	return err
}

func (c *Controller) addInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	if err := c.ibm.AddHandler(context.Background(), handler); err != nil {
		return err
	}
	return nil
}

func (c *Controller) addOutbound(config *core.OutboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(outbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	// Wrap outbound handler to enforce audit rules, keep stats path, and enforce
	// "same node in, same node out" semantics.
	// NOTE: Rate limiting and device limit are handled in mydispatcher/default.go:getLink()
	// to avoid double-application of limits.
	wrapper := &dataPathWrapper{
		Handler: handler,
		pm:      c.pm,
		sm:      c.stm,
		ruleMgr: c.dispatcher.RuleManager,
		// Each controller instance has a unique Tag derived from NodeID, so using
		// c.Tag here ensures per-node isolation for audit rules *and* routing.
		tag: c.Tag,
		obm: c.obm,
	}
	log.Infof("Adding outbound handler: configTag=%s handlerTag=%s wrapperTag=%s controllerTag=%s", config.Tag, handler.Tag(), wrapper.Tag(), c.Tag)
	if err := c.obm.AddHandler(context.Background(), wrapper); err != nil {
		return err
	}
	return nil
}

func (c *Controller) addUsers(users []*protocol.User, tag string) error {
	handler, err := c.ibm.GetHandler(context.Background(), tag)
	if err != nil {
		return fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s has not implemented proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("handler %s has not implemented proxy.UserManager", tag)
	}
	for _, item := range users {
		mUser, err := item.ToMemoryUser()
		if err != nil {
			return err
		}
		err = userManager.AddUser(context.Background(), mUser)
		if err != nil {
			return err
		}
		// Pre-register per-user traffic counters so core can increment them (downlink/uplink)
		uName := "user>>>" + mUser.Email + ">>>traffic>>>uplink"
		dName := "user>>>" + mUser.Email + ">>>traffic>>>downlink"
		if _, _ = stats.GetOrRegisterCounter(c.stm, uName); true {
			// no-op
		}
		if _, _ = stats.GetOrRegisterCounter(c.stm, dName); true {
			// no-op
		}
	}
	return nil
}

func (c *Controller) removeUsers(users []string, tag string) error {
	handler, err := c.ibm.GetHandler(context.Background(), tag)
	if err != nil {
		return fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s is not implement proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("handler %s is not implement proxy.UserManager", err)
	}
	for _, email := range users {
		err = userManager.RemoveUser(context.Background(), email)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) getTraffic(email string) (up int64, down int64, upCounter stats.Counter, downCounter stats.Counter) {
	upName := "user>>>" + email + ">>>traffic>>>uplink"
	downName := "user>>>" + email + ">>>traffic>>>downlink"
	upCounter = c.stm.GetCounter(upName)
	downCounter = c.stm.GetCounter(downName)
	if upCounter != nil && upCounter.Value() != 0 {
		up = upCounter.Value()
	} else {
		upCounter = nil
	}
	if downCounter != nil && downCounter.Value() != 0 {
		down = downCounter.Value()
	} else {
		downCounter = nil
	}
	return up, down, upCounter, downCounter
}

func (c *Controller) resetTraffic(upCounterList *[]stats.Counter, downCounterList *[]stats.Counter) {
	for _, upCounter := range *upCounterList {
		upCounter.Set(0)
	}
	for _, downCounter := range *downCounterList {
		downCounter.Set(0)
	}
}

func (c *Controller) AddInboundLimiter(tag string, nodeSpeedLimit uint64, userList *[]api.UserInfo, globalDeviceLimitConfig *limiter.GlobalDeviceLimitConfig) error {
	err := c.dispatcher.Limiter.AddInboundLimiter(tag, nodeSpeedLimit, userList, globalDeviceLimitConfig)
	return err
}

func (c *Controller) UpdateInboundLimiter(tag string, updatedUserList *[]api.UserInfo) error {
	err := c.dispatcher.Limiter.UpdateInboundLimiter(tag, updatedUserList)
	return err
}

func (c *Controller) DeleteInboundLimiter(tag string) error {
	err := c.dispatcher.Limiter.DeleteInboundLimiter(tag)
	return err
}

func (c *Controller) GetOnlineDevice(tag string) (*[]api.OnlineUser, error) {
	return c.dispatcher.Limiter.GetOnlineDevice(tag)
}

func (c *Controller) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	err := c.dispatcher.RuleManager.UpdateRule(tag, newRuleList)
	return err
}

func (c *Controller) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	return c.dispatcher.RuleManager.GetDetectResult(tag)
}
