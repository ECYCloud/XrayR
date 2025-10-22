package controller

import (
	"context"
	"fmt"

	"github.com/xtls/xray-core/common"
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
	"github.com/ECYCloud/XrayR/common/rule"
)

func (c *Controller) removeInbound(tag string) error {
	err := c.ibm.RemoveHandler(context.Background(), tag)
	return err
}

// statsOutboundWrapper wraps outbound.Handler to ensure user downlink traffic is counted,
// and also records online IPs for alive_ip reporting via limiter.
type statsOutboundWrapper struct {
	outbound.Handler
	pm          policy.Manager
	sm          stats.Manager
	limiter     *limiter.Limiter
	ruleManager *rule.Manager
}

func (w *statsOutboundWrapper) Dispatch(ctx context.Context, link *transport.Link) {
	// Disable kernel splice early to avoid Vision/REALITY bypassing userland stats path
	if sess := session.InboundFromContext(ctx); sess != nil {
		sess.CanSpliceCopy = 3
		// Audit rule detection (prefer OriginalTarget, then Target) — run regardless of limiter
		if w.ruleManager != nil {
			if obs := session.OutboundsFromContext(ctx); len(obs) > 0 {
				ob := obs[len(obs)-1]
				dest := ob.Target.String()
				if ot := ob.OriginalTarget.String(); ot != "" {
					dest = ot
				}
				var email string
				if sess.User != nil {
					email = sess.User.Email
				}
				if dest != "" && w.ruleManager.Detect(sess.Tag, dest, email) {
					// Block connection
					common.Close(link.Writer)
					common.Interrupt(link.Reader)
					return
				}
			}
		}
		// Device limit and per-user/node speed limit & alive_ip reporting
		if w.limiter != nil && sess.User != nil && len(sess.User.Email) > 0 {
			if bucket, ok, reject := w.limiter.GetUserBucket(sess.Tag, sess.User.Email, sess.Source.Address.IP().String()); reject {
				common.Close(link.Writer)
				common.Interrupt(link.Reader)
				return
			} else if ok {
				link.Writer = w.limiter.RateWriter(link.Writer, bucket)
			}
		}
	}
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
	// Wrap outbound handler to ensure downlink stats are always counted (e.g., REALITY/VLESS cases)
	handler = &statsOutboundWrapper{Handler: handler, pm: c.pm, sm: c.stm, limiter: c.limiter, ruleManager: c.ruleManager}
	if err := c.obm.AddHandler(context.Background(), handler); err != nil {
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
	err := c.limiter.AddInboundLimiter(tag, nodeSpeedLimit, userList, globalDeviceLimitConfig)
	return err
}

func (c *Controller) UpdateInboundLimiter(tag string, updatedUserList *[]api.UserInfo) error {
	err := c.limiter.UpdateInboundLimiter(tag, updatedUserList)
	return err
}

func (c *Controller) DeleteInboundLimiter(tag string) error {
	err := c.limiter.DeleteInboundLimiter(tag)
	return err
}

func (c *Controller) GetOnlineDevice(tag string) (*[]api.OnlineUser, error) {
	return c.limiter.GetOnlineDevice(tag)
}

func (c *Controller) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	err := c.ruleManager.UpdateRule(tag, newRuleList)
	return err
}

func (c *Controller) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	return c.ruleManager.GetDetectResult(tag)
}
