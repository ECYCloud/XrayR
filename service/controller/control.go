package controller

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
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
)

func (c *Controller) removeInbound(tag string) error {
	err := c.ibm.RemoveHandler(context.Background(), tag)
	return err
}

// dataPathWrapper wraps outbound.Handler to enforce device limit, user/node speed limit,
// audit rules and ensure userland path is used for stats.
type dataPathWrapper struct {
	outbound.Handler
	pm      policy.Manager
	sm      stats.Manager
	limiter *limiter.Limiter
	// ruleMgr provides audit detection
	ruleMgr interface {
		Detect(tag string, destination string, email string, srcIP string) bool
	}
	// tag identifies this node/inbound tag for limiter and rules
	tag string
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

	if sess := session.InboundFromContext(ctx); sess != nil && sess.User != nil {
		email := sess.User.Email
		srcIP := sess.Source.Address.IP().String()
		// Resolve destination from session
		var destStr string
		if outs := session.OutboundsFromContext(ctx); len(outs) > 0 {
			ob := outs[len(outs)-1]
			destStr = ob.Target.String()
		}

		// Use the wrapper's tag as node identifier; email is formatted as email|uid.
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

		// Device limit and rate limit
		if w.limiter != nil && email != "" {
			if bucket, ok, reject := w.limiter.GetUserBucket(nodeTag, email, srcIP); reject {
				common.Close(link.Writer)
				common.Interrupt(link.Reader)
				return
			} else if ok && bucket != nil {
				// Limit uplink and downlink: wrap Reader and Writer
				link.Reader = w.limiter.RateReader(link.Reader, bucket)
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
	// Wrap outbound handler to enforce audit/device limit/rate limit and keep stats path
	wrapper := &dataPathWrapper{Handler: handler, pm: c.pm, sm: c.stm, limiter: c.dispatcher.Limiter, ruleMgr: c.dispatcher.RuleManager, tag: c.Tag}
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
