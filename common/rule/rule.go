// Package rule is to control the audit rule behaviors
package rule

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	mapset "github.com/deckarep/golang-set"
	"github.com/xtls/xray-core/common/errors"

	"github.com/ECYCloud/XrayR/api"
)

type Manager struct {
	InboundRule         *sync.Map // Key: Tag, Value: []api.DetectRule
	InboundDetectResult *sync.Map // key: Tag, Value: mapset.NewSet []api.DetectResult
	// exemptUsers stores the audit exemption list. Key: UID, Value: *api.ExemptUser
	exemptUsers *sync.Map
}

func New() *Manager {
	return &Manager{
		InboundRule:         new(sync.Map),
		InboundDetectResult: new(sync.Map),
		exemptUsers:         new(sync.Map),
	}
}

// UpdateExemptUsers replaces the exempt user list
func (r *Manager) UpdateExemptUsers(users []api.ExemptUser) {
	// Clear old entries
	r.exemptUsers.Range(func(key, value interface{}) bool {
		r.exemptUsers.Delete(key)
		return true
	})
	// Store new entries
	for i := range users {
		r.exemptUsers.Store(users[i].UID, &users[i])
	}
}

// isExempt checks if a user (by UID) is exempt from a specific rule
func (r *Manager) isExempt(uid int, ruleID int) bool {
	val, ok := r.exemptUsers.Load(uid)
	if !ok {
		return false
	}
	eu := val.(*api.ExemptUser)
	if eu.GlobalExempt {
		return true
	}
	for _, rid := range eu.ExemptRuleIDs {
		if rid == ruleID {
			return true
		}
	}
	return false
}

func (r *Manager) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	if value, ok := r.InboundRule.LoadOrStore(tag, newRuleList); ok {
		oldRuleList := value.([]api.DetectRule)
		if !reflect.DeepEqual(oldRuleList, newRuleList) {
			r.InboundRule.Store(tag, newRuleList)
		}
	}
	return nil
}

func (r *Manager) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	detectResult := make([]api.DetectResult, 0)
	if value, ok := r.InboundDetectResult.LoadAndDelete(tag); ok {
		resultSet := value.(mapset.Set)
		it := resultSet.Iterator()
		for result := range it.C {
			detectResult = append(detectResult, result.(api.DetectResult))
		}
	}
	return &detectResult, nil
}

func (r *Manager) Detect(tag string, destination string, userKey string, srcIP string) (reject bool) {
	reject = false
	var hitRuleID = -1
	// Parse UID early so we can check exemptions before rejecting
	uid := -1
	if n, err := strconv.Atoi(userKey); err == nil {
		uid = n
	} else {
		parts := strings.Split(userKey, "|")
		if n, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
			uid = n
		}
	}
	// If we have some rule for this inbound
	if value, ok := r.InboundRule.Load(tag); ok {
		ruleList := value.([]api.DetectRule)
		for _, rule := range ruleList {
			if rule.Pattern.Match([]byte(destination)) {
				// Check if user is exempt from this rule
				if uid >= 0 && r.isExempt(uid, rule.ID) {
					continue
				}
				hitRuleID = rule.ID
				reject = true
				break
			}
		}
		// If we hit some rule
		if reject && hitRuleID != -1 {
			if uid < 0 {
				errors.LogDebug(context.Background(), fmt.Sprintf("Record illegal behavior failed! Cannot find user's uid: %s", userKey))
				return reject
			}
			newSet := mapset.NewSetWith(api.DetectResult{UID: uid, RuleID: hitRuleID, IP: srcIP})
			// If there are any hit history
			if v, ok := r.InboundDetectResult.LoadOrStore(tag, newSet); ok {
				resultSet := v.(mapset.Set)
				// If this is a new record
				if resultSet.Add(api.DetectResult{UID: uid, RuleID: hitRuleID, IP: srcIP}) {
					r.InboundDetectResult.Store(tag, resultSet)
				}
			}
		}
	}
	return reject
}
