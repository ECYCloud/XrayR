// Package mediacheck provides streaming media unlock detection functionality.
// It checks various streaming services (Netflix, YouTube Premium, Disney+, etc.)
// and reports the results to the panel.
// Detection logic is 100% based on csm.sh script from:
// https://github.com/ECYCloud/check-stream-media
// The script is embedded locally and executed without remote download.
// NO FALLBACK - only uses the embedded csm.sh script for 100% accuracy.
package mediacheck

import (
	"encoding/json"
	"os"
	"os/exec"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Global cache for media check results (shared across all nodes on the same server)
var (
	globalCacheMutex    sync.RWMutex
	globalCachedResults *MediaCheckResults
	globalCacheTime     time.Time
	globalCacheHour     int    // The hour when the cache was created
	globalCacheDate     string // The date when the cache was created

	// Subscribers waiting for detection results
	subscribersMutex sync.Mutex
	subscribers      []chan *MediaCheckResults
	isChecking       bool
)

// GetCachedResults returns cached results if still valid for the current hour, otherwise returns nil
func GetCachedResults() *MediaCheckResults {
	globalCacheMutex.RLock()
	defer globalCacheMutex.RUnlock()

	if globalCachedResults == nil {
		return nil
	}

	// Cache is valid if it was created in the current hour on the same date
	now := time.Now()
	currentHour := now.Hour()
	currentDate := now.Format("2006-01-02")

	if globalCacheDate == currentDate && globalCacheHour == currentHour {
		return globalCachedResults
	}

	return nil
}

// SetCachedResults stores the results in global cache and notifies all waiting subscribers
func SetCachedResults(results *MediaCheckResults) {
	globalCacheMutex.Lock()
	now := time.Now()
	globalCachedResults = results
	globalCacheTime = now
	globalCacheHour = now.Hour()
	globalCacheDate = now.Format("2006-01-02")
	globalCacheMutex.Unlock()

	// Notify all waiting subscribers
	notifySubscribers(results)
}

// WaitForResults waits for detection results from another node
// Returns the results when available, or nil if timeout
func WaitForResults(timeout time.Duration) *MediaCheckResults {
	// First check if results are already available
	if results := GetCachedResults(); results != nil {
		return results
	}

	// Create a channel to receive results
	ch := make(chan *MediaCheckResults, 1)

	subscribersMutex.Lock()
	subscribers = append(subscribers, ch)
	subscribersMutex.Unlock()

	// Wait for results or timeout
	select {
	case results := <-ch:
		return results
	case <-time.After(timeout):
		// Remove this subscriber on timeout
		removeSubscriber(ch)
		return nil
	}
}

// notifySubscribers sends results to all waiting subscribers
func notifySubscribers(results *MediaCheckResults) {
	subscribersMutex.Lock()
	defer subscribersMutex.Unlock()

	for _, ch := range subscribers {
		select {
		case ch <- results:
		default:
			// Channel full or closed, skip
		}
	}
	// Clear subscribers after notification
	subscribers = nil
}

// removeSubscriber removes a subscriber channel from the list
func removeSubscriber(ch chan *MediaCheckResults) {
	subscribersMutex.Lock()
	defer subscribersMutex.Unlock()

	for i, sub := range subscribers {
		if sub == ch {
			subscribers = append(subscribers[:i], subscribers[i+1:]...)
			break
		}
	}
}

// TryAcquireCheckLock tries to acquire the lock for performing detection
// Returns true if this caller should perform the check, false if another node is already checking
func TryAcquireCheckLock() bool {
	subscribersMutex.Lock()
	defer subscribersMutex.Unlock()

	if isChecking {
		return false
	}
	isChecking = true
	return true
}

// ReleaseCheckLock releases the check lock
func ReleaseCheckLock() {
	subscribersMutex.Lock()
	defer subscribersMutex.Unlock()
	isChecking = false
}

// MediaCheckResults represents all media check results
type MediaCheckResults struct {
	YouTubePremium string `json:"YouTube_Premium"`
	Netflix        string `json:"Netflix"`
	DisneyPlus     string `json:"DisneyPlus"`
	HBOMax         string `json:"HBOMax"`
	AmazonPrime    string `json:"AmazonPrime"`
	OpenAI         string `json:"OpenAI"`
	Gemini         string `json:"Gemini"`
	Claude         string `json:"Claude"`
	TikTok         string `json:"TikTok"`
}

// Checker performs media unlock checks using embedded csm.sh script
type Checker struct {
	logger *log.Entry
}

// NewChecker creates a new media checker
func NewChecker(logger *log.Entry) *Checker {
	return &Checker{
		logger: logger,
	}
}

// RunAllChecks performs all media unlock checks by executing embedded csm.sh script
// This ensures 100% consistency with the csm.sh detection logic
// NO FALLBACK - if script fails, returns Unknown for all services
func (c *Checker) RunAllChecks() *MediaCheckResults {
	// Default results (all Unknown)
	defaultResults := &MediaCheckResults{
		YouTubePremium: "Unknown",
		Netflix:        "Unknown",
		DisneyPlus:     "Unknown",
		HBOMax:         "Unknown",
		AmazonPrime:    "Unknown",
		OpenAI:         "Unknown",
		Gemini:         "Unknown",
		Claude:         "Unknown",
		TikTok:         "Unknown",
	}

	// Execute embedded csm.sh script (100% accurate detection)
	scriptResults := c.runCSMScript()
	if scriptResults != nil {
		c.logger.Info("[MediaCheck] csm.sh script executed successfully")
		return scriptResults
	}

	// Script failed - return default Unknown results
	c.logger.Error("[MediaCheck] csm.sh script failed, returning Unknown for all services")
	return defaultResults
}

// runCSMScript executes the embedded csm.sh script locally, returns results or nil if failed
// This uses the locally embedded script (CSM_SCRIPT) instead of downloading from remote
func (c *Checker) runCSMScript() *MediaCheckResults {
	scriptPath := "/tmp/xrayr_csm_check.sh"
	resultPath := "/tmp/xrayr_media_check_result.json"

	// Write embedded script to temp file
	c.logger.Info("[MediaCheck] Writing embedded csm.sh script to temp file...")
	if err := os.WriteFile(scriptPath, []byte(CSM_SCRIPT), 0755); err != nil {
		c.logger.Warnf("[MediaCheck] Failed to write script file: %v", err)
		return nil
	}

	// Execute the script
	c.logger.Info("[MediaCheck] Executing embedded csm.sh script (100% same logic as csm.sh)...")
	execCmd := exec.Command("bash", scriptPath)
	execCmd.Env = append(os.Environ(), "LANG=en_US.UTF-8")
	output, err := execCmd.CombinedOutput()
	if err != nil {
		c.logger.Warnf("[MediaCheck] Failed to execute script: %v, output: %s", err, string(output))
		// Clean up script file
		os.Remove(scriptPath)
		return nil
	}

	// Read result JSON file
	resultData, err := os.ReadFile(resultPath)
	if err != nil {
		c.logger.Warnf("[MediaCheck] Failed to read result file: %v", err)
		os.Remove(scriptPath)
		return nil
	}

	// Parse JSON results
	var results MediaCheckResults
	if err := json.Unmarshal(resultData, &results); err != nil {
		c.logger.Warnf("[MediaCheck] Failed to parse result JSON: %v", err)
		os.Remove(scriptPath)
		os.Remove(resultPath)
		return nil
	}

	// Clean up temp files
	os.Remove(scriptPath)
	os.Remove(resultPath)

	c.logger.Info("[MediaCheck] Embedded csm.sh script executed successfully")
	return &results
}

// ToJSON converts results to JSON string
func (r *MediaCheckResults) ToJSON() string {
	data, err := json.Marshal(r)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// GetCSMScript returns the embedded CSM script content for external use
func GetCSMScript() string {
	return CSM_SCRIPT
}
