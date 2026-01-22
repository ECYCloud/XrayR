// Package mediacheck provides streaming media unlock detection functionality.
// It checks various streaming services (Netflix, YouTube Premium, Disney+, etc.)
// and reports the results to the panel.
package mediacheck

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// MediaCheckResult represents the result of a single media check
type MediaCheckResult struct {
	Status string `json:"status"` // "Yes", "No", "Unknown"
	Region string `json:"region,omitempty"`
}

// MediaCheckResults represents all media check results
type MediaCheckResults struct {
	YouTube     string `json:"YouTube"`
	Netflix     string `json:"Netflix"`
	DisneyPlus  string `json:"DisneyPlus"`
	HBOMax      string `json:"HBOMax"`
	AmazonPrime string `json:"AmazonPrime"`
	OpenAI      string `json:"OpenAI"`
	Gemini      string `json:"Gemini"`
	Claude      string `json:"Claude"`
	TikTok      string `json:"TikTok"`
}

// Checker performs media unlock checks
type Checker struct {
	client *http.Client
	logger *log.Entry
}

// NewChecker creates a new media checker
func NewChecker(logger *log.Entry) *Checker {
	return &Checker{
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger: logger,
	}
}

// RunAllChecks performs all media unlock checks and returns the results
func (c *Checker) RunAllChecks() *MediaCheckResults {
	results := &MediaCheckResults{
		YouTube:     "Unknown",
		Netflix:     "Unknown",
		DisneyPlus:  "Unknown",
		HBOMax:      "Unknown",
		AmazonPrime: "Unknown",
		OpenAI:      "Unknown",
		Gemini:      "Unknown",
		Claude:      "Unknown",
		TikTok:      "Unknown",
	}

	// Run checks concurrently
	done := make(chan struct{})
	go func() {
		results.YouTube = c.checkYouTubePremium()
		done <- struct{}{}
	}()
	go func() {
		results.Netflix = c.checkNetflix()
		done <- struct{}{}
	}()
	go func() {
		results.DisneyPlus = c.checkDisneyPlus()
		done <- struct{}{}
	}()
	go func() {
		results.HBOMax = c.checkHBOMax()
		done <- struct{}{}
	}()
	go func() {
		results.AmazonPrime = c.checkAmazonPrime()
		done <- struct{}{}
	}()
	go func() {
		results.OpenAI = c.checkOpenAI()
		done <- struct{}{}
	}()
	go func() {
		results.Gemini = c.checkGemini()
		done <- struct{}{}
	}()
	go func() {
		results.Claude = c.checkClaude()
		done <- struct{}{}
	}()
	go func() {
		results.TikTok = c.checkTikTok()
		done <- struct{}{}
	}()

	// Wait for all checks to complete
	for i := 0; i < 9; i++ {
		<-done
	}

	return results
}

// ToJSON converts results to JSON string
func (r *MediaCheckResults) ToJSON() string {
	data, err := json.Marshal(r)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// httpGet performs a GET request with custom headers
func (c *Checker) httpGet(url string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}

	// Set default User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return body, resp.StatusCode, nil
}

// formatResult formats the check result
func formatResult(status, region string) string {
	if region != "" {
		return fmt.Sprintf("%s (%s)", status, region)
	}
	return status
}

// extractRegion extracts region code from response using regex
func extractRegion(body string, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.ToUpper(matches[1])
	}
	return ""
}

