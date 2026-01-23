package mediacheck

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// OpenAI supported countries list from csm.sh
var openAISupportedCountries = []string{
	"AL", "DZ", "AD", "AO", "AG", "AR", "AM", "AU", "AT", "AZ", "BS", "BD", "BB", "BE", "BZ", "BJ", "BT", "BO", "BA", "BW",
	"BR", "BN", "BG", "BF", "CV", "CA", "CL", "CO", "KM", "CG", "CR", "CI", "HR", "CY", "CZ", "DK", "DJ", "DM", "DO", "EC",
	"SV", "EE", "EG", "FJ", "FI", "FR", "GA", "GM", "GE", "DE", "GH", "GR", "GD", "GT", "GN", "GW", "GY", "HT", "VA", "HN",
	"HU", "IS", "IN", "ID", "IQ", "IE", "IL", "IT", "JM", "JP", "JO", "KZ", "KE", "KI", "KW", "KG", "LV", "LB", "LS", "LR",
	"LI", "LT", "LU", "MG", "MW", "MY", "MV", "ML", "MT", "MH", "MR", "MU", "MX", "FM", "MD", "MC", "MN", "ME", "MA", "MZ",
	"MM", "NA", "NR", "NP", "NL", "NZ", "NI", "NE", "NG", "MK", "NO", "OM", "PK", "PW", "PS", "PA", "PG", "PY", "PE", "PH",
	"PL", "PT", "QA", "RO", "RW", "KN", "LC", "VC", "WS", "SM", "ST", "SN", "RS", "SC", "SL", "SG", "SK", "SI", "SB", "ZA",
	"KR", "ES", "LK", "SR", "SE", "CH", "TW", "TZ", "TH", "TL", "TG", "TO", "TT", "TN", "TR", "TV", "UG", "UA", "AE", "GB",
	"US", "UY", "VU", "ZM",
}

// checkAmazonPrime checks Amazon Prime Video availability
// Based on csm.sh MediaUnlockTest_PrimeVideo
func (c *Checker) checkAmazonPrime() string {
	// Retry up to 3 times for consistency
	for retry := 0; retry < 3; retry++ {
		result := c.doCheckAmazonPrime()
		if result != "Unknown" {
			return result
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "Unknown"
}

func (c *Checker) doCheckAmazonPrime() string {
	// Create a client that follows redirects (like curl -sL)
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", "https://www.primevideo.com", nil)
	if err != nil {
		return "Unknown"
	}
	req.Header.Set("User-Agent", UA_BROWSER)

	resp, err := client.Do(req)
	if err != nil {
		c.logger.Debugf("Amazon Prime check failed: %v", err)
		return "Unknown"
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Unknown"
	}

	content := string(body)

	// Check if empty response (network error)
	if len(content) == 0 {
		return "Unknown"
	}

	// Check if service is restricted (case-insensitive)
	isBlocked := strings.Contains(strings.ToLower(content), "isservicerestricted")

	// Extract region using the exact pattern from csm.sh
	// Pattern: "currentTerritory":"XX"
	re := regexp.MustCompile(`"currentTerritory"\s*:\s*"([A-Z]{2})"`)
	matches := re.FindStringSubmatch(content)
	region := ""
	if len(matches) > 1 {
		region = matches[1]
	}

	// Logic from csm.sh:
	// if [ -z "$isBlocked" ] && [ -z "$region" ]; then
	//     echo "Failed (Error: PAGE ERROR)"
	// if [ -n "$isBlocked" ]; then
	//     echo "No (Service Not Available)"
	// if [ -n "$region" ]; then
	//     echo "Yes (Region: ${region})"

	// Both empty means page error
	if !isBlocked && region == "" {
		c.logger.Debugf("Amazon Prime: PAGE ERROR - no isBlocked and no region found")
		return "Unknown"
	}

	// Service is restricted
	if isBlocked {
		return "No"
	}

	// Region found, service is available
	if region != "" {
		return formatResult("Yes", region)
	}

	return "Unknown"
}

// checkOpenAI checks OpenAI/ChatGPT availability
// Based on csm.sh MediaUnlockTest_OpenAI
func (c *Checker) checkOpenAI() string {
	// Retry up to 3 times for consistency
	for retry := 0; retry < 3; retry++ {
		result := c.doCheckOpenAI()
		if result != "Unknown" {
			return result
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "Unknown"
}

func (c *Checker) doCheckOpenAI() string {
	// Check compliance API with exact headers from csm.sh
	req1, err := http.NewRequest("GET", "https://api.openai.com/compliance/cookie_requirements", nil)
	if err != nil {
		return "Unknown"
	}
	req1.Header.Set("User-Agent", UA_BROWSER)
	req1.Header.Set("Authority", "api.openai.com")
	req1.Header.Set("Accept", "*/*")
	req1.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req1.Header.Set("Authorization", "Bearer null")
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Origin", "https://platform.openai.com")
	req1.Header.Set("Referer", "https://platform.openai.com/")
	req1.Header.Set("Sec-Ch-Ua", UA_SEC_CH_UA)
	req1.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req1.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req1.Header.Set("Sec-Fetch-Dest", "empty")
	req1.Header.Set("Sec-Fetch-Mode", "cors")
	req1.Header.Set("Sec-Fetch-Site", "same-site")

	resp1, err1 := c.client.Do(req1)
	var content1 string
	if err1 == nil {
		defer resp1.Body.Close()
		body1, _ := io.ReadAll(resp1.Body)
		content1 = string(body1)
	}

	// Check iOS endpoint with exact headers from csm.sh
	req2, err := http.NewRequest("GET", "https://ios.chat.openai.com/", nil)
	if err != nil {
		return "Unknown"
	}
	req2.Header.Set("User-Agent", UA_BROWSER)
	req2.Header.Set("Authority", "ios.chat.openai.com")
	req2.Header.Set("Accept", "*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req2.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req2.Header.Set("Sec-Ch-Ua", UA_SEC_CH_UA)
	req2.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req2.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req2.Header.Set("Sec-Fetch-Dest", "document")
	req2.Header.Set("Sec-Fetch-Mode", "navigate")
	req2.Header.Set("Sec-Fetch-Site", "none")
	req2.Header.Set("Sec-Fetch-User", "?1")
	req2.Header.Set("Upgrade-Insecure-Requests", "1")

	resp2, err2 := c.client.Do(req2)
	var content2 string
	if err2 == nil {
		defer resp2.Body.Close()
		body2, _ := io.ReadAll(resp2.Body)
		content2 = string(body2)
	}

	// Network error
	if err1 != nil && err2 != nil {
		c.logger.Debugf("OpenAI check failed: %v, %v", err1, err2)
		return "Unknown"
	}

	// Check if blocked (unsupported_country or VPN detected)
	if strings.Contains(strings.ToLower(content1), "unsupported_country") ||
		strings.Contains(strings.ToUpper(content2), "VPN") {
		return "No"
	}

	// Get region from Cloudflare trace
	traceBody, _, err := c.httpGet("https://chat.openai.com/cdn-cgi/trace", nil)
	if err == nil {
		content := string(traceBody)
		re := regexp.MustCompile(`loc=([A-Z]{2})`)
		matches := re.FindStringSubmatch(content)
		if len(matches) > 1 {
			region := matches[1]
			// Check if region is in supported list
			for _, country := range openAISupportedCountries {
				if country == region {
					return formatResult("Yes", region)
				}
			}
			return "No"
		}
	}

	return "Unknown"
}

// checkGemini checks Google Gemini availability
// Based on csm.sh MediaUnlockTest_Gemini
func (c *Checker) checkGemini() string {
	// Retry up to 3 times for consistency
	for retry := 0; retry < 3; retry++ {
		result := c.doCheckGemini()
		if result != "Unknown" {
			return result
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "Unknown"
}

func (c *Checker) doCheckGemini() string {
	body, _, err := c.httpGet("https://gemini.google.com/", nil)
	if err != nil {
		c.logger.Debugf("Gemini check failed: %v", err)
		return "Unknown"
	}

	content := string(body)

	// Check if available: grep -q '45631641,null,true'
	isAvailable := strings.Contains(content, "45631641,null,true")

	// Extract country code: grep -o ',2,1,200,"[A-Z]\{3\}"'
	re := regexp.MustCompile(`,2,1,200,"([A-Z]{3})"`)
	matches := re.FindStringSubmatch(content)
	countryCode := ""
	if len(matches) > 1 {
		countryCode = matches[1]
		// Take first 2 characters
		if len(countryCode) >= 2 {
			countryCode = countryCode[:2]
		}
	}

	if isAvailable && countryCode != "" {
		return formatResult("Yes", countryCode)
	} else if isAvailable {
		return "Yes"
	}

	return "No"
}

// checkClaude checks Claude AI availability
// Based on csm.sh WebTest_Claude - checks redirect URL, not page content
func (c *Checker) checkClaude() string {
	// Retry up to 3 times for consistency
	for retry := 0; retry < 3; retry++ {
		result := c.doCheckClaude()
		if result != "Unknown" {
			return result
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "Unknown"
}

func (c *Checker) doCheckClaude() string {
	// Create a client that follows redirects and tracks the final URL
	// This matches the csm.sh logic: curl -s -L -o /dev/null -w '%{url_effective}'
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow redirects to be followed
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", "https://claude.ai/", nil)
	if err != nil {
		return "Unknown"
	}

	req.Header.Set("User-Agent", UA_BROWSER)

	resp, err := client.Do(req)
	if err != nil {
		c.logger.Debugf("Claude check failed: %v", err)
		return "Unknown"
	}
	defer resp.Body.Close()

	// Get the final URL after all redirects
	finalURL := resp.Request.URL.String()

	c.logger.Debugf("Claude final URL: %s", finalURL)

	// Check the final URL to determine availability
	// Based on csm.sh: if final URL is "https://claude.ai/" -> Yes
	// if final URL is "https://www.anthropic.com/app-unavailable-in-region" -> No
	if finalURL == "https://claude.ai/" || strings.HasPrefix(finalURL, "https://claude.ai/") {
		// Claude is available, but we don't have region info from this check
		return "Yes"
	}

	if strings.Contains(finalURL, "app-unavailable-in-region") ||
		strings.Contains(finalURL, "unavailable") ||
		strings.Contains(finalURL, "anthropic.com") {
		return "No"
	}

	// Unknown state
	return "Unknown"
}
