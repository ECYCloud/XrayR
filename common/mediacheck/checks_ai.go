package mediacheck

import (
	"io"
	"net/http"
	"regexp"
	"strings"
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
	body, _, err := c.httpGet("https://www.primevideo.com/", nil)
	if err != nil {
		c.logger.Debugf("Amazon Prime check failed: %v", err)
		return "Unknown"
	}

	content := string(body)

	// Check if service is restricted
	isBlocked := strings.Contains(content, "isServiceRestricted")

	// Extract region
	re := regexp.MustCompile(`"currentTerritory":"([A-Z]{2})"`)
	matches := re.FindStringSubmatch(content)
	region := ""
	if len(matches) > 1 {
		region = matches[1]
	}

	// Both empty means page error
	if !isBlocked && region == "" {
		return "No"
	}

	if isBlocked {
		return "No"
	}

	if region != "" {
		return formatResult("Yes", region)
	}

	return "No"
}

// checkOpenAI checks OpenAI/ChatGPT availability
// Based on csm.sh MediaUnlockTest_OpenAI
func (c *Checker) checkOpenAI() string {
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
// Based on csm.sh MediaUnlockTest_Claude
func (c *Checker) checkClaude() string {
	// Request with exact headers from csm.sh
	req, err := http.NewRequest("GET", "https://claude.ai/", nil)
	if err != nil {
		return "Unknown"
	}

	req.Header.Set("User-Agent", UA_BROWSER)
	req.Header.Set("Authority", "claude.ai")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-Ch-Ua", UA_SEC_CH_UA)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Debugf("Claude check failed: %v", err)
		return "Unknown"
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Unknown"
	}

	content := string(body)

	// Check if blocked
	isBlocked := strings.Contains(strings.ToLower(content), "not available in your country") ||
		strings.Contains(strings.ToLower(content), "region restricted") ||
		strings.Contains(strings.ToLower(content), "access denied") ||
		strings.Contains(strings.ToLower(content), "blocked") ||
		strings.Contains(strings.ToLower(content), "unavailable")

	if isBlocked {
		return "No"
	}

	// Check if Claude/Anthropic is mentioned (page loaded correctly)
	isAvailable := strings.Contains(strings.ToLower(content), "claude") ||
		strings.Contains(strings.ToLower(content), "anthropic")

	// Try to extract region using multiple patterns like csm.sh
	region := ""

	// Method 1: "country":"XX"
	re1 := regexp.MustCompile(`"country":"([A-Z]{2})"`)
	if matches := re1.FindStringSubmatch(content); len(matches) > 1 {
		region = matches[1]
	}

	// Method 2: "countryCode":"XX"
	if region == "" {
		re2 := regexp.MustCompile(`"countryCode":"([A-Z]{2})"`)
		if matches := re2.FindStringSubmatch(content); len(matches) > 1 {
			region = matches[1]
		}
	}

	// Method 3: "location":"XX"
	if region == "" {
		re3 := regexp.MustCompile(`"location":"([A-Z]{2})"`)
		if matches := re3.FindStringSubmatch(content); len(matches) > 1 {
			region = matches[1]
		}
	}

	// Method 4: Fallback to IP API if region not found
	if region == "" && isAvailable {
		ipBody, _, err := c.httpGet("https://api.country.is", nil)
		if err == nil {
			reIP := regexp.MustCompile(`"country":"([A-Z]{2})"`)
			if matches := reIP.FindStringSubmatch(string(ipBody)); len(matches) > 1 {
				region = matches[1]
			}
		}
	}

	if isAvailable && region != "" {
		return formatResult("Yes", region)
	} else if isAvailable {
		// Try ip-api.com as final fallback
		ipBody, _, err := c.httpGet("http://ip-api.com/json", nil)
		if err == nil {
			reIP := regexp.MustCompile(`"countryCode":"([A-Z]{2})"`)
			if matches := reIP.FindStringSubmatch(string(ipBody)); len(matches) > 1 {
				return formatResult("Yes", matches[1])
			}
		}
		return "Yes"
	}

	return "No"
}
