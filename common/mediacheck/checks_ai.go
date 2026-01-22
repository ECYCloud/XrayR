package mediacheck

import (
	"strings"
)

// checkAmazonPrime checks Amazon Prime Video availability
func (c *Checker) checkAmazonPrime() string {
	body, _, err := c.httpGet("https://www.primevideo.com/", nil)
	if err != nil {
		c.logger.Debugf("Amazon Prime check failed: %v", err)
		return "Unknown"
	}

	content := string(body)

	// Check if service is restricted
	if strings.Contains(content, "isServiceRestricted") {
		return "No"
	}

	// Extract region
	region := extractRegion(content, `"currentTerritory":"([A-Z]{2})"`)
	if region != "" {
		return formatResult("Yes", region)
	}

	return "Unknown"
}

// checkOpenAI checks OpenAI/ChatGPT availability
func (c *Checker) checkOpenAI() string {
	// Check compliance API
	body1, _, err1 := c.httpGet("https://api.openai.com/compliance/cookie_requirements", map[string]string{
		"Authorization": "Bearer null",
		"Content-Type":  "application/json",
		"Origin":        "https://platform.openai.com",
		"Referer":       "https://platform.openai.com/",
	})

	// Check iOS endpoint
	body2, _, err2 := c.httpGet("https://ios.chat.openai.com/", nil)

	if err1 != nil && err2 != nil {
		c.logger.Debugf("OpenAI check failed: %v, %v", err1, err2)
		return "Unknown"
	}

	content1 := string(body1)
	content2 := string(body2)

	// Check if blocked
	if strings.Contains(strings.ToLower(content1), "unsupported_country") ||
		strings.Contains(strings.ToLower(content2), "vpn") {
		return "No"
	}

	// Get region from Cloudflare trace
	traceBody, _, err := c.httpGet("https://chat.openai.com/cdn-cgi/trace", nil)
	if err == nil {
		content := string(traceBody)
		region := extractRegion(content, `loc=([A-Z]{2})`)
		if region != "" {
			// Check if region is supported
			supportedCountries := "AL DZ AD AO AG AR AM AU AT AZ BS BD BB BE BZ BJ BT BO BA BW BR BN BG BF CV CA CL CO KM CG CR CI HR CY CZ DK DJ DM DO EC SV EE EG FJ FI FR GA GM GE DE GH GR GD GT GN GW GY HT VA HN HU IS IN ID IQ IE IL IT JM JP JO KZ KE KI KW KG LV LB LS LR LI LT LU MG MW MY MV ML MT MH MR MU MX FM MD MC MN ME MA MZ MM NA NR NP NL NZ NI NE NG MK NO OM PK PW PS PA PG PY PE PH PL PT QA RO RW KN LC VC WS SM ST SN RS SC SL SG SK SI SB ZA KR ES LK SR SE CH TW TZ TH TL TG TO TT TN TR TV UG UA AE GB US UY VU ZM"
			if strings.Contains(supportedCountries, region) {
				return formatResult("Yes", region)
			}
			return "No"
		}
	}

	return "Unknown"
}

// checkGemini checks Google Gemini availability
func (c *Checker) checkGemini() string {
	body, _, err := c.httpGet("https://gemini.google.com/", nil)
	if err != nil {
		c.logger.Debugf("Gemini check failed: %v", err)
		return "Unknown"
	}

	content := string(body)

	// Check if available
	if strings.Contains(content, "45631641,null,true") {
		region := extractRegion(content, `,2,1,200,"([A-Z]{3})"`)
		if region != "" && len(region) >= 2 {
			region = region[:2]
			return formatResult("Yes", region)
		}
		return "Yes"
	}

	return "No"
}

// checkClaude checks Claude AI availability
func (c *Checker) checkClaude() string {
	body, _, err := c.httpGet("https://claude.ai/", nil)
	if err != nil {
		c.logger.Debugf("Claude check failed: %v", err)
		return "Unknown"
	}

	content := string(body)

	// Check if blocked
	blockedKeywords := []string{"not available in your country", "region restricted", "access denied", "blocked", "unavailable"}
	for _, keyword := range blockedKeywords {
		if strings.Contains(strings.ToLower(content), keyword) {
			return "No"
		}
	}

	// Check if Claude/Anthropic is mentioned (indicates page loaded correctly)
	if strings.Contains(strings.ToLower(content), "claude") || strings.Contains(strings.ToLower(content), "anthropic") {
		// Try to get region
		region := extractRegion(content, `"country":"([A-Z]{2})"`)
		if region == "" {
			region = extractRegion(content, `"countryCode":"([A-Z]{2})"`)
		}
		if region != "" {
			return formatResult("Yes", region)
		}
		return "Yes"
	}

	return "No"
}

// checkTikTok checks TikTok availability
func (c *Checker) checkTikTok() string {
	body, _, err := c.httpGet("https://www.tiktok.com/", nil)
	if err != nil {
		c.logger.Debugf("TikTok check failed: %v", err)
		return "Unknown"
	}

	content := string(body)
	region := extractRegion(content, `"region":"([A-Z]{2})"`)

	if region != "" {
		return formatResult("Yes", region)
	}

	return "No"
}

