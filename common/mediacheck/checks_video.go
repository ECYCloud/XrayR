package mediacheck

import (
	"strings"
)

// checkYouTubePremium checks YouTube Premium availability
func (c *Checker) checkYouTubePremium() string {
	body, _, err := c.httpGet("https://www.youtube.com/premium", nil)
	if err != nil {
		c.logger.Debugf("YouTube Premium check failed: %v", err)
		return "Unknown"
	}

	content := string(body)

	// Check if redirected to China
	if strings.Contains(content, "www.google.cn") {
		return "No (CN)"
	}

	// Check if Premium is not available
	if strings.Contains(strings.ToLower(content), "premium is not available in your country") {
		return "No"
	}

	// Extract region
	region := extractRegion(content, `"INNERTUBE_CONTEXT_GL"\s*:\s*"([A-Z]{2})"`)
	if region == "" {
		region = "UNKNOWN"
	}

	// Check if available
	if strings.Contains(strings.ToLower(content), "ad-free") {
		return formatResult("Yes", region)
	}

	return "No"
}

// checkNetflix checks Netflix availability
func (c *Checker) checkNetflix() string {
	// Check LEGO Ninjago (self-produced content)
	_, code1, err1 := c.httpGet("https://www.netflix.com/title/81280792", map[string]string{
		"Host": "www.netflix.com",
	})
	if err1 != nil {
		c.logger.Debugf("Netflix check failed: %v", err1)
		return "Unknown"
	}

	// Check Breaking Bad (licensed content)
	_, code2, err2 := c.httpGet("https://www.netflix.com/title/70143836", map[string]string{
		"Host": "www.netflix.com",
	})
	if err2 != nil {
		c.logger.Debugf("Netflix check failed: %v", err2)
		return "Unknown"
	}

	// Both 404 means only self-produced content
	if code1 == 404 && code2 == 404 {
		return "No (Originals Only)"
	}

	// 403 means blocked
	if code1 == 403 || code2 == 403 {
		return "No"
	}

	// 200 means available
	if code1 == 200 || code2 == 200 {
		// Get region from main page
		body, _, err := c.httpGet("https://www.netflix.com/", nil)
		if err == nil {
			region := extractRegion(string(body), `"id":"([A-Z]{2})"`)
			if region != "" {
				return formatResult("Yes", region)
			}
		}
		return "Yes"
	}

	return "Unknown"
}

// checkDisneyPlus checks Disney+ availability
func (c *Checker) checkDisneyPlus() string {
	// Check if Disney+ is available by checking the main page redirect
	body, code, err := c.httpGet("https://www.disneyplus.com/", nil)
	if err != nil {
		c.logger.Debugf("Disney+ check failed: %v", err)
		return "Unknown"
	}

	content := string(body)

	// Check for unavailable or preview
	if strings.Contains(content, "unavailable") || strings.Contains(content, "preview") {
		return "No"
	}

	// Check for forbidden
	if code == 403 {
		return "No"
	}

	// Try to extract region
	region := extractRegion(content, `"countryCode":"([A-Z]{2})"`)
	if region == "" {
		region = extractRegion(content, `"country":"([A-Z]{2})"`)
	}

	if region != "" {
		return formatResult("Yes", region)
	}

	// If we got a 200 response, assume it's available
	if code == 200 {
		return "Yes"
	}

	return "Unknown"
}

// checkHBOMax checks HBO Max availability
func (c *Checker) checkHBOMax() string {
	body, code, err := c.httpGet("https://www.max.com/", nil)
	if err != nil {
		c.logger.Debugf("HBO Max check failed: %v", err)
		return "Unknown"
	}

	if code == 403 {
		return "No"
	}

	content := string(body)
	region := extractRegion(content, `countryCode=([A-Z]{2})`)

	// List of supported countries
	supportedCountries := "AD AR AT BA BE BG BO BR CL CO CR CZ DE DK DO EC EE ES FI FR GB GR GT HN HR HU IS IT LT LV ME MK MT MX NI NL NO PA PE PL PT PY RO RS SE SI SK SV US UY XK"

	if region != "" {
		if strings.Contains(supportedCountries, region) {
			return formatResult("Yes", region)
		}
		return "No"
	}

	return "Unknown"
}

