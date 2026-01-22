package mediacheck

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// checkYouTubePremium checks YouTube Premium availability
// Based on csm.sh MediaUnlockTest_YouTube_Premium
func (c *Checker) checkYouTubePremium() string {
	// Request with specific headers and cookies like csm.sh
	req, err := http.NewRequest("GET", "https://www.youtube.com/premium", nil)
	if err != nil {
		return "Unknown"
	}

	req.Header.Set("User-Agent", UA_BROWSER)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cookie", "YSC=FSCWhKo2Zgw; VISITOR_PRIVACY_METADATA=CgJERRIEEgAgYQ%3D%3D; PREF=f7=4000; __Secure-YEC=CgtRWTBGTFExeV9Iayjele2yBjIKCgJERRIEEgAgYQ%3D%3D; SOCS=CAISOAgDEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjQwNTI2LjAxX3AwGgV6aC1DTiACGgYIgMnpsgY; VISITOR_INFO1_LIVE=Di84mAIbgKY; __Secure-BUCKET=CGQ")

	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Debugf("YouTube Premium check failed: %v", err)
		return "Unknown"
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
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

	// Extract region using the same pattern as csm.sh
	re := regexp.MustCompile(`"INNERTUBE_CONTEXT_GL"\s*:\s*"([A-Z]{2})"`)
	matches := re.FindStringSubmatch(content)
	region := ""
	if len(matches) > 1 {
		region = matches[1]
	}
	if region == "" {
		region = "UNKNOWN"
	}

	// Check if available (ad-free indicates Premium is available)
	if strings.Contains(strings.ToLower(content), "ad-free") {
		return formatResult("Yes", region)
	}

	return "No"
}

// checkNetflix checks Netflix availability
// Based on csm.sh MediaUnlockTest_Netflix
func (c *Checker) checkNetflix() string {
	headers := map[string]string{
		"Host":               "www.netflix.com",
		"Accept-Language":    "en-US,en;q=0.9",
		"Sec-Ch-Ua":          UA_SEC_CH_UA,
		"Sec-Ch-Ua-Mobile":   "?0",
		"Sec-Ch-Ua-Platform": `"Windows"`,
		"Sec-Fetch-Site":     "none",
		"Sec-Fetch-Mode":     "navigate",
		"Sec-Fetch-User":     "?1",
		"Sec-Fetch-Dest":     "document",
	}

	// Check LEGO Ninjago (self-produced content) - title/81280792
	_, code1, err1 := c.httpGetWithHeaders("https://www.netflix.com/title/81280792", headers)

	// Check Breaking Bad (licensed content) - title/70143836
	_, code2, err2 := c.httpGetWithHeaders("https://www.netflix.com/title/70143836", headers)

	// Network error
	if err1 != nil && err2 != nil {
		c.logger.Debugf("Netflix check failed: %v, %v", err1, err2)
		return "Unknown"
	}

	// Both 404 means only self-produced content (仅限自制)
	if code1 == 404 && code2 == 404 {
		return "No (仅限自制)"
	}

	// 403 means blocked
	if code1 == 403 || code2 == 403 {
		return "No"
	}

	// 200 means available - get region
	if code1 == 200 || code2 == 200 {
		body, _, err := c.httpGetWithHeaders("https://www.netflix.com/", headers)
		if err == nil {
			content := string(body)
			// Extract region: grep -oP '"id":"\K[^"]+' | grep -E '^[A-Z]{2}$'
			re := regexp.MustCompile(`"id":"([A-Z]{2})"`)
			matches := re.FindStringSubmatch(content)
			if len(matches) > 1 {
				return formatResult("Yes", matches[1])
			}
		}
		return "Yes"
	}

	return "Unknown"
}

// checkDisneyPlus checks Disney+ availability
// Based on csm.sh MediaUnlockTest_DisneyPlus
func (c *Checker) checkDisneyPlus() string {
	// Step 1: Get device assertion token
	deviceReq, err := http.NewRequest("POST", "https://disney.api.edge.bamgrid.com/devices", strings.NewReader(`{"deviceFamily":"browser","applicationRuntime":"chrome","deviceProfile":"windows","attributes":{}}`))
	if err != nil {
		return "Unknown"
	}

	deviceReq.Header.Set("User-Agent", UA_BROWSER)
	deviceReq.Header.Set("Authorization", "Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84")
	deviceReq.Header.Set("Content-Type", "application/json; charset=UTF-8")

	deviceResp, err := c.client.Do(deviceReq)
	if err != nil {
		c.logger.Debugf("Disney+ device check failed: %v", err)
		return "Unknown"
	}
	defer deviceResp.Body.Close()

	deviceBody, _ := io.ReadAll(deviceResp.Body)
	var deviceResult map[string]interface{}
	if err := json.Unmarshal(deviceBody, &deviceResult); err != nil {
		return "Unknown"
	}

	assertion, ok := deviceResult["assertion"].(string)
	if !ok || assertion == "" {
		return "Unknown"
	}

	// Step 2: Get token with assertion
	tokenData := "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&latitude=0&longitude=0&platform=browser&subject_token=" + assertion + "&subject_token_type=urn%3Abamtech%3Aparams%3Aoauth%3Atoken-type%3Adevice"
	tokenReq, err := http.NewRequest("POST", "https://disney.api.edge.bamgrid.com/token", strings.NewReader(tokenData))
	if err != nil {
		return "Unknown"
	}

	tokenReq.Header.Set("User-Agent", UA_BROWSER)
	tokenReq.Header.Set("Authorization", "Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84")
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := c.client.Do(tokenReq)
	if err != nil {
		return "Unknown"
	}
	defer tokenResp.Body.Close()

	tokenBody, _ := io.ReadAll(tokenResp.Body)
	tokenContent := string(tokenBody)

	// Check if banned
	if strings.Contains(tokenContent, "forbidden-location") || strings.Contains(tokenContent, "403 ERROR") {
		return "No"
	}

	var tokenResult map[string]interface{}
	if err := json.Unmarshal(tokenBody, &tokenResult); err != nil {
		return "Unknown"
	}

	refreshToken, ok := tokenResult["refresh_token"].(string)
	if !ok || refreshToken == "" {
		return "No"
	}

	// Step 3: GraphQL query for region info
	graphqlData := `{"query":"mutation refreshToken($input: RefreshTokenInput!) { refreshToken(refreshToken: $input) { activeSession { sessionId } } }","variables":{"input":{"refreshToken":"` + refreshToken + `"}}}`
	graphqlReq, err := http.NewRequest("POST", "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql", strings.NewReader(graphqlData))
	if err != nil {
		return "Unknown"
	}

	graphqlReq.Header.Set("User-Agent", UA_BROWSER)
	graphqlReq.Header.Set("Authorization", "ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84")
	graphqlReq.Header.Set("Content-Type", "application/json")

	graphqlResp, err := c.client.Do(graphqlReq)
	if err != nil {
		return "Unknown"
	}
	defer graphqlResp.Body.Close()

	graphqlBody, _ := io.ReadAll(graphqlResp.Body)
	graphqlContent := string(graphqlBody)

	// Extract countryCode
	re := regexp.MustCompile(`"countryCode"\s*:\s*"([A-Z]{2})"`)
	matches := re.FindStringSubmatch(graphqlContent)
	region := ""
	if len(matches) > 1 {
		region = matches[1]
	}

	// Check inSupportedLocation
	inSupportedLocation := strings.Contains(graphqlContent, `"inSupportedLocation":true`)

	// Check preview/unavailable
	previewBody, _, _ := c.httpGet("https://disneyplus.com/", nil)
	isUnavailable := strings.Contains(string(previewBody), "unavailable")

	// JP is always available
	if region == "JP" {
		return formatResult("Yes", "JP")
	}

	if region != "" && !inSupportedLocation && !isUnavailable {
		return "No" // Available soon but not now
	}

	if region != "" && isUnavailable {
		return "No"
	}

	if region != "" && inSupportedLocation {
		return formatResult("Yes", region)
	}

	return "No"
}

// checkHBOMax checks HBO Max availability
// Based on csm.sh MediaUnlockTest_HBOMax
func (c *Checker) checkHBOMax() string {
	body, code, err := c.httpGet("https://www.max.com/", nil)
	if err != nil || code == 0 {
		c.logger.Debugf("HBO Max check failed: %v", err)
		return "Unknown"
	}

	content := string(body)

	// Extract available country list from page
	re := regexp.MustCompile(`"url":"/([a-z]{2})/[a-z]{2}"`)
	matches := re.FindAllStringSubmatch(content, -1)
	countrySet := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 {
			countrySet[strings.ToUpper(m[1])] = true
		}
	}
	countrySet["US"] = true // US is always in the list

	// Extract region
	reRegion := regexp.MustCompile(`countryCode=([A-Z]{2})`)
	regionMatches := reRegion.FindStringSubmatch(content)
	region := ""
	if len(regionMatches) > 1 {
		region = regionMatches[1]
	}

	if region == "" {
		return "Unknown"
	}

	if countrySet[region] {
		return formatResult("Yes", region)
	}

	return "No"
}

// checkTikTok checks TikTok availability
// Based on https://github.com/lmc999/TikTokCheck/blob/main/tiktok.sh
func (c *Checker) checkTikTok() string {
	// First attempt: simple request
	req1, err := http.NewRequest("GET", "https://www.tiktok.com/", nil)
	if err != nil {
		return "Unknown"
	}
	req1.Header.Set("User-Agent", UA_BROWSER)

	resp1, err := c.client.Do(req1)
	if err != nil {
		c.logger.Debugf("TikTok check failed: %v", err)
		return "Unknown"
	}
	defer resp1.Body.Close()

	body1, err := io.ReadAll(resp1.Body)
	if err != nil {
		return "Unknown"
	}

	content1 := string(body1)

	// Extract region from first attempt
	re := regexp.MustCompile(`"region":"([A-Z]{2})"`)
	matches := re.FindStringSubmatch(content1)
	if len(matches) > 1 {
		return formatResult("Yes", matches[1])
	}

	// Second attempt: with Accept headers and gzip (for IDC IPs)
	req2, err := http.NewRequest("GET", "https://www.tiktok.com/", nil)
	if err != nil {
		return "No"
	}
	req2.Header.Set("User-Agent", UA_BROWSER)
	req2.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req2.Header.Set("Accept-Encoding", "gzip")
	req2.Header.Set("Accept-Language", "en")

	resp2, err := c.client.Do(req2)
	if err != nil {
		return "No"
	}
	defer resp2.Body.Close()

	var body2 []byte
	// Check if response is gzip encoded
	if resp2.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp2.Body)
		if err != nil {
			return "No"
		}
		defer gzReader.Close()
		body2, err = io.ReadAll(gzReader)
		if err != nil {
			return "No"
		}
	} else {
		body2, err = io.ReadAll(resp2.Body)
		if err != nil {
			return "No"
		}
	}

	content2 := string(body2)

	// Extract region from second attempt (IDC IP)
	matches2 := re.FindStringSubmatch(content2)
	if len(matches2) > 1 {
		// IDC IP detected, still works but might be flagged
		return formatResult("Yes", matches2[1]) + " (IDC)"
	}

	return "No"
}
