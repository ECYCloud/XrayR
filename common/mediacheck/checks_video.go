package mediacheck

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Netflix cookies from csm.sh for better detection accuracy
const netflixCookies = "flwssn=d2c72c47-49e9-48da-b7a2-2dc6d7ca9fcf; nfvdid=BQFmAAEBEMZa4XMYVzVGf9-kQ1HXumtAKsCyuBZU4QStC6CGEGIVznjNuuTerLAG8v2-9V_kYhg5uxTB5_yyrmqc02U5l1Ts74Qquezc9AE-LZKTo3kY3g%3D%3D; SecureNetflixId=v%3D3%26mac%3DAQEAEQABABSQHKcR1d0sLV0WTu0lL-BO63TKCCHAkeY.%26dt%3D1745376277212; NetflixId=v%3D3%26ct%3DBgjHlOvcAxLAAZuNS4_CJHy9NKJPzUV-9gElzTlTsmDS1B59TycR-fue7f6q7X9JQAOLttD7OnlldUtnYWXL7VUfu9q4pA0gruZKVIhScTYI1GKbyiEqKaULAXOt0PHQzgRLVTNVoXkxcbu7MYG4wm1870fZkd5qrDOEseZv2WIVk4xIeNL87EZh1vS3RZU3e-qWy2tSmfSNUC-FVDGwxbI6-hk3Zg2MbcWYd70-ghohcCSZp5WHAGXg_xWVC7FHM3aOUVTGwRCU1RgGIg4KDKGr_wsTRRw6HWKqeA..; gsid=09bb180e-fbb1-4bf6-adcb-a3fa1236e323"

// checkYouTubePremium checks YouTube Premium availability
// Based on csm.sh MediaUnlockTest_YouTube_Premium
func (c *Checker) checkYouTubePremium() string {
	// Retry up to 3 times for consistency
	for retry := 0; retry < 3; retry++ {
		result := c.doCheckYouTubePremium()
		if result != "Unknown" {
			return result
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "Unknown"
}

func (c *Checker) doCheckYouTubePremium() string {
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
// Based on csm.sh MediaUnlockTest_Netflix with full cookies and headers
func (c *Checker) checkNetflix() string {
	// Retry up to 3 times for consistency
	for retry := 0; retry < 3; retry++ {
		result := c.doCheckNetflix()
		if result != "Unknown" {
			return result
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "Unknown"
}

func (c *Checker) doCheckNetflix() string {
	// Full headers matching csm.sh exactly
	headers := map[string]string{
		"Accept":                     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Accept-Language":            "en-US,en;q=0.9",
		"Cookie":                     netflixCookies,
		"Priority":                   "u=0, i",
		"Sec-Ch-Ua":                  `"Microsoft Edge";v="135", "Not-A.Brand";v="8", "Chromium";v="135"`,
		"Sec-Ch-Ua-Mobile":           "?0",
		"Sec-Ch-Ua-Model":            `""`,
		"Sec-Ch-Ua-Platform":         `"Windows"`,
		"Sec-Ch-Ua-Platform-Version": `"15.0.0"`,
		"Sec-Fetch-Dest":             "document",
		"Sec-Fetch-Mode":             "navigate",
		"Sec-Fetch-Site":             "none",
		"Sec-Fetch-User":             "?1",
		"Upgrade-Insecure-Requests":  "1",
	}

	// Check LEGO Ninjago (self-produced content) - title/81280792
	body1, _, err1 := c.httpGetWithHeaders("https://www.netflix.com/title/81280792", headers)
	content1 := string(body1)

	// Check Breaking Bad (licensed content) - title/70143836
	body2, _, err2 := c.httpGetWithHeaders("https://www.netflix.com/title/70143836", headers)
	content2 := string(body2)

	// Network error
	if err1 != nil && err2 != nil {
		c.logger.Debugf("Netflix check failed: %v, %v", err1, err2)
		return "Unknown"
	}

	// Check for "Oh no!" which indicates content is not available
	result1HasOhNo := strings.Contains(content1, "Oh no!")
	result2HasOhNo := strings.Contains(content2, "Oh no!")

	// Both have "Oh no!" means only originals (self-produced content only)
	if result1HasOhNo && result2HasOhNo {
		return "Originals Only"
	}

	// At least one doesn't have "Oh no!" means full access
	if !result1HasOhNo || !result2HasOhNo {
		// Extract region from response
		// Pattern: "id":"XX" where XX is country code followed by "countryName"
		re := regexp.MustCompile(`"id":"([A-Z]{2})"[^}]*"countryName"`)
		matches := re.FindStringSubmatch(content1)
		if len(matches) > 1 {
			return formatResult("Yes", matches[1])
		}
		// Fallback pattern
		re2 := regexp.MustCompile(`"id":"([A-Z]{2})"`)
		matches2 := re2.FindStringSubmatch(content1)
		if len(matches2) > 1 {
			return formatResult("Yes", matches2[1])
		}
		return "Yes"
	}

	return "Unknown"
}

// checkDisneyPlus checks Disney+ availability
// Based on csm.sh MediaUnlockTest_DisneyPlus
func (c *Checker) checkDisneyPlus() string {
	// Retry up to 3 times for consistency
	for retry := 0; retry < 3; retry++ {
		result := c.doCheckDisneyPlus()
		if result != "Unknown" {
			return result
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "Unknown"
}

func (c *Checker) doCheckDisneyPlus() string {
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

	// Check for 403 ERROR first
	deviceBody, _ := io.ReadAll(deviceResp.Body)
	deviceContent := string(deviceBody)
	if strings.Contains(deviceContent, "403 ERROR") {
		return "No (IP Banned)"
	}

	var deviceResult map[string]any
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

	var tokenResult map[string]any
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
	// Retry up to 3 times for consistency
	for retry := 0; retry < 3; retry++ {
		result := c.doCheckHBOMax()
		if result != "Unknown" {
			return result
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "Unknown"
}

func (c *Checker) doCheckHBOMax() string {
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
	// Retry up to 3 times for consistency
	for retry := 0; retry < 3; retry++ {
		result := c.doCheckTikTok()
		if result != "Unknown" {
			return result
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "Unknown"
}

func (c *Checker) doCheckTikTok() string {
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
