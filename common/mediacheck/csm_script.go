// Package mediacheck provides streaming media unlock detection functionality.
// This file contains the embedded csm.sh script for local execution.
// Script source: https://github.com/ECYCloud/check-stream-media
// All detection logic is embedded locally, no remote download required.
package mediacheck

// CSM_SCRIPT contains the complete csm.sh script for media unlock detection.
// This script is executed locally without downloading from remote.
// The script only runs the detection part (runCheck) and outputs JSON results.
const CSM_SCRIPT = `#!/bin/bash
shopt -s expand_aliases

# Disable color output for parsing
Font_Black=""
Font_Red=""
Font_Green=""
Font_Yellow=""
Font_Blue=""
Font_Purple=""
Font_SkyBlue=""
Font_White=""
Font_Suffix=""

UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36"
UA_BROWSER="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36"
UA_SEC_CH_UA='"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"'
UA_Dalvik="Dalvik/2.1.0 (Linux; U; Android 9; ALP-AL00 Build/HUAWEIALP-AL00)"
CURL_DEFAULT_OPTS="-s --max-time 10"

# Disney+ cookies embedded locally (no remote download)
# Line 1: Disney assertion cookie
DISNEY_COOKIE_1='grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&latitude=0&longitude=0&platform=browser&subject_token=DISNEYASSERTION&subject_token_type=urn%3Abamtech%3Aparams%3Aoauth%3Atoken-type%3Adevice'
# Line 8: Disney refresh token cookie
DISNEY_COOKIE_8='{"query":"mutation refreshToken($input: RefreshTokenInput!) {\n            refreshToken(refreshToken: $input) {\n                activeSession {\n                    sessionId\n                }\n            }\n        }","variables":{"input":{"refreshToken":"ILOVEDISNEY"}}}'

# Result JSON file path
RESULT_FILE="/tmp/xrayr_media_check_result.json"

# Create JSON template
createJsonTemplate() {
    echo '{
    "YouTube": "YouTube_Premium_result",
    "Netflix": "Netflix_result",
    "DisneyPlus": "DisneyPlus_result",
    "HBOMax": "HBOMax_result",
    "AmazonPrime": "AmazonPrime_result",
    "OpenAI": "OpenAI_result",
    "Gemini": "Gemini_result",
    "Claude": "Claude_result",
    "TikTok": "TikTok_result"
}' > "$RESULT_FILE"
}

# Modify JSON template
modifyJsonTemplate() {
    key_word=$1
    result=$2
    region=$3

    if [[ "$3" == "" ]]; then
        sed -i "s#${key_word}#${result}#g" "$RESULT_FILE"
    else
        sed -i "s#${key_word}#${result} (${region})#g" "$RESULT_FILE"
    fi
}

# Netflix check - 100% same as csm.sh
MediaUnlockTest_Netflix() {
    local result1=$(curl ${CURL_DEFAULT_OPTS} -fsL 'https://www.netflix.com/title/81280792' -w %{http_code} -o /dev/null -H 'host: www.netflix.com' -H 'accept-language: en-US,en;q=0.9' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${UA_BROWSER}")
    local result2=$(curl ${CURL_DEFAULT_OPTS} -fsL 'https://www.netflix.com/title/70143836' -w %{http_code} -o /dev/null -H 'host: www.netflix.com' -H 'accept-language: en-US,en;q=0.9' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${UA_BROWSER}")

    if [ "${result1}" == '000' ] || [ "$result2" == '000' ]; then
        modifyJsonTemplate 'Netflix_result' 'Unknown'
        return
    fi
    if [ "$result1" == '404' ] && [ "$result2" == '404' ]; then
        modifyJsonTemplate 'Netflix_result' 'No (仅限自制)'
        return
    fi
    if [ "$result1" == '403' ] || [ "$result2" == '403' ]; then
        modifyJsonTemplate 'Netflix_result' 'No'
        return
    fi
    if [ "$result1" == '200' ] || [ "$result2" == '200' ]; then
        local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.netflix.com/' -H 'accept-language: en-US,en;q=0.9' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${UA_BROWSER}")
        local region=$(echo "$tmpresult" | grep -oP '"id":"\K[^"]+' | grep -E '^[A-Z]{2}$' | head -n 1)
        modifyJsonTemplate 'Netflix_result' 'Yes' "${region}"
        return
    fi
    modifyJsonTemplate 'Netflix_result' 'Failed' "${result1}_${result2}"
}

# YouTube Premium check - 100% same as csm.sh
MediaUnlockTest_YouTube_Premium() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.youtube.com/premium' -H 'accept-language: en-US,en;q=0.9' -H 'cookie: YSC=FSCWhKo2Zgw; VISITOR_PRIVACY_METADATA=CgJERRIEEgAgYQ%3D%3D; PREF=f7=4000; __Secure-YEC=CgtRWTBGTFExeV9Iayjele2yBjIKCgJERRIEEgAgYQ%3D%3D; SOCS=CAISOAgDEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjQwNTI2LjAxX3AwGgV6aC1DTiACGgYIgMnpsgY; VISITOR_INFO1_LIVE=Di84mAIbgKY; __Secure-BUCKET=CGQ' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        modifyJsonTemplate 'YouTube_Premium_result' 'Unknown'
        return
    fi

    local isCN=$(echo "$tmpresult" | grep 'www.google.cn')
    if [ -n "$isCN" ]; then
        modifyJsonTemplate 'YouTube_Premium_result' 'No' 'CN'
        return
    fi

    local isNotAvailable=$(echo "$tmpresult" | grep -i 'Premium is not available in your country')
    local region=$(echo "$tmpresult" | grep -woP '"INNERTUBE_CONTEXT_GL"\s{0,}:\s{0,}"\K[^"]+')
    local isAvailable=$(echo "$tmpresult" | grep -i 'ad-free')

    if [ -n "$isNotAvailable" ]; then
        modifyJsonTemplate 'YouTube_Premium_result' 'No'
        return
    fi
    if [ -z "$region" ]; then
        local region='UNKNOWN'
    fi
    if [ -n "$isAvailable" ]; then
        modifyJsonTemplate 'YouTube_Premium_result' 'Yes' "${region}"
        return
    fi
    modifyJsonTemplate 'YouTube_Premium_result' 'Unknown'
}

# Disney+ check - 100% same as csm.sh
MediaUnlockTest_DisneyPlus() {
    # Step 1: Get PreAssertion from /devices API
    local PreAssertion=$(curl -4 --user-agent "${UA_Browser}" -s --max-time 10 -X POST "https://disney.api.edge.bamgrid.com/devices" -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -H "content-type: application/json; charset=UTF-8" -d '{"deviceFamily":"browser","applicationRuntime":"chrome","deviceProfile":"windows","attributes":{}}' 2>&1)
    if [[ "$PreAssertion" == "curl"* ]]; then
        modifyJsonTemplate 'DisneyPlus_result' 'Unknown'
        return
    fi

    # Step 2: Extract assertion and get TokenContent using DISNEY_COOKIE_1
    local assertion=$(echo $PreAssertion | python -m json.tool 2>/dev/null | grep assertion | cut -f4 -d'"')
    local disneycookie=$(echo "$DISNEY_COOKIE_1" | sed "s/DISNEYASSERTION/${assertion}/g")
    local TokenContent=$(curl -4 --user-agent "${UA_Browser}" -s --max-time 10 -X POST "https://disney.api.edge.bamgrid.com/token" -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "$disneycookie" 2>&1)
    local isBanned=$(echo $TokenContent | python -m json.tool 2>/dev/null | grep 'forbidden-location')
    local is403=$(echo $TokenContent | grep '403 ERROR')

    if [ -n "$isBanned" ] || [ -n "$is403" ]; then
        modifyJsonTemplate 'DisneyPlus_result' 'No'
        return
    fi

    # Step 3: Get refresh_token and query GraphQL using DISNEY_COOKIE_8
    local fakecontent="$DISNEY_COOKIE_8"
    local refreshToken=$(echo $TokenContent | python -m json.tool 2>/dev/null | grep 'refresh_token' | awk '{print $2}' | cut -f2 -d'"')
    local disneycontent=$(echo "$fakecontent" | sed "s/ILOVEDISNEY/${refreshToken}/g")
    local tmpresult=$(curl -4 --user-agent "${UA_Browser}" -X POST -sSL --max-time 10 "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql" -H "authorization: ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "$disneycontent" 2>&1)
    local previewcheck=$(curl -4 -s -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://disneyplus.com" | grep preview)
    local isUnabailable=$(echo $previewcheck | grep 'unavailable')
    local region=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'countryCode' | cut -f4 -d'"')
    local inSupportedLocation=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'inSupportedLocation' | awk '{print $2}' | cut -f1 -d',')

    if [[ "$region" == "JP" ]]; then
        modifyJsonTemplate 'DisneyPlus_result' 'Yes' 'JP'
        return
    elif [ -n "$region" ] && [[ "$inSupportedLocation" == "false" ]] && [ -z "$isUnabailable" ]; then
        modifyJsonTemplate 'DisneyPlus_result' 'No'
        return
    elif [ -n "$region" ] && [ -n "$isUnabailable" ]; then
        modifyJsonTemplate 'DisneyPlus_result' 'No'
        return
    elif [ -n "$region" ] && [[ "$inSupportedLocation" == "true" ]]; then
        modifyJsonTemplate 'DisneyPlus_result' 'Yes' "${region}"
        return
    elif [ -z "$region" ]; then
        modifyJsonTemplate 'DisneyPlus_result' 'No'
        return
    else
        modifyJsonTemplate 'DisneyPlus_result' 'Unknown'
        return
    fi
}

# HBO Max check - 100% same as csm.sh
MediaUnlockTest_HBOMax() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sLi 'https://www.max.com/' -w "_TAG_%{http_code}_TAG_" --user-agent "${UA_Browser}")
    local httpCode=$(echo "$tmpresult" | grep '_TAG_' | awk -F'_TAG_' '{print $2}')
    if [ "$httpCode" == '000' ]; then
        modifyJsonTemplate 'HBOMax_result' 'Unknown'
        return
    fi

    local countryList=$(echo "$tmpresult" | grep -woP '"url":"/[a-z]{2}/[a-z]{2}"' | cut -f4 -d'"' | cut -f2 -d'/' | sort -n | uniq | xargs | tr a-z A-Z)
    local countryList="${countryList} US"
    local region=$(echo "$tmpresult" | grep -woP 'countryCode=\K[A-Z]{2}' | head -n 1)
    local isUnavailable=$(echo "$countryList" | grep "$region")

    if [ -z "$region" ]; then
        modifyJsonTemplate 'HBOMax_result' 'Unknown'
        return
    fi
    if [ -n "$isUnavailable" ]; then
        modifyJsonTemplate 'HBOMax_result' 'Yes' "${region}"
        return
    fi
    modifyJsonTemplate 'HBOMax_result' 'No'
}

# Amazon Prime Video check - 100% same as csm.sh
MediaUnlockTest_PrimeVideo() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.primevideo.com' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        modifyJsonTemplate 'AmazonPrime_result' 'Unknown'
        return
    fi

    local isBlocked=$(echo "$tmpresult" | grep -i 'isServiceRestricted')
    local region=$(echo "$tmpresult" | grep -woP '"currentTerritory":"\K[^"]+' | head -n 1)

    if [ -z "$isBlocked" ] && [ -z "$region" ]; then
        modifyJsonTemplate 'AmazonPrime_result' 'No'
        return
    fi
    if [ -n "$isBlocked" ]; then
        modifyJsonTemplate 'AmazonPrime_result' 'No'
        return
    fi
    if [ -n "$region" ]; then
        modifyJsonTemplate 'AmazonPrime_result' 'Yes' "${region}"
        return
    fi
    modifyJsonTemplate 'AmazonPrime_result' 'No'
}

# OpenAI check - 100% same as csm.sh
MediaUnlockTest_OpenAI() {
    SUPPORT_COUNTRY=(AL DZ AD AO AG AR AM AU AT AZ BS BD BB BE BZ BJ BT BO BA BW BR BN BG BF CV CA CL CO KM CG CR CI HR CY CZ DK DJ DM DO EC SV EE EG FJ FI FR GA GM GE DE GH GR GD GT GN GW GY HT VA HN HU IS IN ID IQ IE IL IT JM JP JO KZ KE KI KW KG LV LB LS LR LI LT LU MG MW MY MV ML MT MH MR MU MX FM MD MC MN ME MA MZ MM NA NR NP NL NZ NI NE NG MK NO OM PK PW PS PA PG PY PE PH PL PT QA RO RW KN LC VC WS SM ST SN RS SC SL SG SK SI SB ZA KR ES LK SR SE CH TW TZ TH TL TG TO TT TN TR TV UG UA AE GB US UY VU ZM)

    local tmpresult1=$(curl ${CURL_DEFAULT_OPTS} -s 'https://api.openai.com/compliance/cookie_requirements' -H 'authority: api.openai.com' -H 'accept: */*' -H 'accept-language: en-US,en;q=0.9' -H 'authorization: Bearer null' -H 'content-type: application/json' -H 'origin: https://platform.openai.com' -H 'referer: https://platform.openai.com/' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-dest: empty' -H 'sec-fetch-mode: cors' -H 'sec-fetch-site: same-site' --user-agent "${UA_BROWSER}")
    local tmpresult2=$(curl ${CURL_DEFAULT_OPTS} -s 'https://ios.chat.openai.com/' -H 'authority: ios.chat.openai.com' -H 'accept: */*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H 'accept-language: en-US,en;q=0.9' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-dest: document' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-site: none' -H 'sec-fetch-user: ?1' -H 'upgrade-insecure-requests: 1' --user-agent "${UA_BROWSER}")

    if [ -z "$tmpresult1" ] || [ -z "$tmpresult2" ]; then
        modifyJsonTemplate 'OpenAI_result' 'Unknown'
        return
    fi

    local result1=$(echo "$tmpresult1" | grep -i 'unsupported_country')
    local result2=$(echo "$tmpresult2" | grep -i 'VPN')

    # Get region from OpenAI CDN trace (same as original csm.sh)
    local iso2_code=$(curl -4 -sS --max-time 5 https://chat.openai.com/cdn-cgi/trace | grep "loc=" | awk -F= '{print $2}')

    if [ -n "$result1" ] || [ -n "$result2" ] || [ "$iso2_code" == "HK" ] || [ "$iso2_code" == "RU" ]; then
        modifyJsonTemplate 'OpenAI_result' 'No'
        return
    fi

    if [ -z "$iso2_code" ]; then
        iso2_code="UNKNOWN"
    fi

    if [[ " ${SUPPORT_COUNTRY[@]} " =~ " ${iso2_code} " ]]; then
        modifyJsonTemplate 'OpenAI_result' 'Yes' "${iso2_code}"
        return
    else
        modifyJsonTemplate 'OpenAI_result' 'No'
        return
    fi

    modifyJsonTemplate 'OpenAI_result' 'Unknown'
}

# Google Gemini check - 100% same as csm.sh
MediaUnlockTest_Gemini() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL "https://gemini.google.com" --user-agent "${UA_BROWSER}")
    if [[ "$tmpresult" = "curl"* ]] || [ -z "$tmpresult" ]; then
        modifyJsonTemplate 'Gemini_result' 'Unknown'
        return
    fi

    local result=$(echo "$tmpresult" | grep -q '45631641,null,true' && echo "Yes" || echo "")
    local countrycode=$(echo "$tmpresult" | grep -o ',2,1,200,"[A-Z]\{3\}"' | sed 's/,2,1,200,"//;s/"//' || echo "")

    if [ -n "$result" ] && [ -n "$countrycode" ]; then
        countrycode=$(echo "$countrycode" | cut -c1-2)
        modifyJsonTemplate 'Gemini_result' 'Yes' "${countrycode}"
    elif [ -n "$result" ]; then
        modifyJsonTemplate 'Gemini_result' 'Yes'
    else
        modifyJsonTemplate 'Gemini_result' 'No'
    fi
}

# Claude check - 100% same as csm.sh
MediaUnlockTest_Claude() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://claude.ai/' -H 'authority: claude.ai' -H 'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H 'accept-language: en-US,en;q=0.9' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-dest: document' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-site: none' -H 'sec-fetch-user: ?1' -H 'upgrade-insecure-requests: 1' --user-agent "${UA_BROWSER}")

    if [ -z "$tmpresult" ]; then
        modifyJsonTemplate 'Claude_result' 'Unknown'
        return
    fi

    local isBlocked=$(echo "$tmpresult" | grep -i 'not available in your country\|region restricted\|access denied\|blocked\|unavailable')

    local region=""
    region=$(echo "$tmpresult" | grep -oP '"country":"[A-Z]{2}"' | cut -d'"' -f4 | head -n 1)
    if [ -z "$region" ]; then
        region=$(echo "$tmpresult" | grep -oP '"countryCode":"[A-Z]{2}"' | cut -d'"' -f4 | head -n 1)
    fi
    if [ -z "$region" ]; then
        region=$(echo "$tmpresult" | grep -oP '"location":"[A-Z]{2}"' | cut -d'"' -f4 | head -n 1)
    fi
    # Use api.country.is as fallback (same as original csm.sh)
    if [ -z "$region" ]; then
        region=$(curl -s --max-time 5 "https://api.country.is" | grep -oP '"country":"[A-Z]{2}"' | cut -d'"' -f4)
    fi

    local isAvailable=$(echo "$tmpresult" | grep -i 'claude\|anthropic')

    if [ -n "$isBlocked" ]; then
        modifyJsonTemplate 'Claude_result' 'No'
        return
    fi

    if [ -n "$isAvailable" ] && [ -n "$region" ]; then
        modifyJsonTemplate 'Claude_result' 'Yes' "${region}"
    elif [ -n "$isAvailable" ]; then
        local fallback_region=$(curl -s --max-time 3 "http://ip-api.com/json" | grep -oP '"countryCode":"[A-Z]{2}"' | cut -d'"' -f4)
        if [ -n "$fallback_region" ]; then
            modifyJsonTemplate 'Claude_result' 'Yes' "${fallback_region}"
        else
            modifyJsonTemplate 'Claude_result' 'Yes'
        fi
    else
        modifyJsonTemplate 'Claude_result' 'No'
    fi
}

# TikTok check - 100% same as csm.sh
MediaUnlockTest_TikTok() {
    local Ftmpresult=$(curl --user-agent "${UA_Browser}" -s --max-time 10 "https://www.TikTok.com/")

    if [[ "$Ftmpresult" = "curl"* ]] || [ -z "$Ftmpresult" ]; then
        modifyJsonTemplate 'TikTok_result' 'Unknown'
        return
    fi

    local FRegion=$(echo $Ftmpresult | grep '"region":' | sed 's/.*"region"//' | cut -f2 -d'"')
    if [ -n "$FRegion" ]; then
        modifyJsonTemplate 'TikTok_result' 'Yes' "${FRegion}"
        return
    fi

    local STmpresult=$(curl --user-agent "${UA_Browser}" -sL --max-time 10 -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9" -H "Accept-Encoding: gzip" -H "Accept-Language: en" "https://www.TikTok.com" | gunzip 2>/dev/null)
    local SRegion=$(echo $STmpresult | grep '"region":' | sed 's/.*"region"//' | cut -f2 -d'"')
    if [ -n "$SRegion" ]; then
        modifyJsonTemplate 'TikTok_result' 'Yes' "${SRegion}"
        return
    else
        modifyJsonTemplate 'TikTok_result' 'No'
        return
    fi
}

# Run all checks
runCheck() {
    createJsonTemplate
    MediaUnlockTest_Netflix
    MediaUnlockTest_YouTube_Premium
    MediaUnlockTest_DisneyPlus
    MediaUnlockTest_HBOMax
    MediaUnlockTest_PrimeVideo
    MediaUnlockTest_OpenAI
    MediaUnlockTest_Gemini
    MediaUnlockTest_Claude
    MediaUnlockTest_TikTok
}

# Main execution
runCheck

# Output result file path
echo "$RESULT_FILE"
`
