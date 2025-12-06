package rule

import (
	"regexp"
	"testing"

	"github.com/ECYCloud/XrayR/api"
)

// Test that Detect results are kept separate per inbound tag so that
// different logical nodes (with different tags) do not report each
// other's audit hits.
func TestManagerSeparatesDetectResultsByTag(t *testing.T) {
	m := New()

	tag1 := "V2ray_0.0.0.0_443_1"
	tag2 := "V2ray_0.0.0.0_443_2"

	rule1 := api.DetectRule{ID: 1, Pattern: regexp.MustCompile("example\\.com")}
	rule2 := api.DetectRule{ID: 2, Pattern: regexp.MustCompile("example\\.org")}

	if err := m.UpdateRule(tag1, []api.DetectRule{rule1}); err != nil {
		t.Fatalf("UpdateRule(tag1) failed: %v", err)
	}
	if err := m.UpdateRule(tag2, []api.DetectRule{rule2}); err != nil {
		t.Fatalf("UpdateRule(tag2) failed: %v", err)
	}

	// Same UID but different tags and destinations should hit different rules.
	if !m.Detect(tag1, "https://example.com", "1", "1.1.1.1") {
		t.Fatalf("expected Detect to reject on tag1")
	}
	if !m.Detect(tag2, "https://example.org", "1", "2.2.2.2") {
		t.Fatalf("expected Detect to reject on tag2")
	}

	res1, err := m.GetDetectResult(tag1)
	if err != nil {
		t.Fatalf("GetDetectResult(tag1) error: %v", err)
	}
	res2, err := m.GetDetectResult(tag2)
	if err != nil {
		t.Fatalf("GetDetectResult(tag2) error: %v", err)
	}

	if len(*res1) != 1 {
		t.Fatalf("expected 1 detect result for tag1, got %d", len(*res1))
	}
	if len(*res2) != 1 {
		t.Fatalf("expected 1 detect result for tag2, got %d", len(*res2))
	}

	if (*res1)[0].RuleID != 1 || (*res1)[0].UID != 1 {
		t.Fatalf("unexpected detect result for tag1: %+v", (*res1)[0])
	}
	if (*res2)[0].RuleID != 2 || (*res2)[0].UID != 1 {
		t.Fatalf("unexpected detect result for tag2: %+v", (*res2)[0])
	}
}
