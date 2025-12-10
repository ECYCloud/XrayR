package limiter

import (
	"testing"

	"github.com/ECYCloud/XrayR/api"
)

// Test that online user tracking in Limiter is properly separated by
// inbound tag. This is the foundation for keeping per-node online
// users independent once controller/hysteria2/anytls/tuic all embed
// NodeID into their tags.
func TestLimiterSeparatesOnlineUsersByTag(t *testing.T) {
	l := New()

	users := []api.UserInfo{{
		UID:         1,
		Email:       "user@example.com",
		SpeedLimit:  0,
		DeviceLimit: 10,
	}}
	userList := &users

	tag1 := "Vmess_0.0.0.0_443_1"
	tag2 := "Vmess_0.0.0.0_443_2"

	if err := l.AddInboundLimiter(tag1, 0, userList, nil); err != nil {
		t.Fatalf("AddInboundLimiter for tag1 failed: %v", err)
	}
	if err := l.AddInboundLimiter(tag2, 0, userList, nil); err != nil {
		t.Fatalf("AddInboundLimiter for tag2 failed: %v", err)
	}

	// Mark different IPs online under different tags for the same UID.
	if _, _, reject := l.GetUserBucket(tag1, "1", "1.1.1.1"); reject {
		t.Fatalf("unexpected reject for tag1 user")
	}
	if _, _, reject := l.GetUserBucket(tag2, "1", "2.2.2.2"); reject {
		t.Fatalf("unexpected reject for tag2 user ip1")
	}
	if _, _, reject := l.GetUserBucket(tag2, "1", "2.2.2.3"); reject {
		t.Fatalf("unexpected reject for tag2 user ip2")
	}

	online1, err := l.GetOnlineDevice(tag1)
	if err != nil {
		t.Fatalf("GetOnlineDevice(tag1) error: %v", err)
	}
	online2, err := l.GetOnlineDevice(tag2)
	if err != nil {
		t.Fatalf("GetOnlineDevice(tag2) error: %v", err)
	}

	if len(*online1) != 1 {
		t.Fatalf("expected 1 online user for tag1, got %d", len(*online1))
	}
	if len(*online2) != 2 {
		t.Fatalf("expected 2 online users for tag2, got %d", len(*online2))
	}

	// Verify that IPs are not mixed across tags.
	ips1 := map[string]struct{}{}
	for _, u := range *online1 {
		if u.UID != 1 {
			t.Fatalf("unexpected UID %d for tag1, want 1", u.UID)
		}
		ips1[u.IP] = struct{}{}
	}
	if _, ok := ips1["1.1.1.1"]; !ok || len(ips1) != 1 {
		t.Fatalf("unexpected IP set for tag1: %#v", ips1)
	}

	ips2 := map[string]struct{}{}
	for _, u := range *online2 {
		if u.UID != 1 {
			t.Fatalf("unexpected UID %d for tag2, want 1", u.UID)
		}
		ips2[u.IP] = struct{}{}
	}
	if len(ips2) != 2 {
		t.Fatalf("unexpected IP count for tag2: %#v", ips2)
	}
	if _, ok := ips2["2.2.2.2"]; !ok {
		t.Fatalf("missing IP 2.2.2.2 for tag2: %#v", ips2)
	}
	if _, ok := ips2["2.2.2.3"]; !ok {
		t.Fatalf("missing IP 2.2.2.3 for tag2: %#v", ips2)
	}
}
