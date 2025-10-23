package sspanel

import (
	"testing"
)

func TestParseUserListResponse_DoesNotClearLastReportOnline(t *testing.T) {
	c := &APIClient{
		DeviceLimit:      0,
		SpeedLimit:       0,
		LastReportOnline: map[int]int{1: 2}, // previously reported 2 devices for UID=1
	}

	users := &[]UserResponse{
		{ID: 1, DeviceLimit: 3, AliveIP: 2, UUID: "uuid-1", Passwd: "pwd", Port: 1000, Method: "aes-128-gcm"},
	}

	got, err := c.ParseUserListResponse(users)
	if err != nil {
		t.Fatalf("ParseUserListResponse error: %v", err)
	}

	if len(*got) != 1 {
		t.Fatalf("expected 1 user, got %d", len(*got))
	}

	u := (*got)[0]
	if u.DeviceLimit <= 0 {
		t.Fatalf("expected positive local device limit, got %d", u.DeviceLimit)
	}

	// Ensure LastReportOnline snapshot not cleared inside ParseUserListResponse
	if c.LastReportOnline[1] != 2 {
		t.Fatalf("LastReportOnline was modified, want 2, got %d", c.LastReportOnline[1])
	}
}
