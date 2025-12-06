package controller

import (
	"testing"

	"github.com/ECYCloud/XrayR/api"
)

// TestBuildNodeTagIncludesNodeID verifies that Controller.buildNodeTag
// embeds NodeID so that different logical nodes sharing the same
// NodeType + ListenIP + Port still get distinct tags.
func TestBuildNodeTagIncludesNodeID(t *testing.T) {
	c := &Controller{
		config: &Config{ListenIP: "0.0.0.0"},
		nodeInfo: &api.NodeInfo{
			NodeType: "V2ray",
			NodeID:   1,
			Port:     443,
		},
	}

	got := c.buildNodeTag()
	want := "V2ray_0.0.0.0_443_1"
	if got != want {
		t.Fatalf("unexpected tag, got %q, want %q", got, want)
	}

	c.nodeInfo.NodeID = 2
	got2 := c.buildNodeTag()
	if got2 == got {
		t.Fatalf("expected different tag when NodeID changes, still got %q", got2)
	}
}
