package consensus

import (
	"errors"
	"testing"
)

func TestIngressResumesReadyViewWithoutTimeoutOrUnboundedBuild(t *testing.T) {
	ready := false
	n := newConfiguredNetwork(t, 5, func(c *Config) {
		c.Execution = new(fixtureExecution)
		c.ActionsWithParent = func(_ []byte, ctx ExecutionContext) ([]byte, error) {
			if !ready {
				return nil, ErrUnavailable
			}
			return []byte{byte(ctx.Height)}, nil
		}
	})
	if err := n.nodes[0].NotifyIngress(); err == nil {
		t.Fatal("ingress scheduled before start")
	}
	drain := func() {
		for step := 0; step < 20000; step++ {
			progress := false
			for _, a := range n.nodes {
				did, err := a.Advance()
				if !benign(err) && !errors.Is(err, ErrUnavailable) {
					t.Fatal("advance", err)
				}
				progress = progress || did
			}
			if len(n.queue) > 0 {
				d := n.queue[0]
				n.queue = n.queue[1:]
				progress = true
				for _, a := range n.nodes {
					if a.Self() == d.to {
						if err := a.Handle(d.message); !benign(err) && !errors.Is(err, ErrUnavailable) {
							t.Fatal("message", err)
						}
						break
					}
				}
			}
			if !progress {
				return
			}
		}
		t.Fatal("bounded ingress fixture did not quiesce")
	}
	for _, a := range n.nodes {
		if err := a.Start(); !benign(err) {
			t.Fatal(err)
		}
	}
	drain()
	if n.nodes[0].CertifiedHeight() != 0 || n.nodes[0].CurrentN() != 1 {
		t.Fatal("empty ingress advanced view")
	}
	for repeat := 0; repeat < 100; repeat++ {
		for _, a := range n.nodes {
			if err := a.NotifyIngress(); !benign(err) {
				t.Fatal(err)
			}
			if len(a.builds) > 1 {
				t.Fatal("notification queued duplicate construction")
			}
		}
	}
	drain()
	ready = true
	for _, a := range n.nodes {
		if err := a.NotifyIngress(); !benign(err) {
			t.Fatal(err)
		}
	}
	drain()
	for i, a := range n.nodes {
		if a.CertifiedHeight() != 5 || a.FinalizedHeight() != 4 || a.disk.Safety.HighestTC != nil {
			t.Fatalf("node%d: cert%d final%d unexpectedly required timeout", i, a.CertifiedHeight(), a.FinalizedHeight())
		}
	}
}
