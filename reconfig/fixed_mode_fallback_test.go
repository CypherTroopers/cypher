package reconfig

import (
	"testing"
	"time"
)

func TestShouldUseFixedModeFallback(t *testing.T) {
	delay := time.Minute

	tests := []struct {
		name             string
		viewAge          time.Duration
		primaryAckRecent bool
		want             bool
	}{
		{name: "before delay", viewAge: delay - time.Millisecond, want: false},
		{name: "primary alive", viewAge: delay, primaryAckRecent: true, want: false},
		{name: "primary alive long after delay", viewAge: 10 * delay, primaryAckRecent: true, want: false},
		{name: "primary unavailable", viewAge: delay, primaryAckRecent: false, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldUseFixedModeFallback(tt.viewAge, delay, tt.primaryAckRecent); got != tt.want {
				t.Fatalf("shouldUseFixedModeFallback(%s, %s, %t) = %t, want %t",
					tt.viewAge, delay, tt.primaryAckRecent, got, tt.want)
			}
		})
	}
}
