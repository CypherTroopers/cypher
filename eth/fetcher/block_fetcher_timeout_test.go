package fetcher

import (
	"testing"
	"time"
)

func TestBodyFetchTimeoutCoversMaximumFrameWithoutExtendingHeaders(t *testing.T) {
	if fetchTimeout != 5*time.Second {
		t.Fatalf("header fetch timeout = %v, want legacy 5s", fetchTimeout)
	}
	maxFrameService := 5*time.Second + time.Duration(257*1024*1024)*time.Second/(2*1024*1024)
	if bodyFetchTimeout <= maxFrameService {
		t.Fatalf("body fetch timeout = %v, want margin above maximum-frame service time %v", bodyFetchTimeout, maxFrameService)
	}
}
