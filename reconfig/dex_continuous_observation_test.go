package reconfig_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/service"
)

// Observing an unavailable bounded API is not an INVALID consensus result.
// This test helper never changes a server deadline, substitutes cached state,
// or retries malformed/explicitly failed status. The caller's phase deadline
// covers requests and backoff together.
func continuousObserveStatus(ctx context.Context, get func(context.Context) (service.Status, error), interval time.Duration) (service.Status, int, error, error) {
	retries := 0
	var last error
	for {
		if err := ctx.Err(); err != nil {
			return service.Status{}, retries, last, err
		}
		status, err := get(ctx)
		if deadlineErr := ctx.Err(); deadlineErr != nil {
			return service.Status{}, retries, last, deadlineErr
		}
		if err == nil {
			if status.Error != "" {
				return service.Status{}, retries, last, fmt.Errorf("explicit DEX failure: %s", status.Error)
			}
			return status, retries, last, nil
		}
		var httpErr *financialHTTPError
		var netErr net.Error
		retryable := errors.As(err, &httpErr) && httpErr.Status == http.StatusServiceUnavailable
		retryable = retryable || errors.As(err, &netErr) && netErr.Timeout()
		if !retryable {
			return service.Status{}, retries, last, err
		}
		retries++
		last = err
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return service.Status{}, retries, last, ctx.Err()
		case <-timer.C:
		}
	}
}

func TestContinuousStatusObservationBounded(t *testing.T) {
	t.Run("busy_then_fresh", func(t *testing.T) {
		calls := 0
		want := service.Status{State: "active", Certified: 18, Finalized: 16}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		got, retries, last, err := continuousObserveStatus(ctx, func(context.Context) (service.Status, error) {
			calls++
			if calls <= 2 {
				return service.Status{Certified: 999}, &financialHTTPError{Path: "/v1/status", Status: 503, Body: "DEX unavailable"}
			}
			return want, nil
		}, time.Microsecond)
		if err != nil || got != want || calls != 3 || retries != 2 || last == nil {
			t.Fatal("fresh-only bounded observation", got, calls, retries, last, err)
		}
	})
	t.Run("permanent_unavailable_deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		got, retries, last, err := continuousObserveStatus(ctx, func(context.Context) (service.Status, error) {
			return service.Status{Certified: 999}, &financialHTTPError{Status: 503}
		}, time.Millisecond)
		if !errors.Is(err, context.DeadlineExceeded) || got != (service.Status{}) || retries == 0 || last == nil {
			t.Fatal("unavailable cannot become observed success", got, retries, last, err)
		}
	})
	t.Run("request_timeout_then_fresh", func(t *testing.T) {
		calls := 0
		want := service.Status{State: "active", Certified: 18, Finalized: 16}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		got, retries, last, err := continuousObserveStatus(ctx, func(context.Context) (service.Status, error) {
			calls++
			if calls == 1 {
				return service.Status{Certified: 999}, &net.DNSError{Err: "synthetic request timeout", IsTimeout: true}
			}
			return want, nil
		}, time.Microsecond)
		if err != nil || got != want || calls != 2 || retries != 1 || last == nil {
			t.Fatal("request timeout did not recover to fresh status", got, calls, retries, last, err)
		}
	})
	t.Run("phase_canceled_during_request", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		got, retries, _, err := continuousObserveStatus(ctx, func(context.Context) (service.Status, error) {
			cancel()
			return service.Status{Certified: 999}, nil
		}, time.Hour)
		if !errors.Is(err, context.Canceled) || got != (service.Status{}) || retries != 0 {
			t.Fatal("late result accepted after phase cancellation", got, retries, err)
		}
	})
	for name, failure := range map[string]error{
		"malformed_json":  &json.SyntaxError{Offset: 1},
		"invalid_request": &financialHTTPError{Status: 400},
		"response_bound":  fmt.Errorf("financial API response bound"),
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			got, retries, _, err := continuousObserveStatus(context.Background(), func(context.Context) (service.Status, error) {
				calls++
				return service.Status{Certified: 999}, failure
			}, time.Hour)
			if err != failure || calls != 1 || retries != 0 || got != (service.Status{}) {
				t.Fatal("invalid observation retried or accepted", got, calls, retries, err)
			}
		})
	}
	t.Run("explicit_failure", func(t *testing.T) {
		calls := 0
		got, retries, _, err := continuousObserveStatus(context.Background(), func(context.Context) (service.Status, error) {
			calls++
			return service.Status{Certified: 999, Error: "WAL unavailable"}, nil
		}, time.Hour)
		if err == nil || calls != 1 || retries != 0 || got != (service.Status{}) {
			t.Fatal("explicit failure retried or accepted", got, calls, retries, err)
		}
	})
}
