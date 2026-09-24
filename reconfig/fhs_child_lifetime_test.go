package reconfig

import (
	"errors"
	"testing"
	"time"
)

// The continuous fixture owns children until its finite parent deadline. This
// process lifetime is unrelated to any FHS timeout, vote or finality deadline.
func fhsChildLifetime(continuous bool, remaining time.Duration, hasDeadline bool) (time.Duration, error) {
	if !continuous {
		return 12 * time.Minute, nil
	}
	if !hasDeadline || remaining <= 0 || remaining > 45*time.Minute {
		return 0, errors.New("continuous FHS child requires finite parent deadline <=45m")
	}
	return remaining + 2*time.Minute, nil
}

func TestFHSChildLifetimeMatchesContinuousParent(t *testing.T) {
	for _, c := range []struct {
		name            string
		continuous, has bool
		remaining, want time.Duration
		bad             bool
	}{
		{"legacy", false, false, 0, 12 * time.Minute, false},
		{"legacy-unaffected", false, true, 44 * time.Minute, 12 * time.Minute, false},
		{"continuous", true, true, 44 * time.Minute, 46 * time.Minute, false},
		{"continuous-max", true, true, 45 * time.Minute, 47 * time.Minute, false},
		{"cold-restart", true, true, 5 * time.Minute, 7 * time.Minute, false},
		{"missing-parent", true, false, 0, 0, true},
		{"expired-parent", true, true, 0, 0, true},
		{"oversize-parent", true, true, 46 * time.Minute, 0, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := fhsChildLifetime(c.continuous, c.remaining, c.has)
			if (err != nil) != c.bad || got != c.want {
				t.Fatal(got, err)
			}
		})
	}
}
