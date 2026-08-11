// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import "math"

type planWindow struct {
	EvaluatedAtUnixNano     int64
	CommitNotBeforeUnixNano int64
	CommitNotAfterUnixNano  int64
}

// newPlanWindow converts semantic point-in-time checks into a durable commit
// interval. A storage adapter must compare its trusted database clock against
// this half-open interval in the same transaction as every CAS.
func newPlanWindow(receiver ReceiverProfile, at int64, notBefore, notAfter []int64) (planWindow, error) {
	if err := validateReceiverProfile(receiver); err != nil || at < 0 || receiver.MaxPlanCommitLatencyNanos > math.MaxInt64-at {
		return planWindow{}, ErrInvalidCommitWindow
	}
	lower := at - receiver.MaxClockSkewNanos
	if lower < 0 {
		lower = 0
	}
	for _, candidate := range notBefore {
		if candidate < 0 {
			return planWindow{}, ErrInvalidCommitWindow
		}
		lower = maximumInt64(lower, candidate)
	}
	upper := at + receiver.MaxPlanCommitLatencyNanos
	for _, candidate := range notAfter {
		if candidate <= 0 {
			return planWindow{}, ErrInvalidCommitWindow
		}
		upper = minimumInt64(upper, candidate)
	}
	if upper <= at || lower >= upper {
		return planWindow{}, ErrInvalidCommitWindow
	}
	return planWindow{EvaluatedAtUnixNano: at, CommitNotBeforeUnixNano: lower, CommitNotAfterUnixNano: upper}, nil
}

func minimumInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func maximumInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
