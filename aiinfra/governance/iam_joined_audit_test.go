// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"errors"
	"reflect"
	"testing"
)

func TestJoinedAuditFragmentIsOpaqueAndNeverStandaloneCommitReady(t *testing.T) {
	fragmentType := reflect.TypeOf(JoinedAuditFragment{})
	mutationType := reflect.TypeOf(MutationPlan{})
	mutationSnapshotType := reflect.TypeOf(MutationPlanSnapshot{})
	for index := 0; index < fragmentType.NumField(); index++ {
		if fragmentType.Field(index).PkgPath == "" {
			t.Fatalf("JoinedAuditFragment field %q is caller-constructible", fragmentType.Field(index).Name)
		}
	}
	for index := 0; index < fragmentType.NumMethod(); index++ {
		method := fragmentType.Method(index)
		for output := 0; output < method.Type.NumOut(); output++ {
			if method.Type.Out(output) == mutationType || method.Type.Out(output) == mutationSnapshotType {
				t.Fatalf("JoinedAuditFragment.%s exposes a standalone governance mutation", method.Name)
			}
		}
	}
	zero := JoinedAuditFragment{}
	if zero.CommitReady() || zero.Snapshot().CommitReady || zero.Digest() != ([32]byte{}) ||
		!errors.Is(zero.VerifyDigest(), ErrInvalidCommand) {
		t.Fatal("zero joined fragment was not inert and non-committable")
	}
}
