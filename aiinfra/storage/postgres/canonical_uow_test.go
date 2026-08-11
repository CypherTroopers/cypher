// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
)

func TestCanonicalUOWMigrationContractInventoryIsClosed(t *testing.T) {
	specs, err := registeredMigrationSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 || specs[1].path != "migrations/0002_canonical_uow.sql" {
		t.Fatalf("registered migration suffix = %+v", specs)
	}
	source, err := readPinnedMigration(migrationFiles, specs[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafeDDL := range [][]byte{
		[]byte("CREATE TABLE IF NOT EXISTS"), []byte("CREATE INDEX IF NOT EXISTS"),
		[]byte("CREATE FUNCTION IF NOT EXISTS"),
	} {
		if bytes.Contains(source, unsafeDDL) {
			t.Fatalf("migration 2 contains unsafe idempotent DDL %q", unsafeDDL)
		}
	}
	if len(v2ColumnContract) != 15 {
		t.Fatalf("v2 table contract count = %d, want 15", len(v2ColumnContract))
	}
	if len(v2RelationContract) != 41 {
		t.Fatalf("v2 relation contract count = %d, want 41", len(v2RelationContract))
	}
	if len(v2IndexContract) != 26 {
		t.Fatalf("v2 index contract count = %d, want 26", len(v2IndexContract))
	}
	if len(v2TriggerContract) != 51 || len(v2TriggerDefinitions) != 51 {
		t.Fatalf("v2 trigger contracts=%d definitions=%d, want 51", len(v2TriggerContract), len(v2TriggerDefinitions))
	}

	contractConstraints := make(map[string]struct{})
	for table, expected := range v2ConstraintContract {
		if _, ok := v2ColumnContract[table]; !ok || len(expected) == 0 {
			t.Fatalf("constraint contract names unknown/empty table %s", table)
		}
		for name, contract := range expected {
			if contract.definition != v2NamedConstraintDefinitions[name] {
				t.Fatalf("constraint %s.%s definition is not the complete pinned clause", table, name)
			}
			if _, duplicate := contractConstraints[name]; duplicate {
				t.Fatalf("duplicate v2 constraint identity %s", name)
			}
			contractConstraints[name] = struct{}{}
		}
	}
	if !maps.Equal(contractConstraints, toSet(maps.Keys(v2NamedConstraintDefinitions))) {
		t.Fatal("migration-2 constraint source and structural contract differ")
	}
	for name, contract := range v2IndexContract {
		if v2RelationContract[name] != "i" || v2RelationContract[contract.table] != "r" ||
			contract.definition == "" || len(contract.keyColumns) == 0 ||
			len(contract.keyColumns) != len(contract.opclasses) || len(contract.keyColumns) != len(contract.collations) {
			t.Fatalf("incomplete v2 index contract %s: %+v", name, contract)
		}
	}
	for key, contract := range v2TriggerContract {
		parts := strings.Split(key, ".")
		if len(parts) != 2 || v2RelationContract[parts[0]] != "r" ||
			contract.definition != v2TriggerDefinitions[parts[1]] || contract.functionSchema != "cph_aiinfra" {
			t.Fatalf("incomplete v2 trigger contract %s: %+v", key, contract)
		}
	}
}

func TestCanonicalUOWPhaseInvariantSourceIsClosed(t *testing.T) {
	specs, err := registeredMigrationSpecs()
	if err != nil {
		t.Fatal(err)
	}
	source, err := readPinnedMigration(migrationFiles, specs[1])
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if strings.Contains(text, "reserved_audit_event_id") {
		t.Fatal("authoritative UoW still owns a singular future EventID")
	}
	for _, required := range []string{
		"uow.uow_kind = 1 AND uow.audit_event_id IS NULL",
		"uow.uow_kind = 2 AND uow.audit_event_id IS NOT NULL",
		"uow.audit_event_id <> NEW.audit_event_id",
		"uow.audit_event_id = NEW.audit_event_id",
		"claim.next_owner_domain = 'cph.aiinfra.governance.audit-event.v1'",
		"claim.audit_event_id = NEW.audit_event_id",
		"NEW.audit_event_id IS DISTINCT FROM OLD.audit_event_id",
		"compound umbrella has no complete exact member set",
		"business idempotency history has no exact same-transaction head",
		"durable pending revision has no exact same-transaction head",
		"durable pending evidence link has no exact same-transaction revision",
		"joined ordinary idempotency row has no exact recoverable pending state",
		"canonical state history has no exact same-transaction head",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("migration 2 lacks phase invariant %q", required)
		}
	}
	if strings.Count(text, "uow.audit_event_id <> NEW.audit_event_id") != 2 {
		t.Fatal("collecting child / audited-parent separation must cover business and pending heads exactly")
	}
}

func toSet(sequence func(func(string) bool)) map[string]struct{} {
	result := make(map[string]struct{})
	sequence(func(value string) bool {
		result[value] = struct{}{}
		return true
	})
	return result
}

func TestCanonicalUOWStorageEnumsAndBoundsArePinned(t *testing.T) {
	for _, test := range []struct {
		name string
		got  []int16
		want []int16
	}{
		{"UoW kind", v2UOWKinds[:], []int16{1, 2}},
		{"idempotency row kind", v2IdempotencyRowKinds[:], []int16{1, 2, 3}},
		{"idempotency state", v2IdempotencyStates[:], []int16{1, 2}},
		{"global claim mode", v2GlobalClaimModes[:], []int16{1, 2, 3}},
		{"pending kind", v2PendingKinds[:], []int16{1, 2, 3, 4, 5, 7}},
		{"pending status", v2PendingStatuses[:], []int16{1, 2}},
		{"evidence kind", v2EvidenceKinds[:], []int16{1, 2, 3, 4}},
		{"state namespace", v2StateNamespaces[:], []int16{1, 2}},
	} {
		if !slices.Equal(test.got, test.want) {
			t.Fatalf("%s catalog = %v, want %v", test.name, test.got, test.want)
		}
	}
	for name, want := range map[string]string{
		"authoritative_uow_kind":            "CHECK (uow_kind IN (1, 2))",
		"business_idempotency_head_kind":    "CHECK (row_kind IN (1, 2, 3))",
		"business_idempotency_history_kind": "CHECK (row_kind IN (1, 2, 3))",
		"global_identifier_claim_mode":      "CHECK (claim_mode IN (1, 2, 3))",
		"durable_pending_head_kind":         "CHECK (pending_kind IN (1, 2, 3, 4, 5, 7))",
		"durable_pending_revision_kind":     "CHECK (pending_kind IN (1, 2, 3, 4, 5, 7))",
		"durable_evidence_kind":             "CHECK (evidence_kind IN (1, 2, 3, 4))",
		"canonical_state_head_namespace":    "CHECK (state_namespace IN (1, 2))",
		"canonical_state_history_namespace": "CHECK (state_namespace IN (1, 2))",
	} {
		if got := normalizeCatalogDefinition(v2NamedConstraintDefinitions[name]); got != want {
			t.Fatalf("enum constraint %s = %q, want %q", name, got, want)
		}
	}
	if v2AuditEventMaxBytes != 64<<20 || v2DurableEnvelopeMaxBytes != 64<<20 ||
		v2EvidenceMaxBytes != 64<<20 || v2CanonicalStateMaxBytes != 64<<20 ||
		v2MaxGlobalClaims != 384 || v2MaxPendingEvidence != 2048 ||
		v2MaxUOWBusinessClaims != 384 || v2MaxUOWPendingRevisions != 384 ||
		v2MaxUOWEvidenceRecords != 2048 || v2MaxUOWCanonicalBytes != 64<<20 {
		t.Fatal("v2 bounded-storage constants drifted")
	}
	for _, name := range []string{
		"business_idempotency_head_operation_catalog",
		"business_idempotency_history_operation_catalog",
		"global_identifier_head_owner_domain_catalog",
		"global_identifier_history_owner_domain_catalog",
		"global_identifier_claim_owner_domain_catalog",
	} {
		definition := v2NamedConstraintDefinitions[name]
		if definition == "" || strings.Contains(strings.ToUpper(definition), "OR TRUE") {
			t.Fatalf("closed catalog constraint %s is missing or tautological", name)
		}
	}
	for _, test := range []struct {
		name string
		want []string
	}{
		{"business_idempotency_head_operation_catalog", v2BusinessOperationDomains[:]},
		{"business_idempotency_history_operation_catalog", v2BusinessOperationDomains[:]},
		{"global_identifier_head_owner_domain_catalog", v2GlobalOwnerDomains[:]},
		{"global_identifier_history_owner_domain_catalog", v2GlobalOwnerDomains[:]},
		{"global_identifier_claim_owner_domain_catalog", v2GlobalOwnerDomains[:]},
	} {
		got := quotedCatalogValues(v2NamedConstraintDefinitions[test.name])
		want := toSet(slices.Values(test.want))
		if !maps.Equal(got, want) {
			t.Fatalf("closed catalog %s = %v, want %v", test.name, got, want)
		}
	}
	stateCatalog := make(map[string]struct{})
	for _, spec := range canonicalStateKindCatalog {
		stateCatalog[string(spec.kind)] = struct{}{}
		stateCatalog[spec.contentType] = struct{}{}
	}
	for _, name := range []string{"canonical_state_head_kind_content_catalog",
		"canonical_state_history_kind_content_catalog"} {
		if got := quotedCatalogValues(v2NamedConstraintDefinitions[name]); !maps.Equal(got, stateCatalog) {
			t.Fatalf("canonical state catalog %s = %v, want %v", name, got, stateCatalog)
		}
	}
	pendingCodecs := map[string]struct{}{DurablePendingIAMCodec: {}, DurablePendingGovernanceCodec: {}}
	for _, name := range []string{"durable_pending_head_kind_codec_catalog",
		"durable_pending_revision_kind_codec_catalog"} {
		if got := quotedCatalogValues(v2NamedConstraintDefinitions[name]); !maps.Equal(got, pendingCodecs) {
			t.Fatalf("pending codec catalog %s = %v, want %v", name, got, pendingCodecs)
		}
	}
}

func quotedCatalogValues(definition string) map[string]struct{} {
	result := make(map[string]struct{})
	for {
		start := strings.IndexByte(definition, '\'')
		if start < 0 {
			return result
		}
		definition = definition[start+1:]
		end := strings.IndexByte(definition, '\'')
		if end < 0 {
			return result
		}
		result[definition[:end]] = struct{}{}
		definition = definition[end+1:]
	}
}

var errSyntheticUOW = errors.New("synthetic canonical UoW invariant")

type syntheticUOW struct {
	kind             int16
	xid              uint64
	actualID         string
	outcome          string
	evidence         map[string]struct{}
	assertedFinalIDs map[string]struct{}
}

type syntheticIdempotency struct {
	kind       int16
	state      int16
	version    uint64
	parent     string
	expectedID string
	xid        uint64
	outcome    string
}

type syntheticPending struct {
	status     int16
	revision   uint64
	expectedID string
	xid        uint64
	outcome    string
	evidence   map[string]struct{}
}

type syntheticCanonicalUOWState struct {
	rows               map[string]syntheticIdempotency
	pending            syntheticPending
	globalReservations map[string]struct{}
}

func newSyntheticAdmission(xid uint64, expectedID string, compound bool) (syntheticCanonicalUOWState, syntheticUOW) {
	uow := syntheticUOW{kind: 1, xid: xid, outcome: "admitted", evidence: map[string]struct{}{},
		assertedFinalIDs: map[string]struct{}{expectedID: {}}}
	state := syntheticCanonicalUOWState{
		rows: map[string]syntheticIdempotency{
			"X": {kind: 1, state: 1, version: 1, expectedID: expectedID, xid: xid},
			"Y": {kind: 2, state: 1, version: 1, parent: "X", expectedID: expectedID, xid: xid},
		},
		pending: syntheticPending{status: 1, revision: 1, expectedID: expectedID, xid: xid,
			evidence: map[string]struct{}{"approval-a": {}}},
		globalReservations: map[string]struct{}{expectedID: {}},
	}
	if compound {
		state.rows["member-key"] = syntheticIdempotency{
			kind: 3, state: 1, version: 1, parent: "X", expectedID: expectedID, xid: xid,
		}
	}
	return state, uow
}

func advanceSyntheticAdmission(state syntheticCanonicalUOWState, xid uint64, evidence string) (syntheticCanonicalUOWState, syntheticUOW) {
	result := cloneSyntheticState(state)
	x := result.rows["X"]
	x.version++
	x.xid = xid
	result.rows["X"] = x
	result.pending.revision++
	result.pending.xid = xid
	result.pending.evidence[evidence] = struct{}{}
	return result, syntheticUOW{kind: 1, xid: xid, outcome: "advanced", evidence: map[string]struct{}{},
		assertedFinalIDs: map[string]struct{}{result.pending.expectedID: {}}}
}

func completeSynthetic(state syntheticCanonicalUOWState, uow syntheticUOW, reconcile bool) syntheticCanonicalUOWState {
	result := cloneSyntheticState(state)
	for key, row := range result.rows {
		row.state = 2
		row.version++
		row.xid = uow.xid
		row.outcome = uow.outcome
		result.rows[key] = row
	}
	result.pending.status = 2
	result.pending.revision++
	result.pending.xid = uow.xid
	result.pending.outcome = uow.outcome
	_ = reconcile
	return result
}

func cloneSyntheticState(state syntheticCanonicalUOWState) syntheticCanonicalUOWState {
	result := syntheticCanonicalUOWState{rows: maps.Clone(state.rows), pending: state.pending,
		globalReservations: maps.Clone(state.globalReservations)}
	result.pending.evidence = maps.Clone(state.pending.evidence)
	return result
}

func validateSyntheticCanonicalState(state syntheticCanonicalUOWState, uow syntheticUOW, requireMember bool) error {
	if uow.xid == 0 || uow.outcome == "" || (uow.kind != 1 && uow.kind != 2) ||
		state.pending.expectedID == "" {
		return errSyntheticUOW
	}
	expectedID := state.pending.expectedID
	if _, reserved := state.globalReservations[expectedID]; !reserved {
		return errSyntheticUOW
	}
	if _, asserted := uow.assertedFinalIDs[expectedID]; !asserted {
		return errSyntheticUOW
	}
	x, xOK := state.rows["X"]
	y, yOK := state.rows["Y"]
	if !xOK || !yOK || x.kind != 1 || y.kind != 2 || y.parent != "X" ||
		x.expectedID != expectedID || y.expectedID != expectedID || x.state != y.state {
		return errSyntheticUOW
	}
	memberCount := 0
	for _, member := range state.rows {
		if member.kind != 3 {
			continue
		}
		memberCount++
		if member.parent != "X" || member.expectedID != expectedID || member.state != x.state {
			return errSyntheticUOW
		}
	}
	if requireMember && memberCount == 0 {
		return errSyntheticUOW
	}

	switch state.pending.status {
	case 1:
		if state.pending.xid != uow.xid || state.pending.outcome != "" ||
			x.state != 1 || x.xid != uow.xid || x.outcome != "" || y.outcome != "" || y.version != 1 ||
			(memberCount > 0 && x.version != 1) {
			return errSyntheticUOW
		}
		for _, row := range state.rows {
			if row.state != 1 || row.outcome != "" || row.expectedID != expectedID ||
				(row.kind == 3 && row.version != 1) {
				return errSyntheticUOW
			}
		}
		if uow.kind == 1 {
			if uow.actualID != "" || len(uow.evidence) != 0 {
				return errSyntheticUOW
			}
			return nil
		}
		if uow.actualID == "" || uow.actualID == expectedID || len(uow.evidence) == 0 {
			return errSyntheticUOW
		}
	case 2:
		if uow.kind != 2 || uow.actualID != expectedID || len(uow.evidence) == 0 ||
			state.pending.xid != uow.xid || state.pending.outcome != uow.outcome ||
			x.state != 2 || y.state != 2 || x.xid != uow.xid || y.xid != uow.xid ||
			x.outcome != uow.outcome || y.outcome != uow.outcome || y.version != 2 ||
			(memberCount > 0 && x.version != 2) {
			return errSyntheticUOW
		}
		for _, row := range state.rows {
			if row.state != 2 || row.xid != uow.xid || row.outcome != uow.outcome ||
				row.expectedID != expectedID || (row.kind == 3 && row.version != 2) {
				return errSyntheticUOW
			}
		}
	default:
		return errSyntheticUOW
	}
	if requireMember {
		member, ok := state.rows["member-key"]
		if !ok || member.kind != 3 || member.parent != "X" || member.expectedID != expectedID {
			return errSyntheticUOW
		}
	}
	for evidence := range uow.evidence {
		if _, retained := state.pending.evidence[evidence]; !retained {
			return errSyntheticUOW
		}
	}
	return nil
}

func TestSyntheticAdmissionAdvanceCrashReloadAndFinalizeOrReconcile(t *testing.T) {
	state, admission := newSyntheticAdmission(11, "cph-audit-v1:00000000000000000000000000000011", false)
	if err := validateSyntheticCanonicalState(state, admission, false); err != nil {
		t.Fatalf("initial admission rejected: %v", err)
	}
	state, advanceOne := advanceSyntheticAdmission(state, 12, "approval-b")
	if err := validateSyntheticCanonicalState(state, advanceOne, false); err != nil {
		t.Fatalf("first advance rejected: %v", err)
	}
	state, advanceTwo := advanceSyntheticAdmission(state, 13, "approval-c")
	if err := validateSyntheticCanonicalState(state, advanceTwo, false); err != nil {
		t.Fatalf("second advance rejected: %v", err)
	}

	// A restart reconstructs only detached durable rows; no in-process state is
	// required to reach either terminal branch.
	reloaded := cloneSyntheticState(state)
	finalUOW := syntheticUOW{kind: 2, xid: 20, actualID: reloaded.pending.expectedID,
		outcome: "success", evidence: maps.Clone(reloaded.pending.evidence),
		assertedFinalIDs: map[string]struct{}{reloaded.pending.expectedID: {}}}
	finalized := completeSynthetic(reloaded, finalUOW, false)
	if err := validateSyntheticCanonicalState(finalized, finalUOW, false); err != nil {
		t.Fatalf("finalize branch rejected: %v", err)
	}

	reconcileUOW := syntheticUOW{kind: 2, xid: 21, actualID: reloaded.pending.expectedID,
		outcome: "timed-out", evidence: maps.Clone(reloaded.pending.evidence),
		assertedFinalIDs: map[string]struct{}{reloaded.pending.expectedID: {}}}
	reconciled := completeSynthetic(reloaded, reconcileUOW, true)
	if err := validateSyntheticCanonicalState(reconciled, reconcileUOW, false); err != nil {
		t.Fatalf("reconcile branch rejected: %v", err)
	}
}

func TestSyntheticCanonicalUOWRejectsMixedAndOrphanTerminalStates(t *testing.T) {
	state, _ := newSyntheticAdmission(31, "cph-audit-v1:00000000000000000000000000000031", true)
	finalUOW := syntheticUOW{kind: 2, xid: 32, actualID: state.pending.expectedID,
		outcome: "success", evidence: maps.Clone(state.pending.evidence),
		assertedFinalIDs: map[string]struct{}{state.pending.expectedID: {}}}
	baseline := completeSynthetic(state, finalUOW, false)
	if err := validateSyntheticCanonicalState(baseline, finalUOW, true); err != nil {
		t.Fatalf("baseline rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*syntheticCanonicalUOWState, *syntheticUOW)
	}{
		{"mixed X/Y xid", func(s *syntheticCanonicalUOWState, _ *syntheticUOW) { row := s.rows["Y"]; row.xid++; s.rows["Y"] = row }},
		{"different member outcome", func(s *syntheticCanonicalUOWState, _ *syntheticUOW) {
			row := s.rows["member-key"]
			row.outcome = "other"
			s.rows["member-key"] = row
		}},
		{"different pending expected ID", func(s *syntheticCanonicalUOWState, _ *syntheticUOW) { s.pending.expectedID = "other" }},
		{"different child expected ID", func(s *syntheticCanonicalUOWState, _ *syntheticUOW) {
			row := s.rows["Y"]
			row.expectedID = "other"
			s.rows["Y"] = row
		}},
		{"orphan X", func(s *syntheticCanonicalUOWState, _ *syntheticUOW) { delete(s.rows, "Y") }},
		{"orphan Y", func(s *syntheticCanonicalUOWState, _ *syntheticUOW) { delete(s.rows, "X") }},
		{"orphan member", func(s *syntheticCanonicalUOWState, _ *syntheticUOW) { delete(s.rows, "member-key") }},
		{"global reservation orphan", func(s *syntheticCanonicalUOWState, _ *syntheticUOW) {
			delete(s.globalReservations, s.pending.expectedID)
		}},
		{"same UoW reservation assertion missing", func(_ *syntheticCanonicalUOWState, u *syntheticUOW) { u.assertedFinalIDs = nil }},
		{"missing evidence assertion", func(_ *syntheticCanonicalUOWState, u *syntheticUOW) { u.evidence = nil }},
		{"unretained evidence assertion", func(_ *syntheticCanonicalUOWState, u *syntheticUOW) { u.evidence["not-retained"] = struct{}{} }},
		{"completed child lacks exact terminal event", func(_ *syntheticCanonicalUOWState, u *syntheticUOW) { u.actualID = "other" }},
		{"different final outcome", func(_ *syntheticCanonicalUOWState, u *syntheticUOW) { u.outcome = "other" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneSyntheticState(baseline)
			uow := finalUOW
			uow.evidence = maps.Clone(finalUOW.evidence)
			test.mutate(&candidate, &uow)
			if err := validateSyntheticCanonicalState(candidate, uow, true); !errors.Is(err, errSyntheticUOW) {
				t.Fatalf("negative state error = %v, want %v", err, errSyntheticUOW)
			}
		})
	}
}

func TestSyntheticAuditedParentMayDeriveDifferentCollectingChild(t *testing.T) {
	state, _ := newSyntheticAdmission(41, "cph-audit-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)
	parent := syntheticUOW{kind: 2, xid: 41, actualID: "cph-audit-v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		outcome: "accepted", evidence: maps.Clone(state.pending.evidence),
		assertedFinalIDs: map[string]struct{}{state.pending.expectedID: {}}}
	if err := validateSyntheticCanonicalState(state, parent, true); err != nil {
		t.Fatalf("audited parent deriving a collecting child rejected: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*syntheticCanonicalUOWState, *syntheticUOW)
	}{
		{"parent event reused as child terminal event", func(s *syntheticCanonicalUOWState, u *syntheticUOW) {
			u.actualID = s.pending.expectedID
		}},
		{"collecting child expected ID mismatch", func(s *syntheticCanonicalUOWState, _ *syntheticUOW) {
			row := s.rows["Y"]
			row.expectedID = "cph-audit-v1:cccccccccccccccccccccccccccccccc"
			s.rows["Y"] = row
		}},
		{"collecting joined row orphan", func(s *syntheticCanonicalUOWState, _ *syntheticUOW) { delete(s.rows, "Y") }},
		{"collecting compound member orphan", func(s *syntheticCanonicalUOWState, _ *syntheticUOW) { delete(s.rows, "member-key") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneSyntheticState(state)
			uow := parent
			uow.evidence = maps.Clone(parent.evidence)
			uow.assertedFinalIDs = maps.Clone(parent.assertedFinalIDs)
			test.mutate(&candidate, &uow)
			if err := validateSyntheticCanonicalState(candidate, uow, true); !errors.Is(err, errSyntheticUOW) {
				t.Fatalf("negative state error = %v, want %v", err, errSyntheticUOW)
			}
		})
	}
}

func TestSyntheticAdmissionsMayShareFutureEventReservation(t *testing.T) {
	const expectedID = "cph-audit-v1:dddddddddddddddddddddddddddddddd"
	first, firstUOW := newSyntheticAdmission(51, expectedID, false)
	second, secondUOW := newSyntheticAdmission(52, expectedID, false)
	if err := validateSyntheticCanonicalState(first, firstUOW, false); err != nil {
		t.Fatalf("first admission rejected: %v", err)
	}
	if err := validateSyntheticCanonicalState(second, secondUOW, false); err != nil {
		t.Fatalf("second admission assertion against shared reservation rejected: %v", err)
	}
	for _, column := range v2ColumnContract["authoritative_uow"] {
		if strings.Contains(column.name, "reserved") {
			t.Fatalf("authoritative UoW must not own a singular reservation column: %s", column.name)
		}
	}
}
