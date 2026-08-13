// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
)

// AuditHeadRecord is the owned transaction-locked historical append head.
// Authorized* mirrors Head* at rest and names the authority that signed the
// latest event; it is not a mutable current-authorization cache. A Governance
// AuditView adapter must combine this row with exact current profile,
// key-state, and writer-lease canonical rows from the same CanonicalUOW.
type AuditHeadRecord struct {
	StreamID                          string
	DeploymentAnchorDigest            [sha256.Size]byte
	Sequence                          uint64
	LastRecordDigest                  [sha256.Size]byte
	AuditEventID                      string
	HeadWriterIdentity                string
	AuthorizedWriterIdentity          string
	HomeRegion                        string
	AuthorizedHomeRegion              string
	WriterEpoch                       uint64
	AuthorizedWriterEpoch             uint64
	HeadGovernanceProfileDigest       [sha256.Size]byte
	AuthorizedGovernanceProfileDigest [sha256.Size]byte
	WriterLeaseEvidenceDigest         [sha256.Size]byte
	WriterLeaseNotBeforeUnixNano      int64
	WriterLeaseNotAfterUnixNano       int64
}

type AuditEventLookup struct {
	EventID      string
	StreamID     string
	Sequence     uint64
	RecordDigest [sha256.Size]byte
}

const selectAuditHeadForUpdateSQL = `
	SELECT deployment_anchor_digest, highest_sequence, latest_record_digest,
		audit_event_id, head_writer_identity, authorized_writer_identity,
		home_region, authorized_home_region, writer_epoch, authorized_writer_epoch,
		head_governance_profile_digest, authorized_governance_profile_digest,
		writer_lease_evidence_digest, writer_lease_not_before_unix_nano,
		writer_lease_not_after_unix_nano
	FROM cph_aiinfra.audit_head
	WHERE stream_id = $1
	FOR UPDATE`

// LoadAuditHead returns the complete exact historical head on the active
// replay transaction connection. Any current lease/profile snapshot used by
// the Governance adapter must be read through this same CanonicalUOW.
func (uow *CanonicalUOW) LoadAuditHead(ctx context.Context,
	streamID string) (AuditHeadRecord, bool, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return AuditHeadRecord{}, false, err
	}
	defer state.mu.Unlock()
	if validateCanonicalText(streamID, 255) != nil {
		return AuditHeadRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	var anchor, last, headProfile, authorizedProfile, lease []byte
	var sequence, writerEpoch, authorizedWriterEpoch string
	record := AuditHeadRecord{StreamID: streamID}
	err = state.tx.QueryRowContext(ctx, selectAuditHeadForUpdateSQL, streamID).Scan(
		&anchor, &sequence, &last, &record.AuditEventID, &record.HeadWriterIdentity,
		&record.AuthorizedWriterIdentity, &record.HomeRegion, &record.AuthorizedHomeRegion,
		&writerEpoch, &authorizedWriterEpoch, &headProfile, &authorizedProfile, &lease,
		&record.WriterLeaseNotBeforeUnixNano, &record.WriterLeaseNotAfterUnixNano)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditHeadRecord{}, false, nil
	}
	if err != nil {
		return AuditHeadRecord{}, false, poisonCanonicalLocked(state,
			fmt.Errorf("%w: read audit head: %v", ErrCanonicalStateCorrupt, err))
	}
	sequenceValue, sequenceErr := strconv.ParseUint(sequence, 10, 64)
	writerValue, writerErr := strconv.ParseUint(writerEpoch, 10, 64)
	authorizedWriterValue, authorizedErr := strconv.ParseUint(authorizedWriterEpoch, 10, 64)
	if sequenceErr != nil || writerErr != nil || authorizedErr != nil ||
		len(anchor) != sha256.Size || len(last) != sha256.Size ||
		len(headProfile) != sha256.Size || len(authorizedProfile) != sha256.Size ||
		len(lease) != sha256.Size {
		return AuditHeadRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	record.Sequence, record.WriterEpoch, record.AuthorizedWriterEpoch =
		sequenceValue, writerValue, authorizedWriterValue
	copy(record.DeploymentAnchorDigest[:], anchor)
	copy(record.LastRecordDigest[:], last)
	copy(record.HeadGovernanceProfileDigest[:], headProfile)
	copy(record.AuthorizedGovernanceProfileDigest[:], authorizedProfile)
	copy(record.WriterLeaseEvidenceDigest[:], lease)
	if !validAuditHeadRecord(record) {
		return AuditHeadRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	return record, true, nil
}

func validAuditHeadRecord(record AuditHeadRecord) bool {
	return validateCanonicalText(record.StreamID, 255) == nil && record.Sequence > 0 &&
		nonzeroDigest(record.DeploymentAnchorDigest) && nonzeroDigest(record.LastRecordDigest) &&
		validateCanonicalText(record.AuditEventID, 1024) == nil &&
		validateCanonicalText(record.HeadWriterIdentity, 1024) == nil &&
		validateCanonicalText(record.AuthorizedWriterIdentity, 1024) == nil &&
		validateCanonicalText(record.HomeRegion, 255) == nil &&
		validateCanonicalText(record.AuthorizedHomeRegion, 255) == nil &&
		record.WriterEpoch > 0 && record.AuthorizedWriterEpoch > 0 &&
		nonzeroDigest(record.HeadGovernanceProfileDigest) &&
		nonzeroDigest(record.AuthorizedGovernanceProfileDigest) &&
		nonzeroDigest(record.WriterLeaseEvidenceDigest) &&
		record.WriterLeaseNotBeforeUnixNano >= 0 &&
		record.WriterLeaseNotAfterUnixNano > record.WriterLeaseNotBeforeUnixNano
}

const selectAuditEventForUpdateSQL = `
	SELECT stream_id, audit_sequence, record_digest
	FROM cph_aiinfra.audit_event
	WHERE event_id = $1`

func (uow *CanonicalUOW) LoadAuditEvent(ctx context.Context,
	eventID string) (AuditEventLookup, bool, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return AuditEventLookup{}, false, err
	}
	defer state.mu.Unlock()
	if validateCanonicalText(eventID, 1024) != nil {
		return AuditEventLookup{}, false, poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	var sequence string
	var digest []byte
	record := AuditEventLookup{EventID: eventID}
	err = state.tx.QueryRowContext(ctx, selectAuditEventForUpdateSQL, eventID).
		Scan(&record.StreamID, &sequence, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditEventLookup{}, false, nil
	}
	if err != nil {
		return AuditEventLookup{}, false, poisonCanonicalLocked(state,
			fmt.Errorf("%w: read AuditEvent: %v", ErrCanonicalStateCorrupt, err))
	}
	parsed, parseErr := strconv.ParseUint(sequence, 10, 64)
	if parseErr != nil || parsed == 0 || len(digest) != sha256.Size ||
		validateCanonicalText(record.StreamID, 255) != nil {
		return AuditEventLookup{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	record.Sequence = parsed
	copy(record.RecordDigest[:], digest)
	return record, true, nil
}
