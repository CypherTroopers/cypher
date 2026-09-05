package reconfig

import (
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/rlp"
)

// reconstructFHSCertifiedBody is independent of the volatile body cache and
// asynchronous content writer. Certified execution already owns the immutable
// transactions/sidecars. Keep its original header and small proof envelope so
// dropping an encoded body never drops the information needed to serve it.
func (s *Service) reconstructFHSCertifiedBody(proposalID common.Hash) (*proposalBodyMsg, bool, error) {
	s.muProposalBody.RLock()
	record := s.fhsCertifiedByID[proposalID]
	if record == nil || record.ref == nil || record.envelope == nil || record.originalHeader == nil || record.verified == nil || record.verified.Block == nil {
		s.muProposalBody.RUnlock()
		return nil, false, nil
	}
	ref := *record.ref
	body := cloneProposalBodyEnvelope(record.envelope)
	header, block := record.originalHeader, record.verified.Block
	s.muProposalBody.RUnlock()

	// The exact header snapshot is immutable and predates QC installation.
	// Copy/encode the large payload outside the consensus/cache lock.
	encoded, err := rlp.EncodeToBytes(block.WithSeal(header))
	if err != nil {
		return nil, true, fmt.Errorf("reconstruct certified FHS body: %w", err)
	}
	if ref.ProposalID() != proposalID || body.ProposalID != proposalID {
		return nil, true, fmt.Errorf("certified FHS body reference mismatch")
	}
	if _, err := validateFHSProposalCommitmentsForConfig(s.chainConfig, &ref, encoded, body.Extra, body.ParentQC); err != nil {
		return nil, true, fmt.Errorf("reconstructed certified FHS body is invalid: %w", err)
	}
	body.EncodedBlock = encoded
	return body, true, nil
}

func (s *Service) localFHSProposalBody(proposalID common.Hash) (*proposalBodyMsg, bool, error) {
	if body, found, err := s.reconstructFHSCertifiedBody(proposalID); found || err != nil {
		return body, found, err
	}
	if s.fhsStore == nil || s.fhsStore.db == nil {
		return nil, false, nil
	}
	_, body, found, err := s.readFHSDurableProposalBody(proposalID)
	return body, found, err
}

// cacheRestoredFHSBodyLocked hydrates only the bounded hot working set. All
// certificates and execution artifacts have already passed atomic recovery
// preflight and can outlive these optional body/index entries.
func (s *Service) cacheRestoredFHSBodyLocked(body *proposalBodyMsg) {
	if body == nil {
		return
	}
	weight := proposalBodyMsgPayloadBytes(body)
	limit := proposalBodyCacheLimitForConfig(s.chainConfig)
	if weight > limit {
		return
	}
	if s.proposalBodies[body.ProposalID] != nil {
		s.evictProposalBodyLocked(body.ProposalID)
	}
	for {
		entries, used := s.proposalBodyCacheUsageLocked()
		if entries < proposalBodyCacheMaxEntries && fitsIntBudget(used, weight, limit) {
			break
		}
		if !s.evictOldestProposalBodyLocked() {
			return
		}
	}
	s.proposalBodies[body.ProposalID] = body
	s.signalProposalBodyUpdateLocked()
}
