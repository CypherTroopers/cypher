package engine

import (
	"errors"
	"github.com/cypherium/cypher/dex/instrumentation"

	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
)

// ApplyInbox consumes only a verifier-created immutable range. Network/RPC
// responses cannot construct that object without complete CLX authentication.
// Trading arithmetic and account signature nonces are unchanged.
func (e *Engine) ApplyInbox(parent *State, verified *clxevidence.VerifiedRange, height uint64) (*State, Delta, error) {
	instrumentation.InboxImported()
	if !e.config.NativeInbox || !verified.Matches(e.config.Domain, e.config.Custody) || e.validate(parent) != nil || verified.Count() < parent.InboxCursor || parent.Height == ^uint64(0) || height != parent.Height+1 || parent.Frozen || parent.PendingFunding != 0 {
		return nil, Delta{}, errors.New("NATIVE_INBOX_STATE")
	}
	entries := verified.Entries()
	if len(entries) > protocol.MaxDepositsPerCheckpoint || (len(entries) > 0 && entries[0].Index != parent.InboxCursor) {
		return nil, Delta{}, errors.New("NATIVE_INBOX_CURSOR")
	}
	s := clone(parent)
	s.Height = height
	if height%10 == 0 {
		for _, account := range s.Accounts {
			if position(account) != 0 {
				return nil, Delta{}, errors.New("FUNDING_PENDING")
			}
		}
	}
	d := Delta{InboxStart: s.InboxCursor, DepositTotal: "0", Fees: "0", Dust: "0", InsuranceUsed: "0", Withdrawals: []protocol.Claim{}}
	for _, entry := range entries {
		if entry.ChainID != e.config.Domain.ChainID || entry.Genesis != e.config.Domain.Genesis || entry.DEXID != e.config.Domain.DEXID || entry.Custody != e.config.Custody || entry.Index != s.InboxCursor {
			return nil, Delta{}, errors.New("NATIVE_INBOX_IDENTITY")
		}
		v := entry.Amount.Big().String()
		switch entry.Bucket {
		case protocol.InboxTrader:
			owner := id(entry.Owner)
			account := s.Accounts[owner]
			if account == nil {
				if len(s.Accounts) >= 16 {
					return nil, Delta{}, errors.New("ACCOUNT_BOUND")
				}
				account = &Account{Cash: "0", Lots: []Lot{}}
				s.Accounts[owner] = account
			}
			account.Cash = sum(account.Cash, v)
			d.DepositTotal = sum(d.DepositTotal, v)
		case protocol.InboxSupport:
			s.Support = sum(s.Support, v)
		case protocol.InboxInsurance:
			s.Insurance = sum(s.Insurance, v)
		default:
			return nil, Delta{}, errors.New("NATIVE_INBOX_BUCKET")
		}
		s.Total = sum(s.Total, v)
		s.InboxCursor++
	}
	d.InboxEnd = s.InboxCursor
	var err error
	d.InboxRoot, err = protocol.InboxEntriesRoot(entries)
	if err != nil {
		return nil, Delta{}, err
	}
	if err = e.validate(s); err != nil {
		return nil, Delta{}, err
	}
	return s, d, nil
}
