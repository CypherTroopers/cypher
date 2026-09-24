package settlement

import (
	"errors"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/params"
)

func (a *Adapter) nativeAccept(config *params.ChainConfig, ctx NativeContext, c protocol.Checkpoint, f protocol.FinanceSummary, proof, evidence []byte) (Acceptance, error) {
	var result Acceptance
	schema := uint16(3)
	if config.DEXDevnet.Version == 3 {
		schema = 4
	}
	if config.DEXDevnet.Version == 4 {
		schema = 5
	}
	if config.DEXDevnet.AncestryProofs() {
		schema = 6
	}
	if c.DataSchema != schema || (config.DEXDevnet.RollingAnchors() && len(evidence) != 0) {
		return result, errors.New("native checkpoint schema/evidence mismatch")
	}
	if a.get("history", c.Sequence) != (common.Hash{}) {
		return a.acceptVerified(c, f, proof, &verifiedInbox{})
	}
	if c.InboxEnd < c.InboxStart || c.InboxEnd-c.InboxStart > protocol.MaxDepositsPerCheckpoint || c.InboxEnd > a.number("deposits") || c.InboxStart != a.number("cursor") || c.CLXHeight >= ctx.BlockNumber {
		return result, errors.New("native checkpoint ancestor/range")
	}
	if config.DEXDevnet.RollingAnchors() {
		status, err := ReadNativeRollingStatus(a.db, a.custody)
		if err != nil || c.CLXHeight == 0 || c.CLXHeight > status.ConfirmedThrough {
			return result, errors.New("native checkpoint anchor is not confirmed")
		}
		anchor, err := ReadNativeAnchor(a.db, a.custody, c.CLXHeight)
		if err != nil || !a.anchorMatches(anchor) || anchor.BlockHash != c.CLXHash || c.InboxEnd > anchor.InboxCount {
			return result, errors.New("native checkpoint retained anchor mismatch")
		}
	} else {
		if ctx.BlockNumber-c.CLXHeight > clxevidence.MaxAncestryBlocks || ctx.GetHash(c.CLXHeight) != common.Hash(c.CLXHash) {
			return result, errors.New("native checkpoint recent ancestor mismatch")
		}
		if len(evidence) > 0 {
			if ctx.GenesisKeyHash == (common.Hash{}) {
				return result, errors.New("trusted genesis keychain unavailable")
			}
			encoded, err := clxevidence.DecodeRangeEvidence(evidence)
			if err != nil {
				return result, err
			}
			verifier, err := a.nativeCLXVerifier(config, ctx)
			if err != nil {
				return result, err
			}
			verified, err := verifier.VerifyRange(c.InboxStart, encoded)
			if err != nil {
				return result, err
			}
			header := verified.Header()
			entries := verified.Entries()
			if header.Number == nil || header.Number.Uint64() != c.CLXHeight || header.Hash() != common.Hash(c.CLXHash) || uint64(len(entries)) != c.InboxEnd-c.InboxStart || verified.Count() > a.number("deposits") {
				return result, errors.New("native evidence checkpoint mismatch")
			}
			for i, entry := range entries {
				stored, err := ReadNativeEntry(a.db, a.custody, c.InboxStart+uint64(i))
				if err != nil || stored != entry {
					return result, errors.New("native finalized entry mismatch")
				}
			}
			a.set("native-anchor", c.CLXHeight, common.Hash(c.CLXHash))
			a.set("native-anchor-count", c.CLXHeight, common.BigToHash(new(big.Int).SetUint64(verified.Count())))
		}
		if a.get("native-anchor", c.CLXHeight) != common.Hash(c.CLXHash) || c.InboxEnd > new(big.Int).SetBytes(a.get("native-anchor-count", c.CLXHeight).Bytes()).Uint64() {
			return result, errors.New("native inbox anchor is not certified")
		}
	}
	entries := make([]protocol.InboxEntry, 0, c.InboxEnd-c.InboxStart)
	total := new(big.Int)
	for i := c.InboxStart; i < c.InboxEnd; i++ {
		entry, err := ReadNativeEntry(a.db, a.custody, i)
		if err != nil {
			return result, err
		}
		if entry.ChainID != a.domain.ChainID || entry.Genesis != a.domain.Genesis || entry.DEXID != a.domain.DEXID || entry.Custody != [20]byte(a.custody) || entry.Index != i || new(big.Int).SetBytes(a.get("native-entry-height", i).Bytes()).Uint64() > c.CLXHeight {
			return result, errors.New("native inbox identity/height")
		}
		entries = append(entries, entry)
		if entry.Bucket == protocol.InboxTrader {
			total.Add(total, entry.Amount.Big())
		}
	}
	root, err := protocol.InboxEntriesRoot(entries)
	if err != nil {
		return result, err
	}
	amount, err := protocol.AmountFromBig(total)
	if err != nil {
		return result, err
	}
	return a.acceptVerified(c, f, proof, &verifiedInbox{root: root, total: amount})
}
