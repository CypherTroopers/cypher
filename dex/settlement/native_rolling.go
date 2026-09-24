package settlement

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"sort"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

const MaxNativeAnchors = uint64(1024)

// RollingStatus is a read-only projection, not a finality certificate. External
// consumers must authenticate its storage slots against a verified CLX root.
type RollingStatus struct {
	TipHeight, ConfirmedThrough, Records uint64
}

func decodeRollingStatus(raw common.Hash) (RollingStatus, error) {
	s := RollingStatus{binary.BigEndian.Uint64(raw[:8]), binary.BigEndian.Uint64(raw[8:16]), binary.BigEndian.Uint64(raw[16:24])}
	if binary.BigEndian.Uint64(raw[24:]) != 0 || s.Records > MaxNativeAnchors || s.ConfirmedThrough > s.TipHeight || (s.Records == 0) != (s.TipHeight == 0) || s.Records > s.TipHeight {
		return RollingStatus{}, errors.New("invalid native rolling metadata")
	}
	return s, nil
}
func (s RollingStatus) encode() common.Hash {
	var out common.Hash
	binary.BigEndian.PutUint64(out[:8], s.TipHeight)
	binary.BigEndian.PutUint64(out[8:16], s.ConfirmedThrough)
	binary.BigEndian.PutUint64(out[16:24], s.Records)
	return out
}

func (a *Adapter) nativeCLXVerifier(config *params.ChainConfig, ctx NativeContext) (*clxevidence.Verifier, error) {
	if ctx.GenesisKeyHash == (common.Hash{}) {
		return nil, errors.New("trusted genesis keychain unavailable")
	}
	indices := make([]int, 0, len(config.GenCommittee))
	for i := range config.GenCommittee {
		indices = append(indices, i)
	}
	sort.Ints(indices)
	members := make([]*common.Cnode, 0, len(indices))
	for _, i := range indices {
		node := config.GenCommittee[i]
		members = append(members, &node)
	}
	return clxevidence.New(clxevidence.Config{ChainID: a.domain.ChainID, Genesis: ctx.Genesis, ChainConfig: config, Seed: config.FairHotstuffSeed, DEXID: a.domain.DEXID, Custody: a.custody, Epochs: []clxevidence.CommitteeEpoch{{First: 1, End: ^uint64(0), KeyHash: ctx.GenesisKeyHash, Members: members}}})
}

func (a *Adapter) anchorMatches(anchor clxevidence.Anchor) bool {
	return anchor.ChainID == a.domain.ChainID && anchor.Genesis == a.domain.Genesis && anchor.DEXID == a.domain.DEXID && anchor.Custody == [20]byte(a.custody)
}

func (a *Adapter) nativeAnchorUpdate(config *params.ChainConfig, ctx NativeContext, evidence clxevidence.RollingEvidence, continuation []clxevidence.HeaderWitness, raw []byte) ([]byte, error) {
	if (a.nativeVersion != 3 && a.nativeVersion != 4 && a.nativeVersion != 5) || len(evidence.Entries) != 0 || len(evidence.Headers) == 0 {
		return nil, errors.New("native anchor must advance certified tip")
	}
	// This bounded target-height lookup permits exact previously verified bytes
	// to replay without cryptography, initialization, surplus writes or logs.
	var target types.Header
	if err := rlp.DecodeBytes(evidence.Headers[len(evidence.Headers)-1].Header, &target); err != nil || target.Number == nil || !target.Number.IsUint64() || target.Number.Sign() == 0 || target.Number.Uint64() >= ctx.BlockNumber {
		return nil, errors.New("native anchor target is not an earlier source block")
	}
	height := target.Number.Uint64()
	status, err := decodeRollingStatus(a.get("rolling-meta", 0))
	if err != nil {
		return nil, err
	}
	digest := common.Hash(protocol.Digest("common-dex/native-anchor-evidence/v1", raw))
	if stored := a.get("rolling-evidence", height); stored != (common.Hash{}) {
		if stored != digest || height > status.TipHeight {
			return nil, errors.New("native anchor occupied height conflict")
		}
		anchor, err := ReadNativeAnchor(a.db, a.custody, height)
		if err != nil || !a.anchorMatches(anchor) {
			return nil, errors.New("native anchor replay identity")
		}
		id, _ := anchor.ID()
		return append(append([]byte(nil), id[:]...), 1), a.db.Error()
	}
	if (height <= status.TipHeight) != (len(continuation) > 0) {
		return nil, errors.New("native anchor continuation/target mismatch")
	}
	if status.Records >= MaxNativeAnchors {
		return nil, errors.New("native anchor record capacity")
	}
	verifier, err := a.nativeCLXVerifier(config, ctx)
	if err != nil {
		return nil, err
	}
	base, err := verifier.BootstrapAnchor()
	if err != nil {
		return nil, err
	}
	genesisID, err := base.ID()
	if err != nil {
		return nil, err
	}
	if evidence.Base != genesisID {
		baseHeight := a.db.GetState(a.custody, RollingAnchorIDStorageKey(evidence.Base)).Big()
		if !baseHeight.IsUint64() || baseHeight.Sign() == 0 {
			return nil, errors.New("native anchor base ID unavailable")
		}
		base, err = ReadNativeAnchor(a.db, a.custody, baseHeight.Uint64())
		baseID, idErr := base.ID()
		if err != nil || idErr != nil || baseID != evidence.Base || !a.anchorMatches(base) {
			return nil, errors.New("native certified base unavailable or inconsistent")
		}
	}
	if len(continuation) == 0 && base.Height != status.TipHeight {
		return nil, errors.New("native advance must extend current tip")
	}

	verified, anchor, err := verifier.VerifyRolling(base, 0, evidence)
	if err != nil {
		return nil, err
	}
	if !a.anchorMatches(anchor) || anchor.Height != height || anchor.BlockHash != protocol.Hash(target.Hash()) || anchor.InboxCount > a.number("deposits") {
		return nil, errors.New("native anchor derived identity/count")
	}
	// Old authenticated segments are staged only. GetHash is called exactly
	// once, and only in its prescribed recent window; it never walks a long lag.
	if len(continuation) > 0 {
		end, endAnchor, _, err := verifier.VerifyHeaderContext(anchor, verified.KeyContext(), continuation)
		if err != nil || end == nil || end.Number == nil || !end.Number.IsUint64() || end.Number.Uint64() <= height || end.Number.Uint64() > status.TipHeight {
			return nil, errors.New("native historical continuation invalid")
		}
		retained, err := ReadNativeAnchor(a.db, a.custody, end.Number.Uint64())
		if err != nil || !a.anchorMatches(retained) || retained.BlockHash != protocol.Hash(end.Hash()) || retained.StateRoot != protocol.Hash(end.Root) || anchor.InboxCount > retained.InboxCount || retained.Version != endAnchor.Version || retained.SourceKeyHash != endAnchor.SourceKeyHash || retained.SourceCommittee != endAnchor.SourceCommittee || retained.SourceEpoch != endAnchor.SourceEpoch || retained.ActivationEnd != endAnchor.ActivationEnd || retained.ActivationRoot != endAnchor.ActivationRoot {
			return nil, errors.New("native historical continuation not retained descendant")
		}
	} else if ctx.BlockNumber-height <= clxevidence.MaxAncestryBlocks {
		if ctx.GetHash(height) != common.Hash(anchor.BlockHash) {
			return nil, errors.New("native recent anchor is not the executing branch ancestor")
		}
		status.ConfirmedThrough = height
	}
	if len(continuation) == 0 {
		status.TipHeight = height
	}
	status.Records++
	encoded, err := anchor.Encode()
	if err != nil {
		return nil, err
	}
	id, err := anchor.ID()
	if err != nil {
		return nil, err
	}
	a.materializeNative()
	a.writeBlob("rolling-anchor", height, encoded)
	a.set("rolling-id", height, common.Hash(id))
	a.set("rolling-evidence", height, digest)
	a.set("rolling-meta", 0, status.encode())
	a.db.SetState(a.custody, RollingAnchorIDStorageKey(id), common.BigToHash(new(big.Int).SetUint64(height)))
	if err := a.db.Error(); err != nil {
		return nil, err
	}
	data := append([]byte(nil), id[:]...)
	var confirmed [8]byte
	binary.BigEndian.PutUint64(confirmed[:], status.ConfirmedThrough)
	data = append(data, confirmed[:]...)
	a.db.AddLog(&types.Log{Address: a.custody, Topics: []common.Hash{NativeAnchorTopic}, Data: data})
	return append(append([]byte(nil), id[:]...), 0), a.db.Error()
}

func ReadNativeRollingStatus(st NativeState, custody common.Address) (RollingStatus, error) {
	if st == nil {
		return RollingStatus{}, errors.New("native state unavailable")
	}
	s, err := decodeRollingStatus(st.GetState(custody, RollingMetadataStorageKey()))
	if err != nil {
		return s, err
	}
	return s, (stateWithError{st}).Error()
}

// ReadNativeAnchor returns only a retained record. Height zero is implicit and
// must instead be derived by Verifier.BootstrapAnchor from trusted genesis.
func ReadNativeAnchor(st NativeState, custody common.Address, height uint64) (clxevidence.Anchor, error) {
	if st == nil || height == 0 {
		return clxevidence.Anchor{}, errors.New("native stored anchor unavailable")
	}
	a := Adapter{db: stateWithError{st}, custody: custody}
	want := a.get("rolling-id", height)
	if want == (common.Hash{}) || a.get("rolling-evidence", height) == (common.Hash{}) {
		return clxevidence.Anchor{}, errors.New("native anchor record absent")
	}
	first := a.readBlob("rolling-anchor", height, 32)
	size, err := nativeAnchorEncodedSize(binary.BigEndian.Uint16(first[:2]))
	if err != nil {
		return clxevidence.Anchor{}, err
	}
	raw := a.readBlob("rolling-anchor", height, ((size+31)/32)*32)
	if !bytes.Equal(raw[size:], make([]byte, len(raw)-size)) {
		return clxevidence.Anchor{}, errors.New("native anchor storage padding")
	}
	anchor, err := clxevidence.DecodeAnchor(raw[:size])
	if err != nil {
		return clxevidence.Anchor{}, err
	}
	id, err := anchor.ID()
	if err != nil || common.Hash(id) != want || anchor.Height != height || anchor.Custody != [20]byte(custody) {
		return clxevidence.Anchor{}, errors.New("native anchor storage identity mismatch")
	}
	return anchor, a.db.Error()
}

// Typed read-only slot helpers describe proof requests; they neither read nor
// authenticate an RPC response, and do not grant a mutable StateDB capability.
func RollingMetadataStorageKey() common.Hash        { return key("rolling-meta", 0, 0) }
func CheckpointSequenceStorageKey() common.Hash     { return key("sequence", 0, 0) }
func CheckpointAcceptedHashStorageKey() common.Hash { return key("accepted-hash", 0, 0) }
func InboxCursorStorageKey() common.Hash            { return key("cursor", 0, 0) }
func CheckpointHistoryStorageKey(sequence uint64) (common.Hash, error) {
	if sequence == 0 || sequence > 4096 {
		return common.Hash{}, errors.New("checkpoint history slot bound")
	}
	return key("history", sequence, 0), nil
}
func ClaimNullifierStorageKey(claim protocol.Claim) (common.Hash, error) {
	nullifier, err := claim.Nullifier()
	if err != nil {
		return common.Hash{}, err
	}
	return common.Hash(protocol.Digest("common-dex/settlement/nullifier/v1", nullifier[:])), nil
}

// The original helper retains the eight-word v1 request exactly. Consumers
// reading either version can request the bounded v2 superset and inspect the
// authenticated first word's version before decoding its payload.
func RollingAnchorStorageKeys(height uint64) ([]common.Hash, error) {
	return RollingAnchorStorageKeysVersion(height, 1)
}
func nativeAnchorEncodedSize(version uint16) (int, error) {
	switch version {
	case 1:
		return clxevidence.AnchorSize, nil
	case 2:
		return clxevidence.AnchorV2Size, nil
	default:
		return 0, errors.New("unsupported native anchor storage version")
	}
}
func RollingAnchorStorageKeysVersion(height uint64, version uint16) ([]common.Hash, error) {
	if height == 0 {
		return nil, errors.New("genesis anchor has no stored slots")
	}
	size, err := nativeAnchorEncodedSize(version)
	if err != nil {
		return nil, err
	}
	slots := uint32((size + 31) / 32)
	out := make([]common.Hash, 0, slots+2)
	for i := uint32(0); i < slots; i++ {
		out = append(out, key("rolling-anchor", height, i))
	}
	return append(out, key("rolling-id", height, 0), key("rolling-evidence", height, 0)), nil
}

// RollingAnchorIDStorageKey locates the retained height for an authenticated ID.
func RollingAnchorIDStorageKey(id protocol.Hash) common.Hash {
	return common.Hash(protocol.Digest("common-dex/settlement/rolling-height-by-id/v1", id[:]))
}
