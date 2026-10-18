package rawdb

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/ethdb"
)

var fhsSafetyStateKey = []byte("cypher-fhs-safety")

var (
	fhsProposalPrefix    = []byte("cypher-fhs-proposal/")
	fhsBodyPrefix        = []byte("cypher-fhs-body/")
	fhsCertificatePrefix = []byte("cypher-fhs-cert/")
)

func fhsHashKey(prefix []byte, hash common.Hash) []byte {
	key := make([]byte, len(prefix)+len(hash))
	copy(key, prefix)
	copy(key[len(prefix):], hash[:])
	return key
}

// ReadFHSSafetyState returns the opaque RLP safety record. Encoding belongs to
// reconfig/hotstuff so rawdb does not create a consensus import cycle.
func ReadFHSSafetyState(db ethdb.KeyValueReader) ([]byte, error) {
	has, err := db.Has(fhsSafetyStateKey)
	if err != nil || !has {
		return nil, err
	}
	data, err := db.Get(fhsSafetyStateKey)
	return common.CopyBytes(data), err
}

func WriteFHSSafetyState(db ethdb.KeyValueWriter, data []byte) error {
	return db.Put(fhsSafetyStateKey, common.CopyBytes(data))
}

func ReadFHSProposal(db ethdb.KeyValueReader, proposalID common.Hash) ([]byte, error) {
	key := fhsHashKey(fhsProposalPrefix, proposalID)
	has, err := db.Has(key)
	if err != nil || !has {
		return nil, err
	}
	data, err := db.Get(key)
	return common.CopyBytes(data), err
}

func WriteFHSProposal(db ethdb.KeyValueWriter, proposalID common.Hash, data []byte) error {
	return db.Put(fhsHashKey(fhsProposalPrefix, proposalID), common.CopyBytes(data))
}

func DeleteFHSProposal(db ethdb.KeyValueWriter, proposalID common.Hash) error {
	return db.Delete(fhsHashKey(fhsProposalPrefix, proposalID))
}

// IterateFHSProposals visits every durable proposal proof. The value is owned
// by the iterator and is only valid for the duration of the callback.
func IterateFHSProposals(db ethdb.Iteratee, visit func(common.Hash, []byte) error) error {
	return iterateFHSHashRecords(db, fhsProposalPrefix, visit)
}

func ReadFHSBody(db ethdb.KeyValueReader, bodyHash common.Hash) ([]byte, error) {
	key := fhsHashKey(fhsBodyPrefix, bodyHash)
	has, err := db.Has(key)
	if err != nil || !has {
		return nil, err
	}
	data, err := db.Get(key)
	return common.CopyBytes(data), err
}

func WriteFHSBody(db ethdb.KeyValueWriter, bodyHash common.Hash, data []byte) error {
	return db.Put(fhsHashKey(fhsBodyPrefix, bodyHash), common.CopyBytes(data))
}

func DeleteFHSBody(db ethdb.KeyValueWriter, bodyHash common.Hash) error {
	return db.Delete(fhsHashKey(fhsBodyPrefix, bodyHash))
}

// IterateFHSBodies visits content-addressed body hashes without loading the
// potentially multi-megabyte values from disk.
func IterateFHSBodies(db ethdb.Iteratee, visit func(common.Hash) error) error {
	if db == nil || visit == nil {
		return fmt.Errorf("invalid FHS body iterator")
	}
	iterator := db.NewIterator(fhsBodyPrefix, nil)
	defer iterator.Release()
	for iterator.Next() {
		key := iterator.Key()
		if len(key) != len(fhsBodyPrefix)+common.HashLength {
			return fmt.Errorf("invalid FHS record key length %d for prefix %q", len(key), fhsBodyPrefix)
		}
		if err := visit(common.BytesToHash(key[len(fhsBodyPrefix):])); err != nil {
			return err
		}
	}
	return iterator.Error()
}

// Certificates are keyed by proposal identity, which includes the view. The
// same execution block may have independently valid certificates in many views.
func ReadFHSCertificate(db ethdb.KeyValueReader, proposalID common.Hash) ([]byte, error) {
	key := fhsHashKey(fhsCertificatePrefix, proposalID)
	has, err := db.Has(key)
	if err != nil || !has {
		return nil, err
	}
	data, err := db.Get(key)
	return common.CopyBytes(data), err
}

func WriteFHSCertificate(db ethdb.KeyValueWriter, proposalID common.Hash, data []byte) error {
	return db.Put(fhsHashKey(fhsCertificatePrefix, proposalID), common.CopyBytes(data))
}

func DeleteFHSCertificate(db ethdb.KeyValueWriter, proposalID common.Hash) error {
	return db.Delete(fhsHashKey(fhsCertificatePrefix, proposalID))
}

// IterateFHSCertificates visits every durable certificate. The value is owned
// by the iterator and is only valid for the duration of the callback.
func IterateFHSCertificates(db ethdb.Iteratee, visit func(common.Hash, []byte) error) error {
	return iterateFHSHashRecords(db, fhsCertificatePrefix, visit)
}

func iterateFHSHashRecords(db ethdb.Iteratee, prefix []byte, visit func(common.Hash, []byte) error) error {
	if db == nil || visit == nil {
		return fmt.Errorf("invalid FHS record iterator")
	}
	iterator := db.NewIterator(prefix, nil)
	defer iterator.Release()
	for iterator.Next() {
		key := iterator.Key()
		if len(key) != len(prefix)+common.HashLength {
			return fmt.Errorf("invalid FHS record key length %d for prefix %q", len(key), prefix)
		}
		if err := visit(common.BytesToHash(key[len(prefix):]), iterator.Value()); err != nil {
			return err
		}
	}
	return iterator.Error()
}

// FHSCheckpointRecord preserves an existing database record byte for byte.
type FHSCheckpointRecord struct{ Key, Value []byte }

var fhsCheckpointReadyKey = []byte("cypher-fhs-checkpoint-ready")

// ReadFHSCheckpointReady reads the opaque completed-checkpoint descriptor.
func ReadFHSCheckpointReady(db ethdb.KeyValueReader) ([]byte, error) {
	has, err := db.Has(fhsCheckpointReadyKey)
	if err != nil || !has {
		return nil, err
	}
	return db.Get(fhsCheckpointReadyKey)
}

func FHSCheckpointReadyRecord(data []byte) FHSCheckpointRecord {
	return FHSCheckpointRecord{common.CopyBytes(fhsCheckpointReadyKey), common.CopyBytes(data)}
}

// FHSCheckpointGenesisRecords contains immutable transaction-genesis metadata.
// Mutable head markers are intentionally excluded.
// Get reads whole values; maxBytes bounds accepted records, not pre-read allocation.
func FHSCheckpointGenesisRecords(db ethdb.KeyValueReader, hash common.Hash, maxBytes uint64) ([]FHSCheckpointRecord, error) {
	keys := [][]byte{headerHashKey(0), headerNumberKey(hash), headerKey(0, hash), blockBodyKey(0, hash), headerTDKey(0, hash), blockReceiptsKey(0, hash), configKey(hash)}
	records := make([]FHSCheckpointRecord, 0, len(keys))
	for _, key := range keys {
		value, err := db.Get(key)
		if err != nil {
			return nil, fmt.Errorf("checkpoint metadata %x: %w", key, err)
		}
		size := uint64(len(key)) + uint64(len(value))
		if len(value) == 0 || size > maxBytes {
			return nil, fmt.Errorf("checkpoint metadata missing or exceeds accepted byte limit")
		}
		maxBytes -= size
		records = append(records, FHSCheckpointRecord{common.CopyBytes(key), common.CopyBytes(value)})
	}
	if !bytes.Equal(records[0].Value, hash[:]) {
		return nil, fmt.Errorf("checkpoint genesis is not canonical")
	}
	return records, nil
}

// FHSCheckpointBlockKeys provides the fixed transaction record order for a
// checkpoint cursor which admits and reads only one record per Step.
func FHSCheckpointBlockKeys(number uint64, hash common.Hash) [][]byte {
	return [][]byte{headerHashKey(number), headerNumberKey(hash), headerKey(number, hash), blockBodyKey(number, hash), headerTDKey(number, hash), blockReceiptsKey(number, hash)}
}

// FHSCheckpointKeyKeys provides canonical mapping, number, header, body,
// difficulty and committee keys. A key header does not commit its body; callers
// authenticate non-genesis bodies against canonical transaction carriers and
// check the committee commitment before acknowledging these records.
func FHSCheckpointKeyKeys(number uint64, hash common.Hash) [][]byte {
	return [][]byte{keyBlockHashKey(number), keyBlockHeaderNumberKey(hash), keyBlockHeaderKey(number, hash), keyBlockBodyKey(number, hash), headerTDKey(number, hash), CommitteeKey(number, hash)}
}

// FHSCheckpointConfigKey identifies the existing genesis configuration record.
func FHSCheckpointConfigKey(hash common.Hash) []byte {
	return configKey(hash)
}

// FHSCheckpointHeadKeys provides the mutable marker order: transaction full
// head, transaction header head, fast head, key full head and key header head.
// The caller must hold the chain lock and check that these still identify the
// selected checkpoint heads before synchronously rewriting any marker.
func FHSCheckpointHeadKeys() [][]byte {
	return [][]byte{common.CopyBytes(headBlockKey), common.CopyBytes(headHeaderKey), common.CopyBytes(headFastBlockKey), common.CopyBytes(headKeyBlockKey), common.CopyBytes(headKeyHeaderKey)}
}

// ReadFHSCheckpointCode preserves legacy and prefixed code lookup and read errors.
func ReadFHSCheckpointCode(db ethdb.KeyValueReader, hash common.Hash) (FHSCheckpointRecord, error) {
	for _, key := range [][]byte{hash.Bytes(), codeKey(hash)} {
		has, err := db.Has(key)
		if err != nil {
			return FHSCheckpointRecord{}, err
		}
		if !has {
			continue
		}
		value, err := db.Get(key)
		if err != nil {
			return FHSCheckpointRecord{}, err
		}
		if len(value) > 0 {
			return FHSCheckpointRecord{key, value}, nil
		}
	}
	return FHSCheckpointRecord{}, fmt.Errorf("checkpoint code %s missing", hash)
}

func ReadFHSCheckpointCanonical(db ethdb.KeyValueReader) (common.Hash, error) {
	return ReadFHSCheckpointCanonicalAt(db, 0)
}

// ReadFHSCheckpointCanonicalAt preserves read errors and requires an exact hash.
func ReadFHSCheckpointCanonicalAt(db ethdb.KeyValueReader, number uint64) (common.Hash, error) {
	value, err := db.Get(headerHashKey(number))
	if err != nil {
		return common.Hash{}, err
	}
	if len(value) != common.HashLength {
		return common.Hash{}, fmt.Errorf("invalid checkpoint canonical mapping at %d", number)
	}
	return common.BytesToHash(value), nil
}

// ReadFHSCheckpointNumber preserves read errors and requires an exact uint64.
func ReadFHSCheckpointNumber(db ethdb.KeyValueReader, hash common.Hash) (uint64, error) {
	value, err := db.Get(headerNumberKey(hash))
	if err != nil {
		return 0, err
	}
	if len(value) != 8 {
		return 0, fmt.Errorf("invalid checkpoint block number for %s", hash)
	}
	return binary.BigEndian.Uint64(value), nil
}
