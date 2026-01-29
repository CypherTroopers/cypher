package core

import (
	"fmt"
	"io"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
)

const (
	ExportKindBlock uint8 = iota
	ExportKindKeyBlock
	ExportKindCommittee
)

type ExportItem struct {
	Kind    uint8
	Payload rlp.RawValue
}

type ExportCommittee struct {
	KeyNumber uint64
	KeyHash   common.Hash
	Committee *bftview.Committee
}

func EncodeExportItem(w io.Writer, kind uint8, payload interface{}) error {
	data, err := rlp.EncodeToBytes(payload)
	if err != nil {
		return err
	}
	return rlp.Encode(w, ExportItem{Kind: kind, Payload: data})
}

func DecodeExportItem(raw rlp.RawValue) (*ExportItem, error) {
	var item ExportItem
	if err := rlp.DecodeBytes(raw, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func (bc *BlockChain) exportKeyBlocksAndCommittees(w io.Writer) error {
	if bc.keyBlockChain == nil {
		return nil
	}
	head := bc.keyBlockChain.CurrentBlockN()
	log.Info("Exporting batch of key blocks", "count", head+1)

	start, reported := time.Now(), time.Now()
	for nr := uint64(0); nr <= head; nr++ {
		block := bc.keyBlockChain.GetBlockByNumber(nr)
		if block == nil {
			return fmt.Errorf("export failed on keyblock #%d: not found", nr)
		}
		if err := EncodeExportItem(w, ExportKindKeyBlock, block); err != nil {
			return err
		}

		committeeData, _ := bc.db.Get(rawdb.CommitteeKey(nr, block.Hash()))
		if len(committeeData) == 0 {
			log.Warn("Missing committee for key block during export", "number", nr, "hash", block.Hash())
		} else {
			var committee bftview.Committee
			if err := rlp.DecodeBytes(committeeData, &committee); err != nil {
				return fmt.Errorf("invalid committee RLP for keyblock #%d: %w", nr, err)
			}
			payload := &ExportCommittee{
				KeyNumber: nr,
				KeyHash:   block.Hash(),
				Committee: &committee,
			}
			if err := EncodeExportItem(w, ExportKindCommittee, payload); err != nil {
				return err
			}
		}

		if time.Since(reported) >= statsReportLimit {
			log.Info("Exporting key blocks", "exported", block.NumberU64(), "elapsed", common.PrettyDuration(time.Since(start)))
			reported = time.Now()
		}
	}
	return nil
}
