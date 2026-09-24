package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

type state struct {
	Safety *hotstuff.FHSSafetyState
	Records map[string]*consensus.Record
	Finalized []json.RawMessage
}

func main() {
	out := []map[string]interface{}{}
	for _, node := range os.Args[1:] {
		p := filepath.Join("build/stage/live-generation-candidate/runtime",node,"dex/fhs/state-00000000000000000000.json")
		b,e := os.ReadFile(p); if e != nil { panic(e) }
		var env struct{ Payload json.RawMessage }; if e=json.Unmarshal(b,&env);e!=nil {panic(e)}
		var d state; if e=json.Unmarshal(env.Payload,&d);e!=nil {panic(e)}
		index:=map[string]*hotstuff.SignedState{}
		for _,r:=range d.Records {if r.QC!=nil {id,e:=hotstuff.SignedStateID(r.QC);if e!=nil {panic(e)};index[id.Hash().Hex()]=r.QC}}
		q:=d.Safety.HighestQC
		chain:=[]map[string]interface{}{}
		for q!=nil {
			r,e:=types.DecodeHotstuffProposalRef(q.State);if e!=nil {panic(e)}
			chain=append(chain,map[string]interface{}{"height":r.Number,"view":r.ViewNumber,"checkpoint_hash":r.BlockHash.Hex(),"parent_hash":r.ParentHash.Hex(),"parent_qc_id":r.ParentQCID.Hex()})
			if r.Number==1 {break}
			q=index[r.ParentQCID.Hex()];if q==nil {panic("missing authenticated parent QC")}
		}
		h:=sha256.Sum256(b)
		out=append(out,map[string]interface{}{"node":node,"wal_sha256":hex.EncodeToString(h[:]),"finalized_count":len(d.Finalized),"record_count":len(d.Records),"highest_timeout_view":d.Safety.LastTimeoutView,"chain_tip_to_genesis":chain})
	}
	b,e:=json.MarshalIndent(out,"","  ");if e!=nil {panic(e)};fmt.Println(string(b))
}
