// Offline canonical genesis derivation. All database objects are in RAM.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/params"
)

func require(ok bool, text string) {
	if !ok { panic(text) }
}
func check(err error) { if err != nil { panic(err) } }

func main() {
	require(len(os.Args)==4,"usage: main.go genesis.json relay-config.json output.json")
	raw,err:=os.ReadFile(os.Args[1]);check(err)
	var genesis core.Genesis;check(json.Unmarshal(raw,&genesis))
	var keyGenesis core.GenesisKey;check(json.Unmarshal(raw,&keyGenesis))
	require(genesis.Config!=nil && genesis.Config.ChainID!=nil && genesis.Config.ChainID.IsUint64(),"missing chain ID")
	commitment,err:=params.FairHotstuffGenesisCommitment(genesis.Config);check(err)
	require(genesis.Mixhash==commitment,"FHS commitment mismatch")
	derived:=genesis.ToBlock(nil)
	db:=rawdb.NewMemoryDatabase();defer db.Close()
	_,keyHash,err:=core.SetupGenesisKeyBlock(db,&keyGenesis);check(err)
	chain,committedHash,err:=core.SetupGenesisBlock(db,&genesis);check(err)
	require(committedHash==derived.Hash(),"ToBlock and validated Commit hashes differ")
	_,reopenedHash,err:=core.SetupGenesisBlock(db,nil);check(err)
	require(reopenedHash==committedHash,"memory genesis reopen differs")
	var config struct { Network struct { ChainID uint64 `json:"chainId"`; GenesisHash string `json:"genesisHash"` } `json:"network"` }
	configBytes,err:=os.ReadFile(os.Args[2]);check(err);check(json.Unmarshal(configBytes,&config))
	require(config.Network.ChainID==chain.ChainID.Uint64(),"standard relay chain ID differs")
	require(config.Network.GenesisHash==committedHash.Hex(),"standard relay genesis pin differs")
	fingerprint:=sha256.Sum256(raw)
	result:=map[string]interface{}{
		"result":"PASS","observedAt":time.Now().UTC().Format(time.RFC3339Nano),
		"genesisPath":os.Args[1],"relayConfigPath":os.Args[2],"genesisFileSHA256":hex.EncodeToString(fingerprint[:]),
		"chainId":chain.ChainID.Uint64(),"genesisBlockHash":committedHash.Hex(),"keyGenesisBlockHash":keyHash.Hex(),
		"toBlockHash":derived.Hash().Hex(),"genesisStateRoot":derived.Root().Hex(),"fhsCommitment":commitment.Hex(),
		"fixedCommittee":chain.FixedCommittee,"fixedLeader":chain.FixedLeader,"fairHotstuff":chain.FairHotstuff,
		"committeeMembers":len(chain.GenCommittee),"standardRelayPinEqual":true,
		"checks":[]string{"native Genesis.ToBlock(nil)","native SetupGenesisKeyBlock in memory", "native SetupGenesisBlock validation and commit in memory", "native stored-config reopen validation in memory", "standard relay network pin equality"},
		"scope":map[string]interface{}{"liveNodeCalled":false,"existingDatadirOpened":false,"database":"rawdb.NewMemoryDatabase","genesisJSONModified":false,"consensusCodeModified":false},
	}
	encoded,err:=json.MarshalIndent(result,"","  ");check(err);check(os.WriteFile(os.Args[3],append(encoded,'\n'),0644))
	fmt.Println(string(encoded))
}
