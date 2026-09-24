package main

// Preparing an integrated leader submission patch never writes to the candidate
// or any data directory. Applying it is a separate, stopped-process operation.
import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cypherium/cypher/dex/clxevidence"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/params"
)

type leaderPatchChange struct {
	Target, Prepared, BeforeSHA256, SHA256 string
}
type leaderPatch struct {
	Version           int
	Candidate         string
	ChainID           uint64
	Genesis, DEXID    string
	Inputs            map[string]string
	Changes           []leaderPatchChange
	RequiresStopped   []string
	ApplyInstructions []string
}

func prepareLeaderSubmissionPatch(candidate, genesisPath, selectionPath, out string) (*leaderPatch, error) {
	if err := privateOwnedDirectory(candidate); err != nil {
		return nil, err
	}
	for _, p := range []string{genesisPath, selectionPath, out} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, errors.New("absolute clean input/output paths required")
		}
	}
	if out == candidate || strings.HasPrefix(out, candidate+string(os.PathSeparator)) || strings.HasPrefix(candidate, out+string(os.PathSeparator)) || selectionPath == filepath.Join(candidate, "local-deployment.json") {
		return nil, errors.New("patch output must be separate from candidate")
	}
	plan := &leaderPatch{Version: 1, Candidate: candidate, Inputs: map[string]string{}, RequiresStopped: []string{"cyphermine", "cypherdex1", "cypherdex2", "cypherdex3", "cypherdex4", "cypherdex5", "cypherdex6", "cypherdex-relay0", "cypherdex-relay1"}, ApplyInstructions: []string{"Prepare only: no existing file or runtime state was modified", "Stop the listed Common and historical relay owners and verify every child process has exited", "Recheck every Inputs SHA256 and each new target absence before applying", "Install private keys and submission configs first, then seven manifests and inventory, then both deployment selections last using same-directory fsync/rename", "Never delete or reset any old relay journal or runtime data; old configs are recorded as RetiredRelayConfigs", "Keep all target applications stopped until every prepared SHA256 matches its installed target"}}
	read := func(path string) ([]byte, error) {
		// Public configuration may be 0644. Reuse the established bounded reader
		// after rejecting every symlink ancestor and special/hard-linked file.
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("configuration path must be absolute and clean")
		}
		for p := path; p != filepath.Dir(p); p = filepath.Dir(p) {
			s, e := os.Lstat(p)
			if e != nil || s.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("configuration symlink or missing ancestor")
			}
		}
		s, e := os.Lstat(path)
		if e != nil || !s.Mode().IsRegular() || s.Size() > 1024*1024 {
			return nil, errors.New("configuration file type/size")
		}
		if st, ok := s.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 {
			return nil, errors.New("configuration hardlink unsupported")
		}
		b, e := os.ReadFile(path)
		if e == nil {
			plan.Inputs[path] = digest(b)
		}
		return b, e
	}
	inventoryPath := filepath.Join(candidate, "public", "inventory.json")
	raw, e := read(inventoryPath)
	if e != nil {
		return nil, e
	}
	var inv inventory
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &inv) != nil || json.Unmarshal(raw, &fields) != nil {
		return nil, errors.New("candidate inventory JSON")
	}
	if inv.ConfigurationVersion != 5 || inv.ChainID != oldChainID || len(inv.Participants) != 7 || len(inv.RelayConfigs) != 2 || len(inv.LeaderSubmissionConfigs) != 0 {
		return nil, errors.New("requires existing v5 candidate with two historical relays and seven participants")
	}
	if _, exists := fields["RetiredRelayConfigs"]; exists {
		return nil, errors.New("candidate already has retired submission owners")
	}
	genesisRaw, e := read(genesisPath)
	if e != nil {
		return nil, e
	}
	candidateGenesis, e := read(filepath.Join(candidate, "genesis.json"))
	if e != nil {
		return nil, e
	}
	var genesis core.Genesis
	if digest(genesisRaw) != inv.GenesisSHA256 || string(genesisRaw) != string(candidateGenesis) || json.Unmarshal(genesisRaw, &genesis) != nil || genesis.Config == nil || genesis.Config.ChainID == nil || genesis.Config.DEXDevnet == nil || genesis.Config.DEXDevnet.Version != 5 || genesis.Config.ChainID.Uint64() != inv.ChainID || genesis.Config.DEXDevnet.DEXID.Hex() != inv.DEXID || genesis.ToBlock(nil).Hash().Hex() != inv.Genesis {
		return nil, errors.New("current genesis and authenticated candidate identity differ")
	}
	commitment, e := params.FairHotstuffGenesisCommitment(genesis.Config)
	if e != nil || genesis.Mixhash != commitment {
		return nil, errors.New("authenticated genesis commitment differs")
	}
	plan.ChainID, plan.Genesis, plan.DEXID = inv.ChainID, inv.Genesis, inv.DEXID
	var templates [2]relayManifest
	for n, path := range inv.RelayConfigs {
		if path != filepath.Join(candidate, "relays", fmt.Sprintf("relay-%d.json", n)) {
			return nil, errors.New("unexpected historical relay path")
		}
		b, e := read(path)
		if e != nil {
			return nil, e
		}
		if json.Unmarshal(b, &templates[n]) != nil {
			return nil, errors.New("historical relay configuration JSON")
		}
		t := templates[n]
		if t.Version != 2 || !t.Devnet || t.Domain.Version != 1 || t.Domain.Epoch != 1 || t.Domain.ChainID != inv.ChainID || h(t.Domain.Genesis) != inv.Genesis || h(t.Domain.DEXID) != inv.DEXID || h(t.Domain.Committee) != inv.DEXCommittee || t.Custody != params.DEXSettlementAddress || t.CLX.Genesis == nil || t.CLX.Genesis.Hash().Hex() != inv.Genesis || t.CLX.ChainConfig == nil || !t.CLX.ChainConfig.DEXDevnet.AncestryProofs() || t.SourceURL != "http://127.0.0.1:8999" || t.SubmitURL != t.SourceURL || t.MaxHeight != inv.MaxHeight {
			return nil, errors.New("historical relay does not match authenticated candidate")
		}
		if _, err := clxevidence.New(t.CLX); err != nil {
			return nil, errors.New("historical source authentication configuration invalid")
		}
	}
	var manifestFields []map[string]json.RawMessage
	var selectionFields []map[string]json.RawMessage
	selectionPaths := []string{filepath.Join(candidate, "local-deployment.json"), selectionPath}
	seenNames := map[string]bool{}
	for n, p := range inv.Participants {
		if p.Name != plan.RequiresStopped[n] || seenNames[p.Name] || p.Manifest != filepath.Join(candidate, "manifests", p.Name+".json") || p.DEXDataDir != filepath.Join(candidate, "runtime", p.Name, "dex") {
			return nil, errors.New("participant path/order differs")
		}
		seenNames[p.Name] = true
		b, e := read(p.Manifest)
		if e != nil {
			return nil, e
		}
		var mf map[string]json.RawMessage
		var shape struct {
			Domain             interface{}
			LeaderSubmission   string
			Index              uint8
			DataDir, APIListen string
		}
		if json.Unmarshal(b, &mf) != nil || json.Unmarshal(b, &shape) != nil || shape.LeaderSubmission != "" || shape.Index != uint8(n) || shape.DataDir != p.DEXDataDir || shape.APIListen != p.API {
			return nil, errors.New("participant manifest ownership differs")
		}
		var domainRaw interface{}
		domainBytes, _ := json.Marshal(templates[0].Domain)
		json.Unmarshal(domainBytes, &domainRaw)
		shapeBytes, _ := json.Marshal(shape.Domain)
		if string(shapeBytes) != string(domainBytes) {
			// Compare semantic JSON because map key ordering differs from struct encoding.
			a, _ := json.Marshal(domainRaw)
			if string(shapeBytes) != string(a) {
				return nil, errors.New("participant submission domain differs")
			}
		}
		manifestFields = append(manifestFields, mf)
	}
	for _, path := range selectionPaths {
		b, e := read(path)
		if e != nil {
			return nil, e
		}
		var sf map[string]json.RawMessage
		var selected struct {
			Version                                       int    `json:"version"`
			ChainID                                       uint64 `json:"chain_id"`
			GenesisSHA256, DEXID, Inventory, InventorySHA string
			Participants                                  map[string]struct {
				Enabled          bool `json:"enabled"`
				Manifest, SHA256 string
			} `json:"participants"`
		}
		if json.Unmarshal(b, &sf) != nil || json.Unmarshal(b, &selected) != nil {
			return nil, errors.New("deployment selection JSON")
		}
		// These names differ from Go field names, so explicitly decode identity fields.
		json.Unmarshal(sf["genesis_sha256"], &selected.GenesisSHA256)
		json.Unmarshal(sf["dex_id"], &selected.DEXID)
		json.Unmarshal(sf["generation_inventory"], &selected.Inventory)
		json.Unmarshal(sf["generation_inventory_sha256"], &selected.InventorySHA)
		if selected.Version != 1 || selected.ChainID != inv.ChainID || selected.GenesisSHA256 != inv.GenesisSHA256 || selected.DEXID != inv.DEXID || selected.Inventory != inventoryPath || selected.InventorySHA != digest(raw) || len(selected.Participants) != 7 {
			return nil, errors.New("deployment selection differs from current candidate")
		}
		for _, p := range inv.Participants {
			item, ok := selected.Participants[p.Name]
			if !ok || item.Manifest != p.Manifest || item.SHA256 != plan.Inputs[p.Manifest] {
				return nil, errors.New("selected participant differs from manifest")
			}
		}
		selectionFields = append(selectionFields, sf)
	}
	// Everything above is read-only. New files are created exclusively under out.
	if e = privateRoot(out); e != nil {
		return nil, e
	}
	for _, name := range []string{"keys", "submissions", "manifests", "public", "selections"} {
		if e = os.Mkdir(filepath.Join(out, name), 0700); e != nil {
			return nil, e
		}
	}
	change := func(target, prepared string, b []byte) error {
		if e := put(prepared, b); e != nil {
			return e
		}
		plan.Changes = append(plan.Changes, leaderPatchChange{Target: target, Prepared: prepared, BeforeSHA256: plan.Inputs[target], SHA256: digest(b)})
		return nil
	}
	encode := func(v interface{}) []byte { b, _ := json.MarshalIndent(v, "", "  "); return append(b, '\n') }
	seenAddresses := map[string]bool{}
	seenPurposes := map[string]bool{}
	for _, k := range inv.Keys {
		seenAddresses[strings.ToLower(k.Address)] = true
		seenPurposes[k.Purpose] = true
	}
	inv.LeaderSubmissionConfigs = nil
	for n, p := range inv.Participants {
		cfg := templates[0]
		cfg.DataDir = filepath.Join(p.DEXDataDir, "submission")
		cfg.DEXURL = "http://" + p.API
		cfg.AutoInbox = true
		cfg.Payers = nil
		for _, lane := range []string{"anchor", "checkpoint", "claim"} {
			purpose := fmt.Sprintf("submission-%d-%s-gas", n, lane)
			target := filepath.Join(candidate, "keys", purpose+".key")
			if _, e := os.Lstat(target); !os.IsNotExist(e) || seenPurposes[purpose] {
				return nil, errors.New("submission key target already exists")
			}
			key, e := newAccount(out, purpose)
			if e != nil {
				return nil, e
			}
			if seenAddresses[strings.ToLower(key.Address)] {
				return nil, errors.New("duplicate generated gas identity")
			}
			seenAddresses[strings.ToLower(key.Address)] = true
			b, e := os.ReadFile(key.KeyFile)
			if e != nil {
				return nil, e
			}
			plan.Changes = append(plan.Changes, leaderPatchChange{Target: target, Prepared: key.KeyFile, SHA256: digest(b)})
			key.KeyFile = target
			inv.Keys = append(inv.Keys, key)
			cfg.Payers = append(cfg.Payers, relayPayer{Lane: lane, Purpose: "leader-submission-gas", Address: common.HexToAddress(key.Address), KeyFile: target, GasLimit: 20000000})
			amount := "1000000000000000000"
			if lane == "checkpoint" {
				amount = "6000000000000000000"
			}
			inv.Funding = append(inv.Funding, funding{From: genesis.Config.GenCommittee[0].CoinBase, Recipient: key.Address, Purpose: purpose, AmountAtoms: amount})
		}
		target := filepath.Join(candidate, "submissions", p.Name+".json")
		if _, e := os.Lstat(target); !os.IsNotExist(e) {
			return nil, errors.New("submission config already exists")
		}
		if e = change(target, filepath.Join(out, "submissions", p.Name+".json"), encode(cfg)); e != nil {
			return nil, e
		}
		inv.LeaderSubmissionConfigs = append(inv.LeaderSubmissionConfigs, target)
		inv.Participants[n].SubmissionConfig = target
		mf := manifestFields[n]
		mf["LeaderSubmission"], _ = json.Marshal(target)
		if e = change(p.Manifest, filepath.Join(out, "manifests", p.Name+".json"), encode(mf)); e != nil {
			return nil, e
		}
	}
	fields["RetiredRelayConfigs"], _ = json.Marshal(inv.RelayConfigs)
	fields["RelayConfigs"], _ = json.Marshal([]string{})
	fields["LeaderSubmissionConfigs"], _ = json.Marshal(inv.LeaderSubmissionConfigs)
	fields["Participants"], _ = json.Marshal(inv.Participants)
	fields["Keys"], _ = json.Marshal(inv.Keys)
	fields["Funding"], _ = json.Marshal(inv.Funding)
	inventoryNext := encode(fields)
	if e = change(inventoryPath, filepath.Join(out, "public", "inventory.json"), inventoryNext); e != nil {
		return nil, e
	}
	for n, sf := range selectionFields {
		sf["generation_inventory_sha256"], _ = json.Marshal(digest(inventoryNext))
		var selected map[string]map[string]interface{}
		json.Unmarshal(sf["participants"], &selected)
		for _, p := range inv.Participants {
			for _, c := range plan.Changes {
				if c.Target == p.Manifest {
					selected[p.Name]["sha256"] = c.SHA256
				}
			}
		}
		sf["participants"], _ = json.Marshal(selected)
		if e = change(selectionPaths[n], filepath.Join(out, "selections", fmt.Sprintf("selection-%d.json", n)), encode(sf)); e != nil {
			return nil, e
		}
	}
	if e = putJSON(filepath.Join(out, "PLAN.json"), plan); e != nil {
		return nil, e
	}
	return plan, nil
}
