// Package finance composes the isolated native financial sidecar. Constructors
// run only after the Common supervisor re-executes the explicitly enabled child.
package finance

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"path/filepath"
	"strconv"

	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/dex/service/replication"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// ValidateRegistration runs after CLX genesis/history authentication and checks
// the exact DEX parameters committed by that genesis, not a caller-selected seed.
func ValidateRegistration(m service.Manifest, seed protocol.Hash) error {
	if m.Finance == nil || m.Finance.CLX.ChainConfig == nil || m.Finance.CLX.Genesis == nil || m.Finance.CLX.ChainConfig.DEXDevnet == nil {
		return errors.New("native DEX missing from authenticated CLX genesis")
	}
	f := m.Finance
	d := f.CLX.ChainConfig.DEXDevnet
	if (d.Version != 2 && d.Version != 3 && d.Version != 4 && d.Version != 5) || d.ActivationBlock == 0 || protocol.Hash(d.GenesisSeed) != seed || protocol.Hash(d.DEXID) != m.Domain.DEXID || [20]byte(d.Custody) != f.Market.Custody || m.Domain.Epoch != 1 || m.MaxHeight > d.MaxCheckpoints || len(d.Committee) != 7 || len(m.Members) != 7 || m.CLXHeight != 0 || m.CLXHash != m.Domain.Genesis || f.CLX.ChainID != m.Domain.ChainID || protocol.Hash(f.CLX.Genesis.Hash()) != m.Domain.Genesis || f.CLX.DEXID != m.Domain.DEXID || [20]byte(f.CLX.Custody) != f.Market.Custody || (d.ContinuousStorage() && len(f.ReceiptHeights) != 0) {
		return errors.New("native registration differs from genesis seed/domain/custody/bounds")
	}
	for i, n := range m.Members {
		if n == nil || *n != d.Committee[i] {
			return errors.New("native committee differs from authenticated genesis")
		}
	}
	return nil
}

func OpenManifest(m service.Manifest) (*service.Service, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if m.Mode != "native-finance" || m.Finance == nil {
		return nil, errors.New("explicit native financial manifest required")
	}
	verifier, err := clxevidence.New(m.Finance.CLX)
	if err != nil {
		return nil, err
	}
	seed, err := protocol.NativeMarketSeed(m.Finance.Market.Oracle)
	if err != nil {
		return nil, err
	}
	if err = ValidateRegistration(m, seed); err != nil {
		return nil, err
	}
	market, err := engine.New(m.Finance.Market)
	if err != nil {
		return nil, err
	}
	recipients := make([][20]byte, 7)
	for i, p := range m.Peers {
		recipients[i] = p.RewardRecipient
	}
	registry, err := rewards.NewRegistry(m.Domain, m.Members, recipients)
	if err != nil {
		return nil, err
	}
	epoch, err := checkpoint.NewEpoch(m.Domain, 1, math.MaxUint64, m.Members)
	if err != nil {
		return nil, err
	}
	deployment := m.Finance.CLX.ChainConfig.DEXDevnet
	continuous := deployment.ContinuousStorage()
	execution := &devnet.Execution{Market: market, Registry: registry, Native: &devnet.NativeContext{Seed: seed, Verifier: verifier, Rolling: deployment.RollingAnchors(), Continuous: continuous, Ancestry: deployment.AncestryProofs()}}
	if _, _, err = execution.Genesis(); err != nil {
		return nil, err
	}
	cfg, err := service.ManifestConfig(m)
	if err != nil {
		return nil, err
	}
	cfg.Consensus.StorageGenerations = continuous
	cfg.Transport.QueueLimit = 256
	collector, err := rewards.OpenCollector(filepath.Join(m.DataDir, "participation"), registry, m.Index, cfg.Consensus.Secret)
	if err != nil {
		return nil, err
	}
	good := false
	defer func() {
		if !good {
			collector.Shutdown()
		}
	}()
	execution.Collector = collector
	pool, err := OpenPool(filepath.Join(m.DataDir, "mempool"), execution)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !good {
			pool.Close()
		}
	}()
	network, err := replication.New(replication.Config{Index: m.Index, Peers: m.Peers, Registry: registry, Collector: collector, Heights: m.Finance.ReceiptHeights, Continuous: continuous, MaxHeight: m.MaxHeight})
	if err != nil {
		return nil, err
	}
	var s *service.Service
	var actor *consensus.Application
	wake := func() error {
		if actor == nil {
			return nil
		}
		err := actor.NotifyIngress()
		if errors.Is(err, hotstuff.ErrProposalValidationPending) {
			return nil
		}
		return err
	}
	relay := func(raw []byte) error {
		var errs []error
		for i, p := range m.Peers {
			if i != int(m.Index) {
				if e := s.Relay(p.ID, transport.KindAction, raw); e != nil {
					errs = append(errs, e)
				}
			}
		}
		return errors.Join(errs...)
	}
	cfg.Consensus.Execution = execution
	cfg.Consensus.ActionsWithParent = pool.Select
	if m.Finance.CLX.ChainConfig.DEXDevnet.Version == 5 {
		ready := pool.timeoutPolicy()
		cfg.TimeoutReady = func(a *consensus.Application) (bool, error) {
			if a.CertifiedHeight() >= m.MaxHeight {
				return false, nil
			}
			return ready(a)
		}
	}
	cfg.Consensus.BeforeVote = func(v *hotstuff.PersistedVote) error {
		if err := pool.check(); err != nil {
			return err
		}
		return collector.BeforeVote(v)
	}
	cfg.Consensus.RestoreVote = collector.CheckFHSWatermark
	cfg.Consensus.ObserveVote = network.Observe
	cfg.Consensus.OnFinalizedExecution = func(height uint64, raw, state []byte) error {
		if err := execution.Finalized(height, raw, state); err != nil {
			return err
		}
		return pool.Finalized(height, raw)
	}
	cfg.ActorInit = func(a *consensus.Application) error { actor = a; return network.Bind(a, s.Relay) }
	cfg.OnExtension = network.Receive
	cfg.OnAction = func(raw []byte) error {
		fresh, err := pool.Admit(raw)
		if err != nil {
			return err
		}
		if fresh {
			_ = relay(raw)
			return wake()
		}
		if stage, reason := pool.Status(protocol.Digest("common-dex/ingress-action/v1", raw)); stage == "rejected" {
			return errors.New("previously rejected action: " + reason)
		}
		return nil
	}
	cfg.IngressStage = pool.Status
	cfg.OnPeerAction = func(_ uint8, raw []byte) error {
		fresh, err := pool.Admit(raw)
		if err == nil && fresh {
			return wake()
		}
		return err
	}
	var ticks, cursor uint64
	cfg.ActorTick = func(a *consensus.Application) error {
		err := network.Tick(a)
		ticks++
		if ticks%50 != 0 {
			return err
		}
		pending := pool.Pending()
		if len(pending) == 0 {
			return err
		}
		raw := pending[cursor%uint64(len(pending))]
		cursor++
		return errors.Join(err, relay(raw))
	}
	configureFinancialQuery(&cfg, m.MaxHeight, pool, execution, epoch, collector, network)
	cfg.OnClose = func() error { return errors.Join(pool.Close(), collector.Shutdown()) }
	s, err = service.Open(cfg)
	if err != nil {
		return nil, err
	}
	good = true
	return s, nil
}

func selectedCertifiedQuery(query url.Values) (bool, error) {
	values, ok := query["selected"]
	if !ok {
		return false, nil
	}
	if len(values) != 1 || (values[0] != "true" && values[0] != "false") {
		return false, errors.New("selected must be one canonical boolean")
	}
	return values[0] == "true", nil
}

// configureFinancialQuery installs the complete route, including its strict outer
// query-key guard. Tests invoke this same cfg.Query used by OpenManifest.
func configureFinancialQuery(cfg *service.Config, maxHeight uint64, pool *Pool, execution *devnet.Execution, epoch *checkpoint.Epoch, collector *rewards.Collector, network *replication.Controller) {
	cfg.Query = func(a *consensus.Application, path string, query url.Values) (interface{}, error) {
		if len(query) != 1 && !(path == "/v1/certified" && len(query) == 2 && query.Has("height") && query.Has("selected")) {
			return nil, errors.New("exact query required")
		}
		if path == "/v1/action-status" {
			ids := query["id"]
			if len(ids) != 1 {
				return nil, errors.New("one action id required")
			}
			raw, err := hex.DecodeString(ids[0])
			if err != nil || len(raw) != 32 {
				return nil, errors.New("action id")
			}
			var id protocol.Hash
			copy(id[:], raw)
			status, reason := pool.Status(id)
			return map[string]string{"stage": status, "reason": reason, "clx_settlement": "separate"}, nil
		}
		heights := query["height"]
		if len(heights) != 1 {
			return nil, errors.New("one height required")
		}
		height, err := strconv.ParseUint(heights[0], 10, 64)
		if err != nil || height == 0 || height > maxHeight {
			return nil, errors.New("height bound")
		}
		switch path {
		case "/v1/certified":
			var data []byte
			selected, queryErr := selectedCertifiedQuery(query)
			if queryErr != nil {
				return nil, queryErr
			}
			if selected {
				data, err = a.SelectedCertifiedData(height)
			} else {
				data, err = a.LatestCertifiedData(height)
			}
			return struct {
				Stage, Finality, CLXSettlement string
				Record                         json.RawMessage
			}{"certified", "not_asserted", "separate", data}, err
		case "/v1/settlement":
			data, err := FinalizedSettlement(a, execution, epoch, height)
			return struct{ Bytes []byte }{data}, err
		case "/v1/snapshot":
			data, err := a.ExportSnapshotAt(height)
			return struct {
				Height uint64
				Bytes  []byte
			}{height, data}, err
		case "/v1/participation":
			certs, err := collector.Certificates(height)
			storage := collector.StorageStatus()
			retention := "hot"
			if (height-1)/rewards.PeriodBlocks+1 <= storage.Retired.Period {
				retention = "retired-to-archive"
			}
			return struct {
				Certificates  []rewards.Certificate
				ReceiptErrors uint64
				Retention     string
				Storage       rewards.StorageStatus
			}{certs, network.Errors, retention, storage}, err
		case "/v1/checkpoint":
			cp, proof, err := a.FinalizedCheckpoint(height)
			if err != nil {
				return nil, err
			}
			state, err := a.FinalizedState(height)
			if err != nil {
				return nil, err
			}
			return struct {
				Checkpoint   protocol.Checkpoint
				Proof, State []byte
			}{cp, proof, state}, nil
		default:
			return nil, errors.New("unknown financial query")
		}
	}
}
