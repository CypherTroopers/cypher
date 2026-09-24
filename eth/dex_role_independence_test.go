package eth

// These opt-in tests exercise actual Common APIs with intentionally unavailable
// normal-mode PoW resources. IsMining is a lifecycle assertion, never evidence
// of nonce search. See docs/dex/real-role-prerequisites.md.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/accounts/keystore"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/commonrpcreward"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	dexconsensus "github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/node"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rpc"
)

type dexRoleSidecarReport struct {
	PID    int
	Height uint64
	Hash   protocol.Hash
}

const dexRoleSidecarPrefix = "DEX_ROLE_READY "

func dexRoleBenign(err error) bool {
	if err == nil {
		return true
	}
	for _, expected := range []error{hotstuff.ErrInsufficientQC, hotstuff.ErrProposalValidationPending, hotstuff.ErrUnhandledMsg, hotstuff.ErrOldState, hotstuff.ErrMissingView, hotstuff.ErrViewOldPhase, hotstuff.ErrFutureState} {
		if errors.Is(err, expected) {
			return true
		}
	}
	return strings.Contains(err.Error(), "counter fixture height limit")
}

func TestDEXRoleSidecarHelper(t *testing.T) {
	dir := os.Getenv("CYPHER_DEX_ROLE_SIDECAR")
	if dir == "" {
		t.Skip("DEX role sidecar helper")
	}
	if os.Getenv("CYPHER_DEX_ROLE_API_DEVNET") != "1" {
		t.Fatal("missing role-test opt-in")
	}
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlWarn, log.StreamHandler(os.Stderr, log.LogfmtFormat())))
	data, err := os.ReadFile(filepath.Join(dir, "domain.json"))
	if err != nil {
		t.Fatal(err)
	}
	var domain protocol.Domain
	if err := json.Unmarshal(data, &domain); err != nil {
		t.Fatal(err)
	}
	var keys [7]bls.SecretKey
	members := make([]*common.Cnode, 7)
	for i := range keys {
		if err := keys[i].SetDecString(strconv.Itoa(1900 + i)); err != nil {
			t.Fatal(err)
		}
		members[i] = &common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 32000+i), Public: keys[i].GetPublicKey().SerializeToHexStr(), CoinBase: fmt.Sprintf("role-fixture-recipient-%d", i)}
	}
	domain.Committee = protocol.Hash((&bftview.Committee{List: members}).RlpHash())
	type envelope struct {
		to      string
		message *hotstuff.HotstuffMessage
	}
	var queue []envelope
	apps := make([]*dexconsensus.Application, 7)
	for i := range apps {
		apps[i], err = dexconsensus.Open(dexconsensus.Config{Domain: domain, Members: members, Index: i, Secret: &keys[i], DataDir: filepath.Join(dir, "wal", strconv.Itoa(i)), CLXHash: domain.Genesis, MaxHeight: 3})
		if err != nil {
			t.Fatal(err)
		}
		defer apps[i].Close()
		apps[i].SetTransport(func(to string, message *hotstuff.HotstuffMessage) error {
			if len(queue) >= 4096 {
				return errors.New("role sidecar message limit exceeded")
			}
			queue = append(queue, envelope{to, message})
			return nil
		})
	}
	for _, app := range apps {
		if err := app.Start(); !dexRoleBenign(err) {
			t.Fatal(err)
		}
	}
	quiesced := false
	for step := 0; step < 20000; step++ {
		progress := false
		for _, app := range apps {
			did, err := app.Advance()
			if !dexRoleBenign(err) {
				t.Fatal(err)
			}
			progress = progress || did
		}
		if len(queue) != 0 {
			item := queue[0]
			queue = queue[1:]
			for _, app := range apps {
				if app.Self() == item.to {
					if err := app.Handle(item.message); !dexRoleBenign(err) {
						t.Fatal(err)
					}
					break
				}
			}
			progress = true
		}
		if !progress {
			quiesced = true
			break
		}
	}
	if !quiesced {
		t.Fatal("bounded sidecar did not quiesce")
	}
	report := dexRoleSidecarReport{PID: os.Getpid(), Height: 2}
	for _, app := range apps {
		if app.FinalizedHeight() != 2 {
			t.Fatal("sidecar did not finalize two counter actions")
		}
		c, _, err := app.FinalizedCheckpoint(2)
		if err != nil {
			t.Fatal(err)
		}
		hash, err := c.Hash()
		if err != nil {
			t.Fatal(err)
		}
		if report.Hash == (protocol.Hash{}) {
			report.Hash = hash
		} else if report.Hash != hash {
			t.Fatal("sidecar actor divergence")
		}
	}
	writeReport := func() { encoded, _ := json.Marshal(report); fmt.Println(dexRoleSidecarPrefix + string(encoded)) }
	writeReport()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64), 128)
	for scanner.Scan() {
		if scanner.Text() != "status" {
			t.Fatal("unknown sidecar command")
		}
		writeReport()
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

type dexRoleSidecar struct {
	cmd     *exec.Cmd
	input   io.WriteCloser
	replies chan dexRoleSidecarReport
	done    chan error
	stopped bool
	initial dexRoleSidecarReport
}

func startDEXRoleSidecar(t *testing.T, domain protocol.Domain) *dexRoleSidecar {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "wal"), 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(domain)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "domain.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestDEXRoleSidecarHelper$", "-test.timeout=3m")
	cmd.Env = append(os.Environ(), "CYPHER_DEX_ROLE_SIDECAR="+dir, "GOMAXPROCS=2")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "sidecar.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = logFile
	s := &dexRoleSidecar{cmd: cmd, input: input, replies: make(chan dexRoleSidecarReport, 2), done: make(chan error, 1)}
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 1024), 64<<10)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, dexRoleSidecarPrefix) {
				var report dexRoleSidecarReport
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, dexRoleSidecarPrefix)), &report); err == nil {
					s.replies <- report
				}
			} else {
				fmt.Fprintln(logFile, line)
			}
		}
	}()
	go func() { err := cmd.Wait(); <-scanned; logFile.Close(); s.done <- err }()
	t.Cleanup(func() {
		if !s.stopped {
			_ = s.cmd.Process.Kill()
			<-s.done
			s.stopped = true
		}
		_ = s.input.Close()
		if t.Failed() {
			data, _ := os.ReadFile(logFile.Name())
			t.Logf("DEX role sidecar log:\n%s", data)
		}
	})
	select {
	case s.initial = <-s.replies:
		if s.initial.PID == os.Getpid() || s.initial.Height != 2 || s.initial.Hash == (protocol.Hash{}) {
			t.Fatal("sidecar did not execute independently")
		}
	case err := <-s.done:
		s.stopped = true
		t.Fatalf("sidecar startup: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("sidecar startup timed out")
	}
	return s
}

func (s *dexRoleSidecar) status(t *testing.T) {
	t.Helper()
	if _, err := io.WriteString(s.input, "status\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case report := <-s.replies:
		if report != s.initial {
			t.Fatal("sidecar state changed unexpectedly")
		}
	case err := <-s.done:
		s.stopped = true
		t.Fatalf("sidecar exited: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("sidecar stopped responding")
	}
}

func (s *dexRoleSidecar) stop(t *testing.T) {
	t.Helper()
	if err := s.input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-s.done:
		s.stopped = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("sidecar stop timed out")
	}
}

func TestDEXActualCommonAPIEightCombinationsWithoutPoWDataset(t *testing.T) {
	if os.Getenv("CYPHER_DEX_ROLE_API_DEVNET") != "1" {
		t.Skip("set CYPHER_DEX_ROLE_API_DEVNET=1 in isolated loopback-only network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&(net.FlagLoopback|net.FlagUp) != net.FlagLoopback|net.FlagUp {
		t.Fatalf("requires isolated active-loopback-only network: interfaces=%+v err=%v", interfaces, err)
	}
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprintf("pow_%t_rpc_%t_dex_%t", mask&1 != 0, mask&2 != 0, mask&4 != 0), func(t *testing.T) { testDEXActualCommonAPIRoles(t, mask) })
	}
}

func testDEXActualCommonAPIRoles(t *testing.T, mask int) {
	powOn, rpcOn, dexOn := mask&1 != 0, mask&2 != 0, mask&4 != 0
	oldCoinbase, oldAddress, oldPublic := bftview.GetServerCoinBase(), bftview.GetServerAddress(), bftview.GetServerInfo(bftview.PublicKey)
	bftview.SetServerCoinBase(common.Address{})
	bftview.SetServerInfo("", "")
	t.Cleanup(func() { bftview.SetServerCoinBase(oldCoinbase); bftview.SetServerInfo(oldAddress, oldPublic) })
	datasetFailure := make(chan struct{}, 8)
	previousHandler := log.Root().GetHandler()
	log.Root().SetHandler(log.FuncHandler(func(record *log.Record) error {
		if record.Msg == "Candidate sealing failed" && strings.Contains(fmt.Sprint(record.Ctx...), "dataset dir is empty") {
			select {
			case datasetFailure <- struct{}{}:
			default:
			}
		}
		return previousHandler.Log(record)
	}))
	t.Cleanup(func() { log.Root().SetHandler(previousHandler) })
	encoded, err := os.ReadFile("../genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	var genesis core.Genesis
	if err := json.Unmarshal(encoded, &genesis); err != nil {
		t.Fatal(err)
	}
	portSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rnetPort := portSocket.LocalAddr().(*net.UDPAddr).Port
	portSocket.Close()
	genesis.Config.RnetPort, genesis.Config.EnabledTPS = strconv.Itoa(rnetPort), DefaultConfig.EnableTPS
	for i, member := range genesis.Config.GenCommittee {
		member.Address = fmt.Sprintf("127.0.0.1:%d", 28000+i)
		genesis.Config.GenCommittee[i] = member
	}
	genesis.Mixhash, err = params.FairHotstuffGenesisCommitment(genesis.Config)
	if err != nil {
		t.Fatal(err)
	}
	payerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	operatorKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	genesis.Alloc[crypto.PubkeyToAddress(payerKey.PublicKey)] = core.GenesisAccount{Balance: new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether))}
	socketDir, err := os.MkdirTemp("", "dex-role-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	nodeConfig := &node.Config{Name: "dex-role", DataDir: t.TempDir(), IPCPath: filepath.Join(socketDir, "rpc.ipc"), NoUSB: true, UseLightweightKDF: true, P2P: p2p.Config{NoDiscovery: true, MaxPeers: 0, ListenAddr: "127.0.0.1:0"}}
	if rpcOn {
		nodeConfig.HTTPHost = "127.0.0.1"
		nodeConfig.HTTPModules = []string{"eth"}
		nodeConfig.HTTPVirtualHosts = []string{"localhost"}
	}
	stack, err := node.New(nodeConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stack.Close(); err != nil {
			t.Error(err)
		}
	})
	store := stack.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	operator, err := store.ImportECDSA(operatorKey, "fixture-only")
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig
	config.Genesis, config.GenesisKey = &genesis, &core.GenesisKey{Config: genesis.Config, Difficulty: big.NewInt(1)}
	config.NetworkId = genesis.Config.ChainID.Uint64()
	config.SyncMode, config.ExternalIp, config.RnetPort = downloader.FullSync, "127.0.0.1", genesis.Config.RnetPort
	config.DatabaseCache, config.DatabaseHandles = 16, 16
	config.TrieCleanCache, config.TrieDirtyCache, config.SnapshotCache = 0, 0, 0
	config.colossusX.CacheDir = filepath.Join(nodeConfig.DataDir, "pow-cache")
	config.colossusX.DatasetDir = "" // Existing normal-mode fail-closed guard: no large DAG generation.
	config.TxQUIC = testTxQUICConfig()
	config.TxQUIC.AutoRole, config.TxQUIC.Enabled, config.TxQUIC.BridgeEnabled = false, false, true
	config.TxQUIC.OutboxRetryMin, config.TxQUIC.OutboxRetryMax = time.Second, time.Second
	service, err := New(stack, &config)
	if err != nil {
		t.Fatal(err)
	}
	if service.engine.PowMode() != uint(colossusX.ModeNormal) {
		t.Fatal("normal ColossusX engine was replaced")
	}
	service.txQUICIngress.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) {
		return TxQUICFHSRoute{}, errors.New("isolated committee intentionally offline")
	})
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	ipc, err := rpc.DialIPC(context.Background(), stack.IPCEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	defer ipc.Close()
	var ok bool
	if err := ipc.Call(&ok, "miner_setEtherbase", operator.Address); err != nil || !ok {
		t.Fatalf("configure existing operational signer: %v", err)
	}
	recipient := common.Address{0xbe, byte(mask)}
	var reward commonrpcreward.Status
	if err := ipc.Call(&reward, "personal_setCommonRPCRewardAddress", operator.Address, recipient, "fixture-only"); err != nil {
		t.Fatal(err)
	}
	if err := ipc.Call(&ok, "personal_unlockAccount", operator.Address, "fixture-only", 0); err != nil || !ok {
		t.Fatalf("unlock fixture signer: %v", err)
	}
	if powOn {
		var status string
		if err := ipc.Call(&status, "miner_start", 1, operator.Address, "fixture-only"); err != nil {
			t.Fatal(err)
		}
		select {
		case <-datasetFailure:
		case <-time.After(5 * time.Second):
			t.Fatal("normal PoW did not explicitly reject absent dataset")
		}
	}
	checkCommon := func(wantMining bool) {
		t.Helper()
		if service.IsMining() != wantMining || bftview.IamMember() >= 0 || service.ServiceIsRunning() {
			t.Fatalf("Common/miner role changed: mining=%t member=%d fhs=%t", service.IsMining(), bftview.IamMember(), service.ServiceIsRunning())
		}
		if bftview.GetServerCoinBase() != operator.Address {
			t.Fatal("DEX altered Common operational account")
		}
		got, err := service.PoWRewardRecipient(operator.Address)
		if err != nil || got != recipient {
			t.Fatalf("PoW/RPC recipient changed: %v", err)
		}
	}
	checkCommon(powOn)
	var sidecar *dexRoleSidecar
	if dexOn {
		sidecar = startDEXRoleSidecar(t, protocol.Domain{Version: 1, ChainID: config.NetworkId, Genesis: protocol.Hash(service.blockchain.Genesis().Hash()), DEXID: protocol.Digest("fixture", []byte("common-api-roles")), Epoch: 1})
		sidecar.status(t)
		checkCommon(powOn)
	}
	var httpClient *rpc.Client
	if rpcOn {
		httpClient, err = rpc.DialHTTP(stack.HTTPEndpoint())
		if err != nil {
			t.Fatal(err)
		}
		defer httpClient.Close()
	} else if stack.HTTPEndpoint() != "http://" {
		t.Fatalf("RPC OFF exposed HTTP: %q", stack.HTTPEndpoint())
	}
	submit := func(nonce uint64) {
		t.Helper()
		if !rpcOn {
			return
		}
		tx, err := types.SignTx(types.NewTransaction(nonce, common.Address{1}, big.NewInt(1), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil), types.NewEIP155Signer(genesis.Config.ChainID), payerKey)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var returned common.Hash
		if err := httpClient.Call(&returned, "eth_sendRawTransaction", hexutil.Bytes(payload)); err != nil || returned != tx.Hash() {
			t.Fatalf("actual HTTP admission: hash=%s err=%v", returned, err)
		}
		admission, found, err := service.txQUICIngress.wal.localRPCAdmission(operator.Address, tx.Hash())
		if err != nil || !found || admission.Batch.Miner != operator.Address || admission.Batch.RewardRecipient != recipient {
			t.Fatalf("durable Common admission mismatch: found=%t err=%v", found, err)
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission.Batch); err != nil {
			t.Fatal(err)
		}
	}
	submit(0)
	wantMining := powOn
	if powOn && rpcOn && sidecar != nil {
		if err := ipc.Call(nil, "miner_stop"); err != nil {
			t.Fatal(err)
		}
		wantMining = false
		checkCommon(false)
		sidecar.status(t) // Existing miner.stop must not terminate the DEX sidecar.
	}
	if sidecar != nil {
		sidecar.stop(t)
		checkCommon(wantMining)
	}
	submit(1)
	if err := ipc.Call(nil, "miner_stop"); err != nil {
		t.Fatal(err)
	}
	checkCommon(false)
	submit(2)
	if service.Miner().HashRate() != 0 {
		t.Fatal("absent dataset unexpectedly performed nonce search")
	}
	t.Logf("actual IPC miner lifecycle=%t, HTTP Common admission=%t, separate-process 7-actor DEX finality=%t; normal-mode dataset explicitly unavailable, nonce search and committee delivery NOT_RUN", powOn, rpcOn, dexOn)
}
