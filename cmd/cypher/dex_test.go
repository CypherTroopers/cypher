package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/accounts/keystore"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/commonrpcreward"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/eth"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rpc"
)

type ownedCLI struct {
	cmd  *exec.Cmd
	done chan error
	log  string
}

func startOwnedCLI(t *testing.T, root string, args ...string) *ownedCLI {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, args...)
	cmd.Args[0] = "cypher-test"
	path := filepath.Join(root, fmt.Sprintf("child-%d.log", time.Now().UnixNano()))
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = f, f
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	if err = cmd.Start(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	p := &ownedCLI{cmd: cmd, done: make(chan error, 1), log: path}
	go func() { err := cmd.Wait(); f.Close(); p.done <- err; close(p.done) }()
	t.Cleanup(func() { p.stop(t) })
	return p
}
func (p *ownedCLI) stop(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		return
	default:
	}
	p.cmd.Process.Signal(os.Interrupt)
	select {
	case <-p.done:
		return
	case <-time.After(8 * time.Second):
		p.cmd.Process.Kill()
		<-p.done
		t.Error("owned CLI required forced stop")
	}
}
func (p *ownedCLI) wait(t *testing.T) {
	t.Helper()
	select {
	case err := <-p.done:
		if err != nil {
			b, _ := os.ReadFile(p.log)
			t.Fatalf("CLI failed: %v\n%s", err, b)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("CLI init timeout")
	}
}
func freeEndpoint(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
func cliManifests(t *testing.T, root string, genesis protocol.Hash, chain uint64) []service.Manifest {
	t.Helper()
	var peers []transport.Peer
	var members []*common.Cnode
	var keys [7]bls.SecretKey
	ms := make([]service.Manifest, 7)
	for i := 0; i < 7; i++ {
		if err := keys[i].SetDecString(fmt.Sprint(401 + i)); err != nil {
			t.Fatal(err)
		}
		addr := freeEndpoint(t)
		members = append(members, &common.Cnode{Address: addr, Public: keys[i].GetPublicKey().SerializeToHexStr(), CoinBase: fmt.Sprint("dedicated-dex-recipient-", i)})
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		priv, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		vote := filepath.Join(root, fmt.Sprint("vote-", i))
		cert := filepath.Join(root, fmt.Sprint("tls-cert-", i))
		secret := filepath.Join(root, fmt.Sprint("tls-secret-", i))
		os.WriteFile(vote, []byte(keys[i].SerializeToHexStr()), 0600)
		os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
		os.WriteFile(secret, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), 0600)
		peers = append(peers, transport.Peer{ID: addr, Address: addr, BLSPublic: members[i].Public, RewardRecipient: [20]byte{byte(i + 1)}, CertSHA256: protocol.Hash(sha256.Sum256(der))})
		ms[i] = service.Manifest{Version: 1, Devnet: true, Mode: "counter", Index: uint8(i), DataDir: filepath.Join(root, fmt.Sprint("dex-", i)), VoteKeyFile: vote, TLSCertFile: cert, TLSKeyFile: secret, APIListen: freeEndpoint(t), CLXHash: genesis, MaxHeight: 3, TimeoutMillis: 2000}
	}
	domain := protocol.Domain{Version: 1, ChainID: chain, Genesis: genesis, DEXID: protocol.Hash{42}, Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	for i := range ms {
		ms[i].Domain = domain
		ms[i].Peers = peers
		ms[i].Members = members
	}
	return ms
}
func readDEXStatus(addr string) (service.Status, error) {
	var s service.Status
	c := http.Client{Timeout: time.Second}
	r, err := c.Get("http://" + addr + "/v1/status")
	if err != nil {
		return s, err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return s, fmt.Errorf("status %d", r.StatusCode)
	}
	err = json.NewDecoder(r.Body).Decode(&s)
	return s, err
}
func waitIPC(t *testing.T, path string, p *ownedCLI) *rpc.Client {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, err := rpc.DialIPC(ctx, path)
		cancel()
		if err == nil {
			return c
		}
		select {
		case <-p.done:
			b, _ := os.ReadFile(p.log)
			t.Fatalf("Common exited before IPC\n%s", b)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	b, _ := os.ReadFile(p.log)
	t.Fatalf("IPC startup timeout\n%s", b)
	return nil
}
func TestDEXNormalCLIEightRoleCombinations(t *testing.T) {
	if os.Getenv("CYPHER_DEX_CLI_DEVNET") != "1" {
		t.Skip("opt-in isolated loopback namespace only")
	}
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) != 1 || ifs[0].Flags&net.FlagLoopback == 0 {
		t.Fatal("loopback-only namespace required", err)
	}
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprintf("pow_%t_rpc_%t_dex_%t", mask&1 != 0, mask&2 != 0, mask&4 != 0), func(t *testing.T) { cliRoles(t, mask) })
	}
}
func cliRoles(t *testing.T, mask int) {
	root := t.TempDir()
	data, err := os.ReadFile("../../genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	var genesis core.Genesis
	if err = json.Unmarshal(data, &genesis); err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rnet := fmt.Sprint(socket.LocalAddr().(*net.UDPAddr).Port)
	socket.Close()
	genesis.Config.RnetPort, genesis.Config.EnabledTPS = rnet, eth.DefaultConfig.EnableTPS
	for i, m := range genesis.Config.GenCommittee {
		m.Address = fmt.Sprintf("127.0.0.1:%d", 28000+i)
		genesis.Config.GenCommittee[i] = m
	}
	genesis.Mixhash, err = params.FairHotstuffGenesisCommitment(genesis.Config)
	if err != nil {
		t.Fatal(err)
	}
	payerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	genesis.Alloc[crypto.PubkeyToAddress(payerKey.PublicKey)] = core.GenesisAccount{Balance: new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether))}
	gdata, err := json.Marshal(&genesis)
	if err != nil {
		t.Fatal(err)
	}
	genesisFile := filepath.Join(root, "genesis.json")
	os.WriteFile(genesisFile, gdata, 0600)
	datadir := filepath.Join(root, "common")
	init := startOwnedCLI(t, root, "--datadir", datadir, "--nat", "extip:127.0.0.1", "--rnetport", rnet, "init", genesisFile)
	init.wait(t)
	operatorKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.NewKeyStore(filepath.Join(datadir, "keystore"), keystore.LightScryptN, keystore.LightScryptP)
	operator, err := ks.ImportECDSA(operatorKey, "fixture-only")
	if err != nil {
		t.Fatal(err)
	}
	ipcDir, err := os.MkdirTemp("", "dex-cli-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(ipcDir) })
	ipcPath := filepath.Join(ipcDir, "node.ipc")
	httpAddr := freeEndpoint(t)
	_, httpPort, _ := net.SplitHostPort(httpAddr)
	manifests := cliManifests(t, root, protocol.Hash(genesis.ToBlock(nil).Hash()), genesis.Config.ChainID.Uint64())
	paths := make([]string, 7)
	for i, m := range manifests {
		b, _ := json.Marshal(m)
		paths[i] = filepath.Join(root, fmt.Sprint("manifest-", i, ".json"))
		os.WriteFile(paths[i], b, 0600)
	}
	// CLI DirectoryFlag normalizes an empty path to '.', and negative threads
	// still allocate a DAG before being clamped to one. A correct magic-only
	// fixture reaches the existing size check before cache/DAG generation.
	datasetDir := filepath.Join(root, "invalid-dataset")
	if err := os.Mkdir(datasetDir, 0700); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 8)
	binary.LittleEndian.PutUint32(header, 0xbaddcafe)
	binary.LittleEndian.PutUint32(header[4:], 0xfee1dead)
	fixtureDAG := filepath.Join(datasetDir, "full-R25-0000000000000000")
	if err := os.WriteFile(fixtureDAG, header, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("PoW lifecycle only: dedicated8byte fixture %s; colossusX.go:396 size rejection precedes line412 cache generation; sealer.go:36 calls dataset before threads", fixtureDAG)
	args := []string{"--datadir", datadir, "--nat", "extip:127.0.0.1", "--rnetport", rnet, "--port", "0", "--nodiscover", "--maxpeers", "0", "--ipcpath", ipcPath, "--syncmode", "full", "--cache", "32", "--cache.trie.journal", "", "--colossusX.dagdir", datasetDir, "--colossusX.cachedir", filepath.Join(root, "pow-cache"), "--allow-insecure-unlock", "--dex.config", paths[0]}
	if mask&4 != 0 {
		args = append(args, "--dex.validator")
	}
	if mask&2 != 0 {
		args = append(args, "--http", "--http.addr", "127.0.0.1", "--http.port", httpPort, "--http.api", "eth", "--http.vhosts", "localhost,127.0.0.1")
	}
	commonNode := startOwnedCLI(t, root, args...)
	ipc := waitIPC(t, ipcPath, commonNode)
	if mask&4 != 0 {
		for i := 1; i < 7; i++ {
			startOwnedCLI(t, root, "dex-validator", "--dex.config", paths[i])
		}
	}
	defer ipc.Close()
	var ok bool
	if err = ipc.Call(&ok, "miner_setEtherbase", operator.Address); err != nil || !ok {
		t.Fatal(err)
	}
	recipient := common.Address{0xbe, byte(mask)}
	var reward commonrpcreward.Status
	if err = ipc.Call(&reward, "personal_setCommonRPCRewardAddress", operator.Address, recipient, "fixture-only"); err != nil {
		t.Fatal(err)
	}
	if err = ipc.Call(&ok, "personal_unlockAccount", operator.Address, "fixture-only", 0); err != nil || !ok {
		t.Fatal(err)
	}
	if mask&1 != 0 {
		var response string
		if err = ipc.Call(&response, "miner_start", 1, operator.Address, "fixture-only"); err != nil {
			t.Fatal(err)
		}

		deadline := time.Now().Add(5 * time.Second)
		observed := false
		for time.Now().Before(deadline) {
			b, _ := os.ReadFile(commonNode.log)
			if strings.Contains(string(b), "invalid colossusX dataset size") {
				observed = true
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !observed {
			t.Fatal("normal PoW did not reject size fixture before allocation")
		}

		var running bool
		if err = ipc.Call(&running, "eth_mining"); err != nil || !running {
			t.Fatal("actual worker lifecycle did not start", err)
		}
		if err = ipc.Call(nil, "miner_stop"); err != nil {
			t.Fatal(err)
		}
	}
	var mining bool
	if err = ipc.Call(&mining, "eth_mining"); err != nil || mining {
		t.Fatal("mining independent role", mining, err)
	}
	if mask&2 != 0 {
		client, err := rpc.DialHTTP("http://" + httpAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		tx, err := types.SignTx(types.NewTransaction(0, common.Address{1}, big.NewInt(1), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil), types.NewEIP155Signer(genesis.Config.ChainID), payerKey)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := tx.MarshalBinary()
		var hash common.Hash
		if err = client.Call(&hash, "eth_sendRawTransaction", hexutil.Bytes(raw)); err != nil || hash != tx.Hash() {
			t.Fatal("actual Common HTTP admission", err)
		}
	}
	if mask&4 != 0 {
		deadline := time.Now().Add(30 * time.Second)
		var st service.Status
		for time.Now().Before(deadline) {
			st, err = readDEXStatus(manifests[0].APIListen)
			if err == nil && st.Finalized >= 2 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err != nil || st.Finalized < 2 {
			b, _ := os.ReadFile(commonNode.log)
			t.Fatalf("ordinary CLI sidecar failed: %+v %v\n%s", st, err, b)
		}
	} else {
		if _, err = os.Stat(manifests[0].DataDir); !os.IsNotExist(err) {
			t.Fatal("DEX OFF touched data directory", err)
		}
	}
	if err = ipc.Call(nil, "miner_stop"); err != nil {
		t.Fatal(err)
	}
	if err = ipc.Call(&mining, "eth_mining"); err != nil || mining {
		t.Fatal("miner stop", err)
	}
	if mask&4 != 0 {
		if _, err = readDEXStatus(manifests[0].APIListen); err != nil {
			t.Fatal("miner.stop stopped sidecar", err)
		}
	}
	if mask&1 != 0 {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			b, _ := os.ReadFile(commonNode.log)
			if strings.Contains(string(b), "invalid colossusX dataset size") {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		b, _ := os.ReadFile(commonNode.log)
		if !strings.Contains(string(b), "invalid colossusX dataset size") {
			t.Fatal("normal PoW invalid-size rejection not observed")
		}
		var rate hexutil.Uint64
		if err = ipc.Call(&rate, "eth_hashrate"); err != nil || rate != 0 {
			t.Fatal("unexpected nonce search", err)
		}
	}
	contents, err := os.ReadFile(fixtureDAG)
	if err != nil || !bytes.Equal(contents, header) {
		t.Fatal("size fixture mutated", err)
	}
	entries, err := os.ReadDir(datasetDir)
	if err != nil || len(entries) != 1 {
		t.Fatal("unexpected DAG generation", err)
	}
	commonNode.stop(t)
	if mask&4 != 0 {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_, err = readDEXStatus(manifests[0].APIListen)
			if err != nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err == nil {
			t.Fatal("owned sidecar survived Common shutdown")
		}
	}
	t.Logf("ordinary CLI Common pow=%t rpc=%t dex=%t; enabled roles checked independently through IPC/HTTP/TLS; normal-size PoW nonces NOT_RUN; payer=%s", mask&1 != 0, mask&2 != 0, mask&4 != 0, hex.EncodeToString(crypto.PubkeyToAddress(payerKey.PublicKey).Bytes()))
}
