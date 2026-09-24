// dex-live-source-observer is a read-only CLX proof observer for measurement.
// It reuses the relay's bounded genesis-anchored source verifier. The only
// writes are its own dedicated proof journal; it never signs/sends transactions
// or opens CLX/DEX canonical databases.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/relay/source"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/params"
)

type request struct {
	Op      string
	Height  uint64
	Hash    common.Hash
	Address common.Address
	Keys    []common.Hash
}
type observation struct{ client *source.Client }

func parse(raw []byte) (request, error) {
	var r request
	if len(raw) == 0 || len(raw) > 16384 {
		return r, errors.New("observer input bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, errors.New("observer input codec")
	}
	if d.Decode(new(interface{})) != io.EOF {
		return r, errors.New("observer trailing input")
	}
	// CLX height is an absolute source coordinate, not a DEX sequence budget.
	// The source implementation accepts heights through MaxInt64. Work remains
	// bounded by its 32-header segments, 1024-segment / 32 MiB proof journal,
	// per-segment bytes, and the 32-slot account proof limit. This does not let a
	// request jump over an unauthenticated segment or bypass journal capacity.
	if r.Height > math.MaxInt64 || len(r.Keys) > clxevidence.MaxAccountStorageSlots {
		return r, errors.New("observer height/slot work bound")
	}
	if r.Op != "current" && r.Op != "advance" && r.Op != "anchor" && r.Op != "account" {
		return r, errors.New("read-only observer operation required")
	}
	if (r.Op == "anchor" || r.Op == "account") && (r.Height == 0 || r.Hash == (common.Hash{})) {
		return r, errors.New("exact non-genesis block identity required")
	}
	if r.Op == "account" && r.Address == (common.Address{}) {
		return r, errors.New("nonzero account required")
	}
	return r, nil
}
func (o observation) call(r request) (interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if r.Op == "current" {
		return o.client.Current(), nil
	}
	if r.Op == "advance" {
		segment, err := o.client.Advance(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"anchor": segment.Target, "base": segment.Base, "headers": len(segment.Evidence.Headers), "evidence": segment.Evidence, "stage": "authenticated_clx_finality"}, nil
	}
	anchor, err := o.client.AnchorAt(ctx, r.Height, protocol.Hash(r.Hash))
	if err != nil {
		return nil, err
	}
	if r.Op == "anchor" {
		return map[string]interface{}{"anchor": anchor, "stage": "authenticated_clx_finality"}, nil
	}
	keys := make([]protocol.Hash, len(r.Keys))
	for i, k := range r.Keys {
		keys[i] = protocol.Hash(k)
	}
	account, raw, err := o.client.Account(ctx, anchor, [20]byte(r.Address), keys)
	if err != nil {
		return nil, err
	}
	values := make(map[common.Hash]common.Hash, len(keys))
	for i, k := range r.Keys {
		values[k] = common.Hash(account.Values[i])
	}
	return map[string]interface{}{"anchor": anchor, "address": r.Address, "nonce": account.Nonce, "balance": account.Balance.String(), "exists": account.Exists, "values": values, "proof": raw, "stage": "authenticated_clx_account_storage"}, nil
}

// Ownership is checked on actual filesystem metadata, not on claims inside
// OWNER.json. Parent ancestors must not be symlinks or writable by unrelated
// users; the root-owned sticky temporary directory is the deliberate exception.
// The finance run itself and any existing observer directory remain private.
func readRunOwner(dir string) ([]byte, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, errors.New("canonical absolute observer directory required")
	}
	parent := filepath.Dir(dir)
	if filepath.Base(dir) != "source-observer" || !strings.HasPrefix(filepath.Base(parent), "live-finance-") {
		return nil, errors.New("dedicated finance observer directory required")
	}
	for path := parent; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("observer ancestor must be a real directory")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != uint32(os.Geteuid()) && st.Uid != 0) {
			return nil, errors.New("observer ancestor ownership mismatch")
		}
		if path == parent {
			if st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
				return nil, errors.New("finance run directory must be owned and private")
			}
		} else if info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return nil, errors.New("observer ancestor is writable by others")
		}
		if path == filepath.Dir(path) {
			break
		}
	}
	if info, err := os.Lstat(dir); err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || !ok || st.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("observer directory must be owned and private")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(parent, "OWNER.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("finance ownership marker required")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || info.Size() > 8192 {
		return nil, errors.New("finance marker must be owned private regular single-link file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) > 8192 {
		return nil, errors.New("finance ownership marker bound")
	}
	return raw, nil
}

func open(manifest, dir string) (*source.Client, error) {
	if !filepath.IsAbs(manifest) || !filepath.IsAbs(dir) {
		return nil, errors.New("absolute manifest and observer directory required")
	}
	// The source package additionally applies its journal marker, no-follow
	// files and an exclusive lock after the containing run is authenticated.
	marker, err := readRunOwner(dir)
	if err != nil {
		return nil, err
	}
	m, err := service.LoadManifest(manifest)
	if err != nil {
		return nil, err
	}
	if m.Version != 2 || m.Domain.ChainID == 0 || m.Finance == nil || !m.StorageGenerations {
		return nil, errors.New("current candidate generation required")
	}
	root := filepath.Dir(filepath.Dir(manifest))
	data, err := os.ReadFile(filepath.Join(root, "public/inventory.json"))
	var inventory struct {
		ChainID                       uint64
		Genesis, GenesisSHA256, DEXID string
		ConfigurationVersion          uint16
		Participants                  []struct{ Manifest string }
	}
	if err != nil || len(data) > 1<<20 || json.Unmarshal(data, &inventory) != nil || inventory.ChainID != m.Domain.ChainID || (inventory.ConfigurationVersion != 4 && inventory.ConfigurationVersion != 5) || common.HexToHash(inventory.Genesis) != common.Hash(m.Domain.Genesis) || common.HexToHash(inventory.DEXID) != common.Hash(m.Domain.DEXID) {
		return nil, errors.New("observer candidate identity mismatch")
	}
	found := false
	for _, p := range inventory.Participants {
		found = found || p.Manifest == manifest
	}
	if !found {
		return nil, errors.New("manifest not in approved candidate inventory")
	}
	genesis, err := os.ReadFile(filepath.Join(root, "genesis.json"))
	var g struct {
		Config *params.ChainConfig `json:"config"`
	}
	if err != nil || len(genesis) > 4<<20 || json.Unmarshal(genesis, &g) != nil || g.Config == nil || g.Config.ChainID == nil || !g.Config.ChainID.IsUint64() || g.Config.ChainID.Uint64() != inventory.ChainID || g.Config.DEXDevnet == nil || g.Config.DEXDevnet.Version != inventory.ConfigurationVersion || fmt.Sprintf("%x", sha256.Sum256(genesis)) != inventory.GenesisSHA256 {
		return nil, errors.New("observer approved genesis/config/hash mismatch")
	}
	var owner struct {
		Tool     string `json:"tool"`
		UID      int    `json:"uid"`
		Identity struct {
			ChainID uint64 `json:"chain_id"`
			Genesis string `json:"genesis"`
			DEXID   string `json:"dex_id"`
		} `json:"identity"`
	}
	if json.Unmarshal(marker, &owner) != nil || owner.Tool != "common-dex-live-finance-v1" || owner.UID != os.Getuid() || owner.Identity.ChainID != inventory.ChainID || common.HexToHash(owner.Identity.Genesis) != common.Hash(m.Domain.Genesis) || common.HexToHash(owner.Identity.DEXID) != common.Hash(m.Domain.DEXID) {
		return nil, errors.New("observer run identity mismatch")
	}
	return source.Open(source.Config{Endpoint: "http://127.0.0.1:8999", Dir: dir, CLX: m.Finance.CLX})
}
func main() {
	manifest := flag.String("manifest", "", "fixed current generation DEX manifest")
	dir := flag.String("directory", "", "dedicated read-only observer proof journal")
	flag.Parse()
	client, err := open(*manifest, *dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "source observer initialization rejected")
		os.Exit(2)
	}
	defer client.Close()
	observer := observation{client}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 16385)
	out := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		r, err := parse(scanner.Bytes())
		var result interface{}
		if err == nil {
			result, err = observer.call(r)
		}
		if err != nil {
			category := "authentication_or_local_error"
			if errors.Is(err, source.ErrUnavailable) {
				category = "proof_unavailable"
			}
			out.Encode(map[string]interface{}{"ok": false, "category": category, "error": err.Error()})
		} else {
			out.Encode(map[string]interface{}{"ok": true, "result": result})
		}
	}
	if scanner.Err() != nil {
		fmt.Fprintln(os.Stderr, "observer bounded input failure")
		os.Exit(2)
	}
}
