package reconfig

import (
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/reconfig/bftview"
)

type repairTestChain struct {
	blocks map[common.Hash]*types.KeyBlock
	head   *types.KeyBlock
}

func (c *repairTestChain) CurrentBlock() *types.KeyBlock { return c.head }
func (c *repairTestChain) CurrentBlockN() uint64 {
	if c.head == nil {
		return 0
	}
	return c.head.NumberU64()
}
func (c *repairTestChain) CurrentCommittee() []*common.Cnode { return nil }
func (c *repairTestChain) GetBlockByHash(hash common.Hash) *types.KeyBlock {
	return c.blocks[hash]
}

func (c *repairTestChain) add(block *types.KeyBlock) {
	if c.blocks == nil {
		c.blocks = make(map[common.Hash]*types.KeyBlock)
	}
	c.blocks[block.Hash()] = block
	c.head = block
}

func repairTestNode(address, coinbase, public string) *common.Cnode {
	return &common.Cnode{Address: address, CoinBase: coinbase, Public: public}
}

// blockAsStored reproduces ReadKeyBlock: the database body does not keep the
// permissionless flag, so the reloaded block looks like a legacy shuffle.
func blockAsStored(block *types.KeyBlock) *types.KeyBlock {
	return types.NewKeyBlock(block.Header()).WithBody(block.InPubKey(), block.InAddress(), block.OutPubKey(), block.OutAddress(0), block.LeaderPubKey(), block.LeaderAddress())
}

func repairTestBlock(parent *types.KeyBlock, number uint64, blockType uint8, committee *bftview.Committee, in, out, leader *common.Cnode) *types.KeyBlock {
	parentHash := common.Hash{}
	if parent != nil {
		parentHash = parent.Hash()
	}
	header := &types.KeyBlockHeader{
		Number:        big.NewInt(int64(number)),
		ParentHash:    parentHash,
		Difficulty:    big.NewInt(1),
		Time:          1000 + number,
		BlockType:     blockType,
		CommitteeHash: committee.RlpHash(),
	}
	block := types.NewKeyBlock(header)
	if in == nil {
		in = leader
	}
	if out == nil {
		out = &common.Cnode{}
	}
	block = block.WithBody(in.Public, in.CoinBase, out.Public, out.CoinBase, leader.Public, leader.CoinBase)
	block.SetPermissionlessFaults(nil)
	return block
}

func withoutAddress(committee *bftview.Committee, public string) *bftview.Committee {
	stripped := &bftview.Committee{List: make([]*common.Cnode, len(committee.List))}
	for i, member := range committee.List {
		if member == nil {
			continue
		}
		clone := *member
		if clone.Public == public {
			clone.Address = ""
		}
		stripped.List[i] = &clone
	}
	return stripped
}

// A node that leaves and returns was stored locally without its address, and
// the following time-reconfig keys copied that record. Repair must make the
// current committee readable with addresses so miner.start can authenticate.
func TestRepairRestoresReseatedMemberAddress(t *testing.T) {
	kept := []*common.Cnode{
		repairTestNode("13.140.169.170:7102", "0x01", "aa"),
		repairTestNode("13.140.169.170:7104", "0x02", "bb"),
		repairTestNode("13.140.169.170:7106", "0x03", "cc"),
	}
	former := repairTestNode("10.0.0.4:7110", "0x04", "dd")
	external := repairTestNode("13.140.169.170:7155", "0x93", "ee")
	live := repairTestNode("13.140.169.170:7110", former.CoinBase, former.Public)

	original := &bftview.Committee{List: append(append([]*common.Cnode{}, kept...), former)}
	evicted := &bftview.Committee{List: append(append([]*common.Cnode{}, kept...), external)}
	returned := &bftview.Committee{List: append(append([]*common.Cnode{}, kept...), live)}

	chain := &repairTestChain{}
	genesis := repairTestBlock(nil, 0, types.Initialization, original, nil, nil, original.List[0])
	chain.add(genesis)
	replaced := repairTestBlock(genesis, 1, types.PowReconfig, evicted, external, former, evicted.List[0])
	chain.add(replaced)
	reseated := repairTestBlock(replaced, 2, types.PowReconfig, returned, live, external, returned.List[0])
	chain.add(reseated)
	carried := repairTestBlock(reseated, 3, types.TimeReconfig, returned, returned.List[0], nil, returned.List[0])
	chain.add(carried)

	db := rawdb.NewMemoryDatabase()
	bftview.SetCommitteeConfig(db, chain, nil)
	t.Cleanup(func() {
		bftview.SetServerInfo("", "")
		bftview.SetCommitteeConfig(nil, nil, nil)
		db.Close()
	})
	if !original.StoreWithoutCallback(genesis) || !evicted.StoreWithoutCallback(replaced) {
		t.Fatal("store addressed ancestor committees")
	}
	if !withoutAddress(returned, live.Public).StoreWithoutCallback(reseated) {
		t.Fatal("store reseated committee without its address")
	}
	if !withoutAddress(returned, live.Public).StoreWithoutCallback(carried) {
		t.Fatal("store carried committee without its address")
	}
	if bftview.LoadMember(carried.NumberU64(), carried.Hash(), true) != nil {
		t.Fatal("address-less committee was readable")
	}

	service := &Service{kbc: nil, netService: &netService{serverAddress: live.Address}}
	// The production caller passes the live key chain. The helper is used
	// directly here because Service.kbc is the concrete chain type.
	bftview.SetServerInfo(live.Address, live.Public)
	repairStoredCommitteeAddresses(chain, carried, bftview.GetServerInfo(bftview.PublicKey), service.netService.serverAddress, nil)

	restored := bftview.LoadMember(carried.NumberU64(), carried.Hash(), true)
	if restored == nil || !restored.HasIP() {
		t.Fatal("current committee is still missing addresses")
	}
	if restored.RlpHash() != carried.CommitteeHash() {
		t.Fatalf("restored committee hash %s, block has %s", restored.RlpHash(), carried.CommitteeHash())
	}
	found, index := restored.Get(live.Public, bftview.PublicKey)
	if found == nil || index != 3 || found.Address != live.Address {
		t.Fatalf("reseated member = index %d address %q", index, found)
	}
	for seat, member := range kept {
		got, _ := restored.Get(member.Public, bftview.PublicKey)
		if got == nil || got.Address != member.Address {
			t.Fatalf("seat %d address changed to %v", seat, got)
		}
	}
}

func TestRepairRestoresCommitteeReadFromDatabase(t *testing.T) {
	kept := []*common.Cnode{
		repairTestNode("13.140.169.170:7102", "0x01", "aa"),
		repairTestNode("13.140.169.170:7104", "0x02", "bb"),
		repairTestNode("13.140.169.170:7106", "0x03", "cc"),
	}
	former := repairTestNode("10.0.0.4:7110", "0x04", "dd")
	external := repairTestNode("13.140.169.170:7155", "0x93", "ee")
	live := repairTestNode("13.140.169.170:7110", former.CoinBase, former.Public)
	original := &bftview.Committee{List: append(append([]*common.Cnode{}, kept...), former)}
	evicted := &bftview.Committee{List: append(append([]*common.Cnode{}, kept...), external)}
	returned := &bftview.Committee{List: append(append([]*common.Cnode{}, kept...), live)}

	chain := &repairTestChain{}
	chain.add(repairTestBlock(nil, 0, types.Initialization, original, nil, nil, original.List[0]))
	replaced := repairTestBlock(chain.head, 1, types.PowReconfig, evicted, external, former, evicted.List[0])
	chain.add(replaced)
	reseated := blockAsStored(repairTestBlock(replaced, 2, types.PowReconfig, returned, live, external, returned.List[0]))
	chain.add(reseated)
	carried := blockAsStored(repairTestBlock(reseated, 3, types.TimeReconfig, returned, returned.List[0], nil, returned.List[0]))
	chain.add(carried)
	if reseated.PermissionlessSeat() || carried.PermissionlessSeat() {
		t.Fatal("stored key block kept the permissionless flag")
	}

	db := rawdb.NewMemoryDatabase()
	bftview.SetCommitteeConfig(db, chain, nil)
	t.Cleanup(func() {
		bftview.SetServerInfo("", "")
		bftview.SetCommitteeConfig(nil, nil, nil)
		db.Close()
	})
	if !original.StoreWithoutCallback(chain.blocks[replaced.ParentHash()]) || !evicted.StoreWithoutCallback(replaced) {
		t.Fatal("store addressed ancestor committees")
	}
	if !withoutAddress(returned, live.Public).StoreWithoutCallback(reseated) || !withoutAddress(returned, live.Public).StoreWithoutCallback(carried) {
		t.Fatal("store committees without the reseated address")
	}
	bftview.SetServerInfo(live.Address, live.Public)
	repairStoredCommitteeAddresses(chain, carried, live.Public, live.Address, nil)

	restored := bftview.LoadMember(carried.NumberU64(), carried.Hash(), true)
	if restored == nil || !restored.HasIP() || restored.RlpHash() != carried.CommitteeHash() {
		t.Fatal("database-loaded committee was not restored")
	}
	found, _ := restored.Get(live.Public, bftview.PublicKey)
	if found == nil || found.Address != live.Address {
		t.Fatalf("reseated address = %v", found)
	}
}

func TestRepairRecoversAddressFromAncestorCommittee(t *testing.T) {
	former := repairTestNode("13.140.169.170:7110", "0x04", "dd")
	external := repairTestNode("13.140.169.170:7155", "0x93", "ee")
	keeper := repairTestNode("13.140.169.170:7102", "0x01", "aa")
	original := &bftview.Committee{List: []*common.Cnode{keeper, former}}
	evicted := &bftview.Committee{List: []*common.Cnode{keeper, external}}
	returned := &bftview.Committee{List: []*common.Cnode{keeper, &common.Cnode{CoinBase: former.CoinBase, Public: former.Public}}}

	chain := &repairTestChain{}
	genesis := repairTestBlock(nil, 0, types.Initialization, original, nil, nil, keeper)
	chain.add(genesis)
	replaced := repairTestBlock(genesis, 1, types.PowReconfig, evicted, external, former, keeper)
	chain.add(replaced)
	reseated := repairTestBlock(replaced, 2, types.PowReconfig, &bftview.Committee{List: []*common.Cnode{keeper, former}}, former, external, keeper)
	chain.add(reseated)

	db := rawdb.NewMemoryDatabase()
	bftview.SetCommitteeConfig(db, chain, nil)
	t.Cleanup(func() {
		bftview.SetServerInfo("", "")
		bftview.SetCommitteeConfig(nil, nil, nil)
		db.Close()
	})
	if !original.StoreWithoutCallback(genesis) || !evicted.StoreWithoutCallback(replaced) || !returned.StoreWithoutCallback(reseated) {
		t.Fatal("store committees")
	}
	bftview.SetServerInfo(keeper.Address, keeper.Public)
	repairStoredCommitteeAddresses(chain, reseated, keeper.Public, keeper.Address, nil)

	restored := bftview.LoadMember(reseated.NumberU64(), reseated.Hash(), true)
	if restored == nil {
		t.Fatal("ancestor address was not restored")
	}
	found, _ := restored.Get(former.Public, bftview.PublicKey)
	if found == nil || found.Address != former.Address {
		t.Fatalf("restored address %v, want %s", found, former.Address)
	}
}

func TestRepairUsesCertifiedCandidateEndpoint(t *testing.T) {
	keeper := repairTestNode("13.140.169.170:7102", "0x01", "aa")
	former := repairTestNode("13.140.169.170:7110", "0x04", "dd")
	external := repairTestNode("13.140.169.170:7155", "0x93", "ee")
	parentCommittee := &bftview.Committee{List: []*common.Cnode{keeper, former}}
	childCommittee := &bftview.Committee{List: []*common.Cnode{keeper, &common.Cnode{CoinBase: external.CoinBase, Public: external.Public}}}

	chain := &repairTestChain{}
	genesis := repairTestBlock(nil, 0, types.Initialization, parentCommittee, nil, nil, keeper)
	chain.add(genesis)
	child := repairTestBlock(genesis, 1, types.PowReconfig, childCommittee, external, former, keeper)
	chain.add(child)

	db := rawdb.NewMemoryDatabase()
	bftview.SetCommitteeConfig(db, chain, nil)
	t.Cleanup(func() {
		bftview.SetServerInfo("", "")
		bftview.SetCommitteeConfig(nil, nil, nil)
		db.Close()
	})
	if !parentCommittee.StoreWithoutCallback(genesis) {
		t.Fatal("store parent committee")
	}
	bftview.SetServerInfo(keeper.Address, keeper.Public)
	repairStoredCommitteeAddresses(chain, child, keeper.Public, keeper.Address, func(block *types.KeyBlock) (string, bool) {
		return "", false
	})
	if got := bftview.LoadMember(child.NumberU64(), child.Hash(), true); got != nil {
		t.Fatal("unverified candidate endpoint became dialable")
	}

	repairStoredCommitteeAddresses(chain, child, keeper.Public, keeper.Address, func(block *types.KeyBlock) (string, bool) {
		if block.Hash() != child.Hash() || block.InPubKey() != external.Public {
			return "192.0.2.1:1", true
		}
		return external.Address, true
	})
	restored := bftview.LoadMember(child.NumberU64(), child.Hash(), true)
	if restored == nil || restored.RlpHash() != child.CommitteeHash() {
		t.Fatal("certified endpoint did not restore the committee")
	}
	found, _ := restored.Get(external.Public, bftview.PublicKey)
	if found == nil || found.Address != external.Address {
		t.Fatalf("new member address = %v, want %s", found, external.Address)
	}
}

func TestAuthenticatedNewMemberEndpointRejectsUnboundCandidate(t *testing.T) {
	keeper := repairTestNode("13.140.169.170:7102", "0x01", "aa")
	external := repairTestNode("13.140.169.170:7155", "0x93", "ee")
	committee := &bftview.Committee{List: []*common.Cnode{keeper, external}}
	block := repairTestBlock(nil, 7, types.PowReconfig, committee, external, keeper, keeper)
	candidate := &types.Candidate{
		KeyCandidate: block.Header(),
		IP:           net.ParseIP(external.Address[:strings.LastIndex(external.Address, ":")]).To4(),
		Port:         7155,
		PubKey:       external.Public,
		Coinbase:     external.CoinBase,
	}
	verified := 0
	verify := func(types.KeyChainReader, *types.Candidate) error {
		verified++
		return nil
	}
	endpoint, err := authenticatedNewMemberEndpoint(block, candidate, verify, nil)
	if err != nil || endpoint != external.Address {
		t.Fatalf("bound candidate endpoint = %s, %v", endpoint, err)
	}
	if verified != 1 {
		t.Fatalf("verifier calls = %d", verified)
	}

	swapped := *candidate
	swapped.IP = net.ParseIP("192.0.2.8").To4()
	swapped.Port = 9
	if _, err := authenticatedNewMemberEndpoint(block, &swapped, func(types.KeyChainReader, *types.Candidate) error {
		return fmt.Errorf("seal does not bind this endpoint")
	}, nil); err == nil {
		t.Fatal("rejected seal supplied an endpoint")
	}
	other := *candidate
	other.PubKey = "ff"
	if _, err := authenticatedNewMemberEndpoint(block, &other, verify, nil); err == nil {
		t.Fatal("different public key supplied an endpoint")
	}
	unspecified := *candidate
	unspecified.IP = net.IPv4zero.To4()
	if _, err := authenticatedNewMemberEndpoint(block, &unspecified, verify, nil); err == nil {
		t.Fatal("unspecified address supplied an endpoint")
	}
}
