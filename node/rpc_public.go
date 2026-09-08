package node

import (
	"sort"
	"strings"
)

// This is the network RPC authority boundary. Module configuration and API.Public
// only select from this list. New methods, aliases, promoted Go methods, and new
// namespaces require an explicit review here before they become network APIs.
// Services themselves are shared with IPC, so stateful raw TX workers are not
// constructed twice. The filter never inspects TX senders or invokes a wallet.
var publicRPCMethods = func() map[string]bool {
	groups := map[string]string{
		"rpc":  "modules",
		"web3": "clientVersion sha3",
		"net":  "listening peerCount version",
		"eth": `accounts gasPrice maxPriorityFeePerGas feeHistory protocolVersion syncing
			chainId blockNumber keyBlockNumber getBalance getProof getHeaderByNumber getHeaderByHash
			getBlockByNumber getBlockByHash getUncleByBlockNumberAndIndex getKeyBlockByNumber
			getKeyBlockByHash getKeyBlocksByNumbers getUncleByBlockHashAndIndex
			getUncleCountByBlockNumber getUncleCountByBlockHash getCommitteeMember getCode getStorageAt
			call estimateGas getBlockTransactionCountByNumber getBlockTransactionCountByHash
			getTransactionByBlockNumberAndIndex getTransactionByBlockHashAndIndex
			getRawTransactionByBlockNumberAndIndex getRawTransactionByBlockHashAndIndex
			getTransactionCount getTransactionByHash getRawTransactionByHash getTransactionReceipt
			fillTransaction sendRawTransactions sendRawTransaction sendRawTransactionWithOpts pendingTransactions
			etherbase coinbase hashrate status committeeMembers mining
			newPendingTransactionFilter newBlockFilter newFilter getLogs uninstallFilter getFilterLogs getFilterChanges`,
		"txpool":   "content status inspect",
		"personal": "listAccounts listWallets ecRecover",
		"miner":    "status getHashrate content",
		"admin":    "peers nodeInfo datadir",
		"debug": `getBlockRlp printBlock seedHash chaindbProperty dumpBlock accountRange preimage getBadBlocks
			storageRangeAt getModifiedAccountsByNumber getModifiedAccountsByHash memStats gcStats stacks`,
		"clique":   "getSnapshot getSnapshotAtHash getSigners getSignersAtHash proposals status",
		"reconfig": "role leader fhsStatus roleList id members exceptions",
	}
	methods := make(map[string]bool)
	for namespace, names := range groups {
		for _, name := range strings.Fields(names) {
			methods[namespace+"_"+name] = true
		}
	}
	return methods
}()

var publicRPCSubscriptions = map[string]bool{
	"eth_syncing": true, "eth_newPendingTransactions": true,
	"eth_newHeads": true, "eth_newKeyHeads": true, "eth_logs": true,
	"admin_peerEvents": true,
}

func allowPublicRPCMethod(method string, subscription bool) bool {
	if subscription {
		return publicRPCSubscriptions[method]
	}
	return publicRPCMethods[method]
}

// PublicRPCMethods returns the full network allowlist, independent of configured
// modules. RegisteredMethods on a server reports its actual selected inventory.
// Subscription callbacks are represented as namespace_subscribe:subscriptionName.
func PublicRPCMethods() []string {
	methods := make([]string, 0, len(publicRPCMethods)+len(publicRPCSubscriptions))
	for method := range publicRPCMethods {
		methods = append(methods, method)
	}
	for method := range publicRPCSubscriptions {
		parts := strings.SplitN(method, "_", 2)
		methods = append(methods, parts[0]+"_subscribe:"+parts[1])
	}
	sort.Strings(methods)
	return methods
}
