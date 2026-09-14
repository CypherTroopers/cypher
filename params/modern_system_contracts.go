package params

import "github.com/cypherium/cypher/common"

var (
	// SystemAddress is the privileged caller used by execution-layer system
	// contracts. It has no private key and cannot originate a transaction.
	SystemAddress = common.HexToAddress("0xfffffffffffffffffffffffffffffffffffffffe")

	// EIP-2935 history storage contract. ColossusX supplies the canonical parent
	// transaction-block hash; no Beacon consensus dependency is required.
	HistoryStorageAddress = common.HexToAddress("0x0000F90827F1C53a10cb7A02335B175320002935")
	HistoryStorageCode    = common.FromHex(
		"3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111604257611fff81430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303065500",
	)

	// These canonical Ethereum system-contract addresses depend on Beacon/CL
	// inputs that ColossusX does not possess. They are installed with a tiny
	// always-reverting runtime so calls fail explicitly instead of succeeding as
	// empty-account calls and silently pretending the CL-dependent feature ran.
	BeaconRootsAddress          = common.HexToAddress("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02")
	WithdrawalRequestAddress    = common.HexToAddress("0x00000961Ef480Eb55e80D19ad83579A64c007002")
	ConsolidationRequestAddress = common.HexToAddress("0x0000BBdDc7CE488642fb579F8B00f3a590007251")
	UnsupportedCLSystemCode     = common.FromHex("0x5f5ffd") // PUSH0 PUSH0 REVERT
)
