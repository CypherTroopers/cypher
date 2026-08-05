// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import (
	"math/big"
	"time"

	"github.com/cypherium/cypher/common"
)

const (
	DisableGAS             = false
	KeyblockPerTxBlocks    = 360
	MaxTxCountPerBlock     = 1024
	AckTimeout             = 120 * time.Second
	HeatBeatTimeout        = 10 * time.Second
	PaceMakerTimeout       = 3 * time.Minute
	KeyBlockTimeout        = 20 * time.Minute
	KeyBlock_Reward        = 1e+18 // Block reward in wei for successfully mining a block
	CheckBackNumber        = 10
	CollectVoteInfoTimeout = 5 * time.Second

	// these are original values from upstream Geth, used in ethash consensus
	OriginalMinGasLimit          uint64 = 5000
	OriginalGasLimitBoundDivisor uint64 = 1024

	// modified values for Cypher
	GasLimitBoundDivisor uint64 = 4096
	MinGasLimit          uint64 = 700000000
	GenesisGasLimit      uint64 = 800000000

	MaximumExtraDataSize  uint64 = 51200
	ExpByteGas            uint64 = 10
	SloadGas              uint64 = 50
	CallValueTransferGas  uint64 = 9000
	CallNewAccountGas     uint64 = 25000
	TxGas                 uint64 = 21000
	TxGasContractCreation uint64 = 53000
	TxDataZeroGas         uint64 = 4
	QuadCoeffDiv          uint64 = 512
	LogDataGas            uint64 = 8
	CallStipend           uint64 = 2300

	Sha3Gas     uint64 = 30
	Sha3WordGas uint64 = 6

	SstoreSetGas    uint64 = 20000
	SstoreResetGas  uint64 = 5000
	SstoreClearGas  uint64 = 5000
	SstoreRefundGas uint64 = 15000

	NetSstoreNoopGas  uint64 = 200
	NetSstoreInitGas  uint64 = 20000
	NetSstoreCleanGas uint64 = 5000
	NetSstoreDirtyGas uint64 = 200

	NetSstoreClearRefund      uint64 = 15000
	NetSstoreResetRefund      uint64 = 4800
	NetSstoreResetClearRefund uint64 = 19800

	SstoreSentryGasEIP2200   uint64 = 2300
	SstoreNoopGasEIP2200     uint64 = 800
	SstoreDirtyGasEIP2200    uint64 = 800
	SstoreInitGasEIP2200     uint64 = 20000
	SstoreInitRefundEIP2200  uint64 = 19200
	SstoreCleanGasEIP2200    uint64 = 5000
	SstoreCleanRefundEIP2200 uint64 = 4200
	SstoreClearRefundEIP2200 uint64 = 15000

	JumpdestGas   uint64 = 1
	EpochDuration uint64 = 30000

	CreateDataGas            uint64 = 200
	CallCreateDepth          uint64 = 1024
	ExpGas                   uint64 = 10
	LogGas                   uint64 = 375
	CopyGas                  uint64 = 3
	StackLimit               uint64 = 1024
	TierStepGas              uint64 = 0
	LogTopicGas              uint64 = 375
	CreateGas                uint64 = 32000
	Create2Gas               uint64 = 32000
	SelfdestructRefundGas    uint64 = 24000
	MemoryGas                uint64 = 3
	TxDataNonZeroGasFrontier uint64 = 68
	TxDataNonZeroGasEIP2028  uint64 = 16

	// These have been changed during the course of the chain
	CallGasFrontier              uint64 = 40
	CallGasEIP150                uint64 = 700
	BalanceGasFrontier           uint64 = 20
	BalanceGasEIP150             uint64 = 400
	BalanceGasEIP1884            uint64 = 700
	ExtcodeSizeGasFrontier       uint64 = 20
	ExtcodeSizeGasEIP150         uint64 = 700
	SloadGasFrontier             uint64 = 50
	SloadGasEIP150               uint64 = 200
	SloadGasEIP1884              uint64 = 800
	SloadGasEIP2200              uint64 = 800
	ExtcodeHashGasConstantinople uint64 = 400
	ExtcodeHashGasEIP1884        uint64 = 700
	SelfdestructGasEIP150        uint64 = 5000

	// EXP has a dynamic portion depending on the size of the exponent
	ExpByteFrontier uint64 = 10
	ExpByteEIP158   uint64 = 50

	// Extcodecopy has a dynamic AND a static cost.
	ExtcodeCopyBaseFrontier uint64 = 20
	ExtcodeCopyBaseEIP150   uint64 = 700

	// CreateBySelfdestructGas is used when the refunded account does not exist.
	CreateBySelfdestructGas uint64 = 25000

	MaxCodeSize = 24576

	// Precompiled contract gas prices
	EcrecoverGas        uint64 = 3000
	Sha256BaseGas       uint64 = 60
	Sha256PerWordGas    uint64 = 12
	Ripemd160BaseGas    uint64 = 600
	Ripemd160PerWordGas uint64 = 120
	IdentityBaseGas     uint64 = 15
	IdentityPerWordGas  uint64 = 3
	ModExpQuadCoeffDiv  uint64 = 20

	Bn256AddGasByzantium             uint64 = 500
	Bn256AddGasIstanbul              uint64 = 150
	Bn256ScalarMulGasByzantium       uint64 = 40000
	Bn256ScalarMulGasIstanbul        uint64 = 6000
	Bn256PairingBaseGasByzantium     uint64 = 100000
	Bn256PairingBaseGasIstanbul      uint64 = 45000
	Bn256PairingPerPointGasByzantium uint64 = 80000
	Bn256PairingPerPointGasIstanbul  uint64 = 34000

	Bls12381G1AddGas          uint64 = 600
	Bls12381G1MulGas          uint64 = 12000
	Bls12381G2AddGas          uint64 = 4500
	Bls12381G2MulGas          uint64 = 55000
	Bls12381PairingBaseGas    uint64 = 115000
	Bls12381PairingPerPairGas uint64 = 23000
	Bls12381MapG1Gas          uint64 = 5500
	Bls12381MapG2Gas          uint64 = 110000

	CypherMaximumExtraDataSize uint64 = 65
	CypherMaxPayloadBufferSize uint64 = 128
)

var BadBlockHash = []common.Hash{
	common.HexToHash("0x7434dbe3c3c6d5eb1f15004c35cd85dc7cf3aa0d0cbee1752d597d7cce6c333e"),
	common.HexToHash("0xecf9006a84f035706f955c276de0191f63d0d869f2fa17b456e0190089b361e1"),
}

// core/constants.go 新增常量定义
const (
	BadBlockNumber          = 139977
	Roll139976ParentHash    = "0xd77e54ac71f75fddcd81678a0bd0dbb6ee1d64c6a7b4a4821e1ebce04b2e3f07"
	Roll139976backTarget    = 139976
	BadKeyBlockNumber       = 131881
	NonTrustedCountThresold = 2
)

// Gas discount table for BLS12-381 G1 and G2 multi exponentiation operations
var Bls12381MultiExpDiscountTable = [128]uint64{
	1200, 888, 764, 641, 594, 547, 500, 453,
	438, 423, 408, 394, 379, 364, 349, 334,
	330, 326, 322, 318, 314, 310, 306, 302,
	298, 294, 289, 285, 281, 277, 273, 269,
	268, 266, 265, 263, 262, 260, 259, 257,
	256, 254, 253, 251, 250, 248, 247, 245,
	244, 242, 241, 239, 238, 236, 235, 233,
	232, 231, 229, 228, 226, 225, 223, 222,
	221, 220, 219, 219, 218, 217, 216, 216,
	215, 214, 213, 213, 212, 211, 211, 210,
	209, 208, 208, 207, 206, 205, 205, 204,
	203, 202, 202, 201, 200, 199, 199, 198,
	197, 196, 196, 195, 194, 193, 193, 192,
	191, 191, 190, 189, 188, 188, 187, 186,
	185, 185, 184, 183, 182, 182, 181, 180,
	179, 179, 178, 177, 176, 176, 175, 174,
}

var (
	DifficultyBoundDivisor = big.NewInt(2048)
	GenesisDifficulty      = big.NewInt(131072)
	MinimumDifficulty      = big.NewInt(131072)
	DurationLimit          = big.NewInt(13)

	BlackAddressList = []common.Address{
		common.HexToAddress("0x5561dcdc624eeb569e42698017b632a49a177fee"),
		common.HexToAddress("0xdc97e8ca50691596039e7428f6ce5d5cc43c6d17"),
		common.HexToAddress("0x43eb8148fcfba29263d7955e9091b51970cb8c67"),
	}

	TrustedAddressList = []common.Address{
		common.HexToAddress("0x8c22B884c3f774DCd4F0cC4C6E920Bd23b5d513F"),
		common.HexToAddress("0x83Ea72F02B82199B29CAE3118e163F3A05EF4B16"),
		common.HexToAddress("0x999086E1149346E803535e7176E6cE8658883f33"),
		common.HexToAddress("0xCAb788F0767A3b62c33Fe25Ee3e87A94C0403F8E"),
		common.HexToAddress("0x31cF88E26297545aBdF1E6c1f8fb041CEBb89290"),
		common.HexToAddress("0x7cB40ba4a764D646100C5A9C058791B26ffBF96E"),
		common.HexToAddress("0x05c6aCA0Ab3e47C7515c93Ea563dBaF8861d5d5f"),
		common.HexToAddress("0x2d1E776D5cE8906DcA30635819609b2bb2dE245c"),
		common.HexToAddress("0xc3a86479301b07a5849e382418fd524fc9e88fbe"),
		common.HexToAddress("0x41fb9FdF1Db61B4594e3eF0b27A6840F3d2E9208"),
		common.HexToAddress("0x5A3c2b79Faa6cf64A33a701F345E96911112cBBD"),
		common.HexToAddress("0x630484e88bA61BA42F98F81bd5981E48B3547a58"),
		common.HexToAddress("0xca0b3882b1e0a1540cfef7364ccf2ed8027fa86d"),
		common.HexToAddress("0x597fe78278722f5d96ba85bb66d67785015cbb8a"),
		common.HexToAddress("0x10CA2b7e3E26801E2A78c67000aC1982Cb8b709e"),
		common.HexToAddress("0xcA6dF652714911B4C6D14881c143cC09E9Ad61C0"),
		common.HexToAddress("0x9FFeDc42447cB915DE3EDf1593E81e95c06B408b"),
		common.HexToAddress("0x693CA592Fa363109dC8B5E8a9a0C8D467D4E69A6"),
		common.HexToAddress("0xaf006145AfceB9B3f34C03B16893c98b72160323"),
		common.HexToAddress("0x52cd8c3a22a91b93b672f8d10e19d1c6fbe1ae42"),

		common.HexToAddress("0xb2C802F5F4Da65f0F8D836c64b6Dbbb56349ce10"),
		common.HexToAddress("0x737868Db41E87d0dc7a694f7D401F016203E3D3B"),

		common.HexToAddress("0x9e566f65ca723208dae1438da4ae3b4afe2572ce"),
		common.HexToAddress("0x387e6e009605b381b872e77d3927dba96a2b6b87"),
		common.HexToAddress("0x0ed6e7154f6f80b8213116a1051efb656f76a425"),
		common.HexToAddress("0x5c4b6175868d74b6b1a6083da7c7ed0d1fc0ab9a"),
		common.HexToAddress("0x781c15851e8172035b43007f8405e8edb57de907"),
		common.HexToAddress("0xef5623c95e6bc5e46a9e19110238ca43b1cda921"),
		common.HexToAddress("0x39f5f51477a8bd2163615ca2f60f633c57cf907b"),
		common.HexToAddress("0xb5f2473e1d3d275eec3204c160fc3276ad89fa89"),
		common.HexToAddress("0x62bf2afbafcfd15cc9298356f7e2e0782fea7a33"),
		common.HexToAddress("0xd2eda44c9a6497b392ae606bfbe27d126447c643"),
		common.HexToAddress("0xe13fa7580b4be81cca6d27d7d655a09c884f712c"),
		common.HexToAddress("0x4faa1a95c2f526e06ef7917d1209e9bd9194d5aa"),
		common.HexToAddress("0x13ab4a455f41296b6545ecc448f5f4e2af289780"),
		common.HexToAddress("0xe338228b3dcec3794fbf0a205cd34ca72efe55e1"),
		common.HexToAddress("0xd6effff6f002263c77298288f680be503ddfee28"),
		common.HexToAddress("0x3d47a84aa278478d0c2bec22f0d2e82964fe61e2"),
		common.HexToAddress("0x307cd2708de635fa8c3262abc53dbaeaa8e20546"),
		common.HexToAddress("0xdf077badbf48efed9b1985f01870b691e18d01a0"),
		common.HexToAddress("0x2060cc6c17f2007eb6b84ab4454a2c0326ec063a"),
		common.HexToAddress("0x134f189e4f6d57c1feac63272ddfee1349ee065c"),
		common.HexToAddress("0x572ca5c2630b7f86ad8c2c36e0e0433b6c6449a3"),
		common.HexToAddress("0xbb9ffe0fbfc30695d6ff07907441abf04efc3cae"),
		common.HexToAddress("0x334d3ebd91ba9a82d838504285468fa1260cd6aa"),
		common.HexToAddress("0x779d7836e2fba0c31237c6fe5ddecc92a09ae43f"),
		common.HexToAddress("0x2cf82dc408d011258a3a05706e3b446d67e1452a"),
		common.HexToAddress("0xfafe548b925f5a73212c88a41063e0012fca0289"),
		common.HexToAddress("0x5fab307e1e80bc8f8f6f0c1b09d55a8f246be08f"),
		common.HexToAddress("0xffc7ad45f3049f9fe2a65ebf70e3e9b752616414"),
		common.HexToAddress("0x68ae2a95e570cbb8643281539921e8c11155ec73"),
		common.HexToAddress("0x713b947b6b938376587023bb24c2caa2f07ef60b"),
		common.HexToAddress("0x29b5af9f746a4990101b30dbb8b6f98223aaffcd"),
		common.HexToAddress("0x9b2eb23b4937f4e5f8d8987de8ba813e66335961"),
		common.HexToAddress("0x2a0d6953c779d35114cf82a886f78f8c48ff0231"),
		common.HexToAddress("0x7a5171689c241985df82822d50146943051439d0"),
		common.HexToAddress("0x9363ddaf30de209d7300624091cc39c50708d4a5"),
		common.HexToAddress("0xdc72c69c7cf39251d50ae4da16cdabf6c93c77dc"),
		common.HexToAddress("0x3a6a5fabf078f222f9ee2385037da49f84d65341"),
		common.HexToAddress("0xe68fca58cdbc69f8109a2fa90eda5645f856f9b1"),
		common.HexToAddress("0xd2f2ea1eb16cb8f35268236bed2985c9678331f9"),
		common.HexToAddress("0xaf20a440eec9fcadc99cb39a9ec73efc9356d03c"),
		common.HexToAddress("0x3dca53460920791507ce6fb7ed597da26474635a"),
		common.HexToAddress("0xd69468fed3fe7dc7dbfc68d3625a75c2a76efda0"),
		common.HexToAddress("0xfe43c802b7592f7f8243febc4caf95de095b171d"),
		common.HexToAddress("0x08b602ebb437dedfcc481b64736636a9e4ef8e8e"),
		common.HexToAddress("0xca318933a6bc3aed69430d09932d3c9617b0dfe8"),
		common.HexToAddress("0x568203c7de2829350ede712e2ae92a5993ef8f72"),
	}
)

func GetMaximumExtraDataSize(isCypher bool) uint64 {
	if isCypher {
		return CypherMaximumExtraDataSize
	}
	return MaximumExtraDataSize
}

func IsBadBlock(number uint64, hash common.Hash) bool {
	if number != BadBlockNumber {
		return false
	}
	for _, badHash := range BadBlockHash {
		if hash == badHash {
			return true
		}
	}
	return false
}
