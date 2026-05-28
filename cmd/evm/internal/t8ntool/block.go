package t8ntool

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/rlp"
	"gopkg.in/urfave/cli.v1"
)

type blockHeaderInput struct {
	ParentHash  common.Hash       `json:"parentHash"`
	OmmerHash   *common.Hash      `json:"sha3Uncles"`
	Coinbase    *common.Address   `json:"miner"`
	Root        common.Hash       `json:"stateRoot"`
	TxHash      *common.Hash      `json:"transactionsRoot"`
	ReceiptHash *common.Hash      `json:"receiptsRoot"`
	Bloom       types.Bloom       `json:"logsBloom"`
	Difficulty  *big.Int          `json:"difficulty"`
	Number      *big.Int          `json:"number"`
	GasLimit    uint64            `json:"gasLimit"`
	GasUsed     uint64            `json:"gasUsed"`
	Time        uint64            `json:"timestamp"`
	Extra       []byte            `json:"extraData"`
	MixDigest   common.Hash       `json:"mixHash"`
	Nonce       *types.BlockNonce `json:"nonce"`

	BaseFee               *big.Int     `json:"baseFeePerGas"`
	WithdrawalsHash       *common.Hash `json:"withdrawalsRoot"`
	BlobGasUsed           *uint64      `json:"blobGasUsed"`
	ExcessBlobGas         *uint64      `json:"excessBlobGas"`
	ParentBeaconBlockRoot *common.Hash `json:"parentBeaconBlockRoot"`
	RequestsHash          *common.Hash `json:"requestsHash"`

	BlockType *uint8       `json:"blockType"`
	KeyHash   *common.Hash `json:"keyHash"`
	KeyInfo   []byte       `json:"keyInfo"`
}

type bbInput struct {
	Header    *blockHeaderInput `json:"header,omitempty"`
	TxRlp     string            `json:"txs,omitempty"`
	OmmersRlp []string          `json:"ommers,omitempty"`
	Clique    json.RawMessage   `json:"clique,omitempty"`

	Txs    []*types.Transaction `json:"-"`
	Ommers []*types.Header      `json:"-"`
}

func (i *bbInput) ToBlock() (*types.Block, error) {
	if i == nil || i.Header == nil {
		return nil, NewError(ErrorJson, fmt.Errorf("missing block header input"))
	}
	headerInput := i.Header
	header := &types.Header{
		ParentHash:  headerInput.ParentHash,
		UncleHash:   types.EmptyUncleHash,
		Coinbase:    common.Address{},
		Root:        headerInput.Root,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Bloom:       headerInput.Bloom,
		Difficulty:  big.NewInt(0),
		Number:      big.NewInt(0),
		GasLimit:    headerInput.GasLimit,
		GasUsed:     headerInput.GasUsed,
		Time:        headerInput.Time,
		Extra:       common.CopyBytes(headerInput.Extra),
		MixDigest:   headerInput.MixDigest,
	}
	if headerInput.BaseFee != nil {
		header.BaseFee = new(big.Int).Set(headerInput.BaseFee)
	}
	if headerInput.Number != nil {
		header.Number = new(big.Int).Set(headerInput.Number)
	}
	if headerInput.Difficulty != nil {
		header.Difficulty = new(big.Int).Set(headerInput.Difficulty)
	}
	if headerInput.OmmerHash != nil {
		header.UncleHash = *headerInput.OmmerHash
	} else if len(i.Ommers) > 0 {
		header.UncleHash = types.CalcUncleHash(i.Ommers)
	}
	if headerInput.Coinbase != nil {
		header.Coinbase = *headerInput.Coinbase
	}
	if headerInput.TxHash != nil {
		header.TxHash = *headerInput.TxHash
	}
	if headerInput.ReceiptHash != nil {
		header.ReceiptHash = *headerInput.ReceiptHash
	}
	if headerInput.Nonce != nil {
		header.Nonce = *headerInput.Nonce
	}
	if headerInput.WithdrawalsHash != nil {
		header.WithdrawalsHash = *headerInput.WithdrawalsHash
	}
	if headerInput.BlobGasUsed != nil {
		header.BlobGasUsed = *headerInput.BlobGasUsed
	}
	if headerInput.ExcessBlobGas != nil {
		header.ExcessBlobGas = *headerInput.ExcessBlobGas
	}
	if headerInput.ParentBeaconBlockRoot != nil {
		header.ParentBeaconRoot = *headerInput.ParentBeaconBlockRoot
	}
	if headerInput.RequestsHash != nil {
		header.RequestsHash = *headerInput.RequestsHash
	}
	if headerInput.BlockType != nil {
		header.BlockType = *headerInput.BlockType
	}
	if headerInput.KeyHash != nil {
		header.KeyHash = *headerInput.KeyHash
	}
	if len(headerInput.KeyInfo) > 0 {
		header.KeyInfo = common.CopyBytes(headerInput.KeyInfo)
	}
	return types.NewBlockWithHeader(header).WithBody(i.Txs, i.Ommers), nil
}

func BuildBlock(ctx *cli.Context) error {
	baseDir := ""
	if base := ctx.String(OutputBasedir.Name); len(base) > 0 {
		if err := os.MkdirAll(base, 0755); err != nil {
			return NewError(ErrorIO, fmt.Errorf("failed creating output basedir: %v", err))
		}
		baseDir = base
	}
	if val := ctx.String(SealCliqueFlag.Name); val != "" {
		return NewError(ErrorIO, fmt.Errorf("seal.clique is not supported in this cypherium b11r implementation"))
	}
	inputData, err := readBlockInput(ctx)
	if err != nil {
		return err
	}
	block, err := inputData.ToBlock()
	if err != nil {
		return err
	}
	return dispatchBlock(ctx, baseDir, block)
}

func readBlockInput(ctx *cli.Context) (*bbInput, error) {
	in := &bbInput{}
	headerPath := ctx.String(InputHeaderFlag.Name)
	txsPath := ctx.String(InputTxsRlpFlag.Name)
	ommersPath := ctx.String(InputOmmersFlag.Name)
	cliquePath := ctx.String(SealCliqueFlag.Name)

	if headerPath == stdinSelector || txsPath == stdinSelector || ommersPath == stdinSelector || cliquePath == stdinSelector {
		if err := json.NewDecoder(os.Stdin).Decode(in); err != nil {
			return nil, NewError(ErrorJson, fmt.Errorf("failed unmarshalling stdin: %v", err))
		}
	}
	if headerPath != stdinSelector {
		if err := readJSONFile(headerPath, &in.Header); err != nil {
			return nil, err
		}
	}
	if txsPath != stdinSelector {
		txRlp, err := readRLPHexFile(txsPath)
		if err != nil {
			return nil, err
		}
		in.TxRlp = txRlp
	}
	if ommersPath != "" && ommersPath != stdinSelector {
		if err := readJSONFile(ommersPath, &in.OmmersRlp); err != nil {
			return nil, err
		}
	}
	if in.Header == nil {
		return nil, NewError(ErrorJson, fmt.Errorf("missing block header input"))
	}

	var txs []*types.Transaction
	if in.TxRlp != "" {
		if err := rlp.DecodeBytes(common.FromHex(in.TxRlp), &txs); err != nil {
			return nil, NewError(ErrorRlp, fmt.Errorf("unable to decode transaction list from rlp data: %v", err))
		}
	}
	in.Txs = txs
	for _, enc := range in.OmmersRlp {
		type extblock struct {
			Header *types.Header
			Txs    []*types.Transaction
			Ommers []*types.Header
		}
		var ommer *extblock
		if err := rlp.DecodeBytes(common.FromHex(enc), &ommer); err != nil {
			return nil, NewError(ErrorRlp, fmt.Errorf("unable to decode ommer from rlp data: %v", err))
		}
		in.Ommers = append(in.Ommers, ommer.Header)
	}
	return in, nil
}

func readJSONFile(file string, out interface{}) error {
	f, err := os.Open(file)
	if err != nil {
		return NewError(ErrorIO, fmt.Errorf("failed reading input file %s: %v", file, err))
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(out); err != nil {
		return NewError(ErrorJson, fmt.Errorf("failed unmarshalling input file %s: %v", file, err))
	}
	return nil
}

func readRLPHexFile(file string) (string, error) {
	blob, err := ioutil.ReadFile(file)
	if err != nil {
		return "", NewError(ErrorIO, fmt.Errorf("failed reading input file %s: %v", file, err))
	}
	var encoded string
	if err := json.Unmarshal(blob, &encoded); err != nil {
		encoded = strings.TrimSpace(string(blob))
	} else {
		encoded = strings.TrimSpace(encoded)
	}
	if encoded == "" {
		return "", nil
	}
	if !strings.HasPrefix(encoded, "0x") && !strings.HasPrefix(encoded, "0X") {
		return "", NewError(ErrorRlp, fmt.Errorf("rlp input file %s must contain a 0x-prefixed hex string", file))
	}
	return encoded, nil
}

func dispatchBlock(ctx *cli.Context, baseDir string, block *types.Block) error {
	raw, err := rlp.EncodeToBytes(block)
	if err != nil {
		return NewError(ErrorRlp, fmt.Errorf("failed encoding block to rlp: %v", err))
	}
	enc := struct {
		Rlp  hexutil.Bytes `json:"rlp"`
		Hash common.Hash   `json:"hash"`
	}{Rlp: raw, Hash: block.Hash()}

	switch out := ctx.String(OutputBlockFlag.Name); out {
	case "stdout":
		b, err := json.MarshalIndent(enc, "", " ")
		if err != nil {
			return NewError(ErrorJson, fmt.Errorf("failed marshalling output: %v", err))
		}
		os.Stdout.Write(b)
		os.Stdout.WriteString("\n")
	case "stderr":
		b, err := json.MarshalIndent(enc, "", " ")
		if err != nil {
			return NewError(ErrorJson, fmt.Errorf("failed marshalling output: %v", err))
		}
		os.Stderr.Write(b)
		os.Stderr.WriteString("\n")
	default:
		if err := saveFile(baseDir, out, enc); err != nil {
			return err
		}
	}
	return nil
}
