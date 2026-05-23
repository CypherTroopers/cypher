package t8ntool

import "gopkg.in/urfave/cli.v1"

var (
	InputHeaderFlag = cli.StringFlag{
		Name:  "input.header",
		Usage: "stdin or file name of where to find the block header json to use.",
		Value: "header.json",
	}
	InputTxsRlpFlag = cli.StringFlag{
		Name:  "input.txs.rlp",
		Usage: "stdin or file name of where to find the block transaction list RLP hex.",
		Value: "txs.rlp",
	}
	InputOmmersFlag = cli.StringFlag{
		Name:  "input.ommers",
		Usage: "stdin or file name of where to find the ommer RLP list json.",
		Value: "",
	}
	OutputBlockFlag = cli.StringFlag{
		Name:  "output.block",
		Usage: "Determines where to put the assembled block output.",
		Value: "block.json",
	}
	SealCliqueFlag = cli.StringFlag{
		Name:  "seal.clique",
		Usage: "Clique sealing input file. Present for b11r compatibility; ColossusX builds leave this empty.",
		Value: "",
	}
)
