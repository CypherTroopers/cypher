package utils

import cli "gopkg.in/urfave/cli.v1"

var DEXValidatorFlag = cli.BoolFlag{Name: "dex.validator", Usage: "Run a separate registered DEX validator sidecar (isolated devnet only)"}
var DEXConfigFlag = cli.StringFlag{Name: "dex.config", Usage: "Dedicated DEX devnet JSON registration/configuration file"}

// DEXConfig persists only participation intent and the dedicated manifest path.
// It never shares miner coinbase, RPC signer, reconfig identity, or vote keys.
type DEXConfig struct {
	Validator bool
	Config    string
}

func SetDEXConfig(ctx *cli.Context, cfg *DEXConfig) {
	if ctx.GlobalIsSet(DEXValidatorFlag.Name) {
		cfg.Validator = ctx.GlobalBool(DEXValidatorFlag.Name)
	}
	if ctx.GlobalIsSet(DEXConfigFlag.Name) {
		cfg.Config = ctx.GlobalString(DEXConfigFlag.Name)
	}
}
