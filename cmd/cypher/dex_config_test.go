package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/cmd/utils"
	cli "gopkg.in/urfave/cli.v1"
)

func TestDEXConfigurationRoundTripAndExplicitDisable(t *testing.T) {
	want := utils.DEXConfig{Validator: true, Config: "/dedicated/devnet/registration.json"}
	raw, err := tomlSettings.Marshal(struct{ DEX utils.DEXConfig }{want})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var loaded gethConfig
	if err = loadConfig(path, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.DEX != want {
		t.Fatal("DEX config did not persist", loaded.DEX)
	}
	for _, tc := range []struct {
		name string
		args []string
		want utils.DEXConfig
	}{
		{"absent_preserves_saved", nil, want},
		{"explicit_disable", []string{"--dex.validator=false"}, utils.DEXConfig{Config: want.Config}},
		{"path_only", []string{"--dex.config=/new/devnet/registration.json"}, utils.DEXConfig{Validator: true, Config: "/new/devnet/registration.json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := flag.NewFlagSet("DEX", flag.ContinueOnError)
			utils.DEXValidatorFlag.Apply(flags)
			utils.DEXConfigFlag.Apply(flags)
			if err := flags.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			cfg := loaded.DEX
			utils.SetDEXConfig(cli.NewContext(cli.NewApp(), flags, nil), &cfg)
			if cfg != tc.want {
				t.Fatal("explicit flag precedence", cfg, tc.want)
			}
		})
	}
	flags := flag.NewFlagSet("default", flag.ContinueOnError)
	utils.DEXValidatorFlag.Apply(flags)
	utils.DEXConfigFlag.Apply(flags)
	var disabled utils.DEXConfig
	utils.SetDEXConfig(cli.NewContext(cli.NewApp(), flags, nil), &disabled)
	if disabled.Validator || disabled.Config != "" {
		t.Fatal("DEX enabled by default")
	}
}
