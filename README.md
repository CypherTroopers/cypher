~~~
touch chaindbname/cypher/blocks.rlp
~~~
all blocks ver
~~~
./build/bin/cypher --datadir ./chaindbname  export ./chaindbname/cypher/blocks.rlp
~~~
Range specification　ver
~~~
./build/bin/cypher --datadir ./chaindbname export ./chaindbname/cypher/blocks.rlp 0 141118
~~~
###
~~~
mkdir chaindata-rebuild
~~~
###
~~~
chmod +x scripts/rebuild-state-from-blocks.sh
~~~
###
~~~
./scripts/rebuild-state-from-blocks.sh --datadir ./chaindata-rebuild --genesis ./genesis.json --blocks ./chaindbname/cypher/blocks.rlp --cache 4096 --syncmode full --gcmode archive
~~~
###
~~~
./build/bin/cypher --datadir ./chaindata-rebuild <your usual flags>
~~~
###
~~~
./build/bin/cypher attach ipc:./chaindata-rebuild/cypher.ipc
~~~
###export　and import
~~~
mkdir -p ./exports
~~~
~~~
./build/bin/cypher --datadir ./data3 export ./exports/blocks-000001-184999.rlp 1 184999
~~~
~~~
./build/bin/cypher --datadir ./data4 export ./exports/blocks-185000-208223.rlp 185000 208223
~~~
~~~
scripts/rebuild-state-from-blocks.sh --datadir ./data5 --genesis ./genesis.json --blocks ./exports --cache 4096 --syncmode full --gcmode archive
~~~
~~~bash
cat > /tmp/fixcfg.go <<'EOF'
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/params"
)

func main() {
	chaindata := flag.String("chaindata", "", "path to .../cypher/chaindata")
	dry := flag.Bool("dry", false, "dry-run (do not write)")
	flag.Parse()
	if *chaindata == "" {
		log.Fatal("need -chaindata")
	}

	db, err := rawdb.NewLevelDBDatabase(*chaindata, 256, 256, "")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// canonical hash for block 0
	h0 := rawdb.ReadCanonicalHash(db, 0)
	fmt.Println("canonicalHash(0) =", h0)
	if h0 == (common.Hash{}) {
		log.Fatal("canonicalHash(0) is empty -> this DB is not properly initialized (run `cypher init` on this datadir)")
	}

	// sanity: header(0) should exist and its hash should match canonicalHash(0)
	head0 := rawdb.ReadHeader(db, h0, 0)
	if head0 == nil {
		log.Fatal("header(0) is nil -> block 0 header not found in DB (init likely wrong or different namespace)")
	}
	fmt.Println("header(0).hash   =", head0.Hash())
	if head0.Hash() != h0 {
		log.Fatal("mismatch: header(0).hash != canonicalHash(0) -> wrong DB/namespace/path")
	}

	// show current chain config
	old := rawdb.ReadChainConfig(db, h0)
	fmt.Printf("old chainConfig = %+v\n", old)

	// show the config we are about to write
	fmt.Printf("params.MainnetChainConfig = %+v\n", params.MainnetChainConfig)

	if *dry {
		fmt.Println("DRY-RUN: not writing chain config")
		return
	}

	// write config
	rawdb.WriteChainConfig(db, h0, params.MainnetChainConfig)

	newcfg := rawdb.ReadChainConfig(db, h0)
	fmt.Printf("new chainConfig = %+v\n", newcfg)

	fmt.Println("OK: chain config written into DB")
}
EOF
~~~
~~~
go run /tmp/fixcfg.go -dry -chaindata /root/go/src/github.com/cypherium/cypher/data5/cypher/chaindata
~~~
~~~
go run /tmp/fixcfg.go -chaindata /root/go/src/github.com/cypherium/cypher/data5/cypher/chaindata
~~~
