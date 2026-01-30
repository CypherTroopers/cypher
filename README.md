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
./build/bin/cypher --datadir ./data3 export ./exports/blocks-000001-184999.rlp 1 184999
~~~
~~~
./build/bin/cypher --datadir ./data4 export ./exports/blocks-185000-208223.rlp 185000 208223
~~~
~~~
scripts/rebuild-state-from-blocks.sh --datadir ./data5 --genesis ./genesis.json --blocks ./exports --cache 4096 --syncmode full --gcmode archive

~~~
~~~
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
	flag.Parse()
	if *chaindata == "" {
		log.Fatal("need -chaindata")
	}

	db, err := rawdb.NewLevelDBDatabase(*chaindata, 256, 256, "")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	genesisHash := rawdb.ReadCanonicalHash(db, 0)
	fmt.Println("genesisHash =", genesisHash)
	if genesisHash == (common.Hash{}) {
		log.Fatal("genesisHash is empty (0x00..00). Did you run `cypher init` on this datadir?")
	}

	old := rawdb.ReadChainConfig(db, genesisHash)
	fmt.Printf("old chainConfig = %+v\n", old)

	rawdb.WriteChainConfig(db, genesisHash, params.MainnetChainConfig)

	newcfg := rawdb.ReadChainConfig(db, genesisHash)
	fmt.Printf("new chainConfig = %+v\n", newcfg)

	fmt.Println("OK: chain config written into DB")
}
EOF
~~~

