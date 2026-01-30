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
#Test run
~~~
go run /tmp/fixcfg.go -dry -chaindata /root/go/src/github.com/cypherium/cypher/data5/cypher/chaindata
~~~
~~~
go run /tmp/fixcfg.go -chaindata /root/go/src/github.com/cypherium/cypher/data5/cypher/chaindata
~~~

##BlockScan in console
~~~bash
// mega_verify.js
// Cypher/geth console script: chain sanity checks in one run

(function () {
  // ========= config =========
  var START = 0;
  var END   = 208223;         // inclusive
  var STEP  = 1;              // 1: full scan, 10/100: sampling
  var PROGRESS_EVERY = 2000;

  var CHECK = {
    blockExist: true,         // eth.getBlock(i)
    headerExist: true,        // eth.getHeaderByNumber(i)
    receipts: false,          // tx receipts (heavy)
    txCount: false,           // eth.getBlockTransactionCount(i) (heavy)
    keyHashToKeyBlock: true,  // b.keyHash -> eth.getKeyBlockByHash
    committeeProbe: true,     // eth.committeeMembers(i) の例外/空
    storageRootProbe: false   // eth.storageRoot(i) (if your client supports)
  };

  var COMMITTEE_EVERY = 5000;   // 0: disable, or e.g. 1000/5000
  var COMMITTEE_FROM  = 0;

  // ========= state =========
  var missBlock = [];
  var missHeader = [];
  var err = [];
  var keyBlockMiss = [];    
  var committeeErr = [];
  var committeeEmpty = [];
  var receiptErr = [];
  var txCountErr = [];
  var storageRootErr = [];

  function now() { return (new Date()).toISOString(); }

  function safe(fn, onerr) {
    try { return fn(); } catch (e) { onerr(String(e)); return undefined; }
  }

  function logProgress(i) {
    if (i % PROGRESS_EVERY === 0) {
      console.log("PROGRESS", i, "/", END,
        "missBlock=", missBlock.length,
        "missHeader=", missHeader.length,
        "keyBlockMiss=", keyBlockMiss.length,
        "err=", err.length,
        "t=", now()
      );
    }
  }

  // ========= preflight =========
  console.log("=== MEGA VERIFY START ===", now());
  console.log("range", START, "->", END, "step", STEP);
  console.log("latest blockNumber =", safe(function(){ return eth.blockNumber; }, function(e){ err.push(["eth.blockNumber", e]); }));
  console.log("latest keyBlockNumber =", safe(function(){ return eth.keyBlockNumber; }, function(e){ err.push(["eth.keyBlockNumber", e]); }));
  console.log("syncing =", safe(function(){ return eth.syncing; }, function(e){ err.push(["eth.syncing", e]); }));

  // ========= scan =========
  for (var i = START; i <= END; i += STEP) {

    // --- block existence ---
    var b;
    if (CHECK.blockExist) {
      b = safe(
        function(){ return eth.getBlock(i); },
        function(e){ err.push(["getBlock", i, e]); }
      );
      if (!b) missBlock.push(i);
    }

    // --- header existence ---
    if (CHECK.headerExist) {
      var h = safe(
        function(){ return eth.getHeaderByNumber(i); },
        function(e){ err.push(["getHeaderByNumber", i, e]); }
      );
      if (!h) missHeader.push(i);
    }

    // --- keyHash -> keyblock check (Cypherium specific) ---
    if (CHECK.keyHashToKeyBlock && b && b.keyHash) {
      var kb = safe(
        function(){ return eth.getKeyBlockByHash(b.keyHash); },
        function(e){ err.push(["getKeyBlockByHash", i, String(b.keyHash), e]); }
      );
      if (!kb) keyBlockMiss.push([i, String(b.keyHash)]);
    }

    // --- tx count (optional heavy) ---
    if (CHECK.txCount) {
      var tcnt = safe(
        function(){ return eth.getBlockTransactionCount(i); },
        function(e){ txCountErr.push([i, e]); }
      );
      // optional: sanity print when huge
      // if (tcnt > 10000) console.log("HUGE_TX_COUNT", i, tcnt);
    }

    // --- receipts check (very heavy) ---
    if (CHECK.receipts && b && b.transactions && b.transactions.length) {
      for (var k = 0; k < b.transactions.length; k++) {
        var txh = b.transactions[k];
        var r = safe(
          function(){ return eth.getTransactionReceipt(txh); },
          function(e){ receiptErr.push([i, String(txh), e]); }
        );
        if (!r) receiptErr.push([i, String(txh), "null receipt"]);
      }
    }

    // --- committeeMembers probe (sampled) ---
    if (CHECK.committeeProbe && COMMITTEE_EVERY > 0) {
      if (i >= COMMITTEE_FROM && (i % COMMITTEE_EVERY === 0)) {
        var members = safe(
          function(){ return eth.committeeMembers(i); },
          function(e){ committeeErr.push([i, e]); }
        );
       
        if (members && members.length === 0) committeeEmpty.push(i);
      }
    }

    // --- storageRoot probe (optional) ---
    if (CHECK.storageRootProbe) {
      safe(
        function(){ return eth.storageRoot(i); },
        function(e){ storageRootErr.push([i, e]); }
      );
    }

    logProgress(i);
  }

  // ========= summary =========
  console.log("=== MEGA VERIFY DONE ===", now());

  function printList(tag, list, limit) {
    limit = (limit === undefined) ? 50 : limit;
    console.log(tag + "_COUNT", list.length);
    if (list.length === 0) return;
    var head = list.slice(0, limit);
    console.log(tag + "_HEAD(" + limit + ")", JSON.stringify(head));
    if (list.length > limit) console.log(tag + "_NOTE", "truncated; increase limit in printList()");
  }

  printList("MISSING_BLOCK", missBlock, 200);
  printList("MISSING_HEADER", missHeader, 200);
  printList("KEYBLOCK_MISSING", keyBlockMiss, 50);
  printList("COMMITTEE_ERR", committeeErr, 50);
  printList("COMMITTEE_EMPTY", committeeEmpty, 200);
  printList("RECEIPT_ERR", receiptErr, 50);
  printList("TXCOUNT_ERR", txCountErr, 50);
  printList("STORAGEROOT_ERR", storageRootErr, 50);
  printList("OTHER_ERR", err, 50);

  // quick verdict
  console.log("VERDICT",
    (missBlock.length || missHeader.length || keyBlockMiss.length || committeeErr.length || receiptErr.length || txCountErr.length || storageRootErr.length || err.length)
      ? "ISSUES_FOUND"
      : "OK"
  );
})();

~~~
