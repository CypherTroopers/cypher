package main

import (
        "flag"
        "fmt"
        "log"
        "path/filepath"

        "github.com/cypherium/cypher/common"
        "github.com/cypherium/cypher/core/rawdb"
        "github.com/cypherium/cypher/ethdb"
        "github.com/cypherium/cypher/params"
)

func openDB(datadir string) (ethdb.Database, error) {
        chaindata := filepath.Join(datadir, "cypher", "chaindata")
        freezer := filepath.Join(chaindata, "ancient")
        // namespace）
        return rawdb.NewLevelDBDatabaseWithFreezer(chaindata, 512, 512, freezer, "")
}

func main() {
        src := flag.String("src", "./data2", "source datadir")
        dst := flag.String("dst", "./data3", "destination datadir")
        start := flag.Uint64("start", 93958, "start block (inclusive)")
        end := flag.Uint64("end", 104001, "end block (inclusive)")
        flag.Parse()

        srcDB, err := openDB(*src)
        if err != nil {
                log.Fatalf("open src db: %v", err)
        }
        defer srcDB.Close()

        dstDB, err := openDB(*dst)
        if err != nil {
                log.Fatalf("open dst db: %v", err)
        }
        defer dstDB.Close()

        genesisHash := rawdb.ReadCanonicalHash(dstDB, 0)
        cfg := rawdb.ReadChainConfig(dstDB, genesisHash)
        if cfg == nil {
                cfg = params.MainnetChainConfig
                log.Printf("WARN: chain config not found in dst; fallback to params.MainnetChainConfig")
        }

        var copied, skipped uint64

        for n := *start; n <= *end; n++ {
                h := rawdb.ReadCanonicalHash(srcDB, n)
                if (h == common.Hash{}) {
                        log.Printf("MISS src canonical hash: %d", n)
                        skipped++
                        continue
                }

                header := rawdb.ReadHeader(srcDB, h, n)
                body := rawdb.ReadBody(srcDB, h, n)
                if header == nil || body == nil {
                        log.Printf("MISS src header/body: %d %s", n, h.Hex())
                        skipped++
                        continue
                }

                td := rawdb.ReadTd(srcDB, h, n)
                receipts := rawdb.ReadReceipts(srcDB, h, n, cfg)

                // write to dst
                rawdb.WriteCanonicalHash(dstDB, h, n)
                rawdb.WriteHeader(dstDB, header)
                rawdb.WriteBody(dstDB, h, n, body)
                if td != nil {
                        rawdb.WriteTd(dstDB, h, n, td)
                }
                if receipts != nil {
                        rawdb.WriteReceipts(dstDB, h, n, receipts)
                }

                if n%1000 == 0 {
                        log.Printf("COPIED %d", n)
                }
                copied++
        }

        fmt.Printf("DONE copied=%d skipped=%d\n", copied, skipped)
}
