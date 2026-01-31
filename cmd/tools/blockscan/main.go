// Copyright 2024 The Cypherium Authors
// This file is part of the cypherium library.
//
// The cypherium library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The cypherium library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the cypherium library. If not, see <http://www.gnu.org/licenses/>.

// blockscan is a tool to scan chaindata for missing blocks offline.
// It checks both the leveldb (.ldb files) and ancient directory for block continuity.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/ethdb/leveldb"
	"github.com/cypherium/cypher/log"
)

var (
	chaindataFlag = flag.String("chaindata", "", "Path to the chaindata directory (required)")
	ancientFlag   = flag.String("ancient", "", "Path to the ancient directory (default: <chaindata>/ancient)")
	startFlag     = flag.Uint64("start", 0, "Start block number to scan from")
	endFlag       = flag.Uint64("end", 0, "End block number to scan to (0 means scan to the highest block)")
	verboseFlag   = flag.Bool("verbose", false, "Enable verbose logging")
)

func main() {
	flag.Parse()

	// Setup logging
	if *verboseFlag {
		log.Root().SetHandler(log.LvlFilterHandler(log.LvlDebug, log.StreamHandler(os.Stderr, log.TerminalFormat(true))))
	} else {
		log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, log.StreamHandler(os.Stderr, log.TerminalFormat(true))))
	}

	// Validate required flags
	if *chaindataFlag == "" {
		fmt.Fprintf(os.Stderr, "Error: --chaindata flag is required\n")
		flag.Usage()
		os.Exit(1)
	}

	// Check if chaindata directory exists
	if _, err := os.Stat(*chaindataFlag); os.IsNotExist(err) {
		log.Crit("Chaindata directory does not exist", "path", *chaindataFlag)
	}

	// Set ancient directory if not specified
	ancient := *ancientFlag
	if ancient == "" {
		ancient = filepath.Join(*chaindataFlag, "ancient")
	}

	log.Info("Starting block scan", "chaindata", *chaindataFlag, "ancient", ancient)

	// Open the database
	db, err := openDatabase(*chaindataFlag, ancient)
	if err != nil {
		log.Crit("Failed to open database", "err", err)
	}
	defer db.Close()

	// Run the scan
	if err := scanBlocks(db, *startFlag, *endFlag); err != nil {
		log.Crit("Block scan failed", "err", err)
	}

	log.Info("Block scan completed successfully")
}

// openDatabase opens the chaindata database with ancient support
func openDatabase(chaindata, ancient string) (ethdb.Database, error) {
	// Open the leveldb database
	kvdb, err := leveldb.New(chaindata, 128, 256, "")
	if err != nil {
		return nil, fmt.Errorf("failed to open leveldb: %v", err)
	}

	// Check if ancient directory exists
	if _, err := os.Stat(ancient); os.IsNotExist(err) {
		log.Warn("Ancient directory does not exist, using leveldb only", "path", ancient)
		return rawdb.NewDatabase(kvdb), nil
	}

	// Open with ancient support
	db, err := rawdb.NewDatabaseWithFreezer(kvdb, ancient, "")
	if err != nil {
		kvdb.Close()
		return nil, fmt.Errorf("failed to open database with freezer: %v", err)
	}

	return db, nil
}

// scanBlocks scans the database for missing blocks
func scanBlocks(db ethdb.Database, start, end uint64) error {
	log.Info("Scanning blocks for missing entries")

	// Get the number of ancient blocks
	ancientBlocks, err := db.Ancients()
	if err != nil {
		log.Warn("Failed to get ancient block count", "err", err)
		ancientBlocks = 0
	}
	log.Info("Ancient blocks", "count", ancientBlocks)

	// Get the head block hash to determine the highest block
	headHash := rawdb.ReadHeadBlockHash(db)
	if headHash.Hex() == "0x0000000000000000000000000000000000000000000000000000000000000000" {
		return fmt.Errorf("no head block found in database")
	}

	headNumber := rawdb.ReadHeaderNumber(db, headHash)
	if headNumber == nil {
		return fmt.Errorf("failed to get head block number")
	}

	log.Info("Head block", "number", *headNumber, "hash", headHash.Hex())

	// Determine scan range
	scanStart := start
	scanEnd := end
	if scanEnd == 0 || scanEnd > *headNumber {
		scanEnd = *headNumber
	}

	if scanStart > scanEnd {
		return fmt.Errorf("invalid scan range: start (%d) > end (%d)", scanStart, scanEnd)
	}

	log.Info("Scanning range", "start", scanStart, "end", scanEnd)

	// Track missing blocks
	var missingBlocks []uint64
	var missingHeaders []uint64
	var missingBodies []uint64

	// Scan blocks
	for blockNum := scanStart; blockNum <= scanEnd; blockNum++ {
		// Get canonical hash for this block number
		hash := rawdb.ReadCanonicalHash(db, blockNum)
		if hash.Hex() == "0x0000000000000000000000000000000000000000000000000000000000000000" {
			log.Warn("Missing canonical hash", "block", blockNum)
			missingBlocks = append(missingBlocks, blockNum)
			continue
		}

		// Check if header exists
		header := rawdb.ReadHeader(db, hash, blockNum)
		if header == nil {
			log.Warn("Missing header", "block", blockNum, "hash", hash.Hex())
			missingHeaders = append(missingHeaders, blockNum)
			continue
		}

		// Check if body exists
		body := rawdb.ReadBody(db, hash, blockNum)
		if body == nil {
			log.Warn("Missing body", "block", blockNum, "hash", hash.Hex())
			missingBodies = append(missingBodies, blockNum)
			continue
		}

		// Log progress periodically
		if blockNum%10000 == 0 && blockNum > 0 {
			log.Info("Scan progress", "block", blockNum, "progress", fmt.Sprintf("%.2f%%", float64(blockNum-scanStart)/float64(scanEnd-scanStart)*100))
		}
	}

	// Print summary
	fmt.Println("\n=== Block Scan Summary ===")
	fmt.Printf("Scanned range: %d - %d (%d blocks)\n", scanStart, scanEnd, scanEnd-scanStart+1)
	fmt.Printf("Ancient blocks: %d\n", ancientBlocks)
	fmt.Printf("Head block: %d\n", *headNumber)
	fmt.Println()

	if len(missingBlocks) > 0 {
		fmt.Printf("Missing blocks (no canonical hash): %d\n", len(missingBlocks))
		if len(missingBlocks) <= 100 {
			fmt.Printf("Missing block numbers: %v\n", missingBlocks)
		} else {
			fmt.Printf("First 100 missing blocks: %v\n", missingBlocks[:100])
			fmt.Printf("... and %d more\n", len(missingBlocks)-100)
		}
		fmt.Println()
	}

	if len(missingHeaders) > 0 {
		fmt.Printf("Missing headers: %d\n", len(missingHeaders))
		if len(missingHeaders) <= 100 {
			fmt.Printf("Missing header numbers: %v\n", missingHeaders)
		} else {
			fmt.Printf("First 100 missing headers: %v\n", missingHeaders[:100])
			fmt.Printf("... and %d more\n", len(missingHeaders)-100)
		}
		fmt.Println()
	}

	if len(missingBodies) > 0 {
		fmt.Printf("Missing bodies: %d\n", len(missingBodies))
		if len(missingBodies) <= 100 {
			fmt.Printf("Missing body numbers: %v\n", missingBodies)
		} else {
			fmt.Printf("First 100 missing bodies: %v\n", missingBodies[:100])
			fmt.Printf("... and %d more\n", len(missingBodies)-100)
		}
		fmt.Println()
	}

	if len(missingBlocks) == 0 && len(missingHeaders) == 0 && len(missingBodies) == 0 {
		fmt.Println("✓ No missing blocks found in the scanned range!")
	} else {
		fmt.Printf("✗ Found %d issues total\n", len(missingBlocks)+len(missingHeaders)+len(missingBodies))
	}

	return nil
}
