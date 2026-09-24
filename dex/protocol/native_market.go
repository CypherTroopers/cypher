package protocol

import "errors"

// NativeMarketSeed binds the versioned native fixture to its configurable oracle.
func NativeMarketSeed(oracle [20]byte) (Hash, error) {
	if oracle == ([20]byte{}) {
		return Hash{}, errors.New("native oracle must be nonzero")
	}
	return Digest("common-dex/native-market-config/v2", oracle[:]), nil
}
