
// You should have received a copy of the GNU Lesser General Public License
// along with the cypherBFT library. If not, see <http://www.gnu.org/licenses/>.

package colossusX

import (
	crand "crypto/rand"
	"math"
	"math/big"
	"math/rand"
	"runtime"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
)

// SealCandidate implements pow.Engine, attempting to find a nonce that satisfies
// the candidate's difficulty requirements.
func (colossusX *colossusX) SealCandidate(candidate *types.Candidate, stop <-chan struct{}) (*types.Candidate, error) {
	log.Info("pow work,finding...", "PowMode", colossusX.config.PowMode)
	// If we're running a fake PoW, simply return a 0 nonce immediately
	if colossusX.config.PowMode == ModeFake || colossusX.config.PowMode == ModeFullFake {
		candidate.KeyCandidate.Nonce, candidate.KeyCandidate.MixDigest = types.BlockNonce{}, common.Hash{}
		return candidate, nil
	}
	// Create a runner and the multiple search threads it directs
	abort := make(chan struct{})
	found := make(chan *types.Candidate)

	colossusX.lock.Lock()
	threads := colossusX.threads
	if colossusX.rand == nil {
		seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			colossusX.lock.Unlock()
			return nil, err
		}
		colossusX.rand = rand.New(rand.NewSource(seed.Int64()))
	}

	colossusX.lock.Unlock()
	if threads == 0 {
		threads = runtime.NumCPU()
	}
	if threads < 0 {
		threads = 1
	}
	var pend sync.WaitGroup
	for i := 0; i < threads; i++ {
		pend.Add(1)
		go func(id int, nonce uint64) {
			defer pend.Done()
			colossusX.mineCandidate(candidate, id, nonce, abort, found)
		}(i, uint64(colossusX.rand.Int63()))
	}
	// Wait until sealing is terminated or a nonce is found
	var result *types.Candidate
	select {
	case <-stop:
		// Outside abort, stop all miner threads
		close(abort)
	case result = <-found:

		// One of the threads found a block, abort all others
		close(abort)
	case <-colossusX.update:
		// Thread count was changed on user request, restart
		close(abort)
		pend.Wait()
		log.Info("SealCandidate.update")
		return colossusX.SealCandidate(candidate, stop)
	}
	// Wait for all miners to terminate and return the block
	pend.Wait()
	return result, nil
}

// mineCandidate is the actual proof-of-work miner that searches for a nonce starting from
// seed that results in correct final block difficulty.
func (colossusX *colossusX) mineCandidate(candidate *types.Candidate, id int, seed uint64, abort chan struct{}, found chan *types.Candidate) {
	// Extract some data from the header
	var (
		hash   = candidate.HashNoNonce().Bytes()
		target = new(big.Int).Div(maxUint256, candidate.KeyCandidate.Difficulty)
		number = candidate.KeyCandidate.Number.Uint64()
	)
	dataset, err := colossusX.dataset(number)
	if err != nil {
		log.Error("colossusX mining aborted: dataset initialization failed", "epoch", number/epochLength, "err", err)
		return
	}
	// Start generating random nonces until we abort or find a good one
	var (
		attempts = int64(0)
		nonce    = seed
	)
	log.Debug("mineCandidate", "seed", seed)
	logger := log.New("miner", id)
search:
	for {
		select {
		case <-abort:
			// Mining terminated, update stats and abort
			logger.Trace("colossusX nonce search aborted", "attempts", nonce-seed)
			colossusX.hashrate.Mark(attempts)
			break search

		default:
			// We don't have to update hash rate on every nonce, so update after after 2^X nonces
			attempts++
			if (attempts % (1 << 15)) == 0 {
				colossusX.hashrate.Mark(attempts)
				attempts = 0
			}
			// Compute the PoW value of this nonce
			digest, result := colossusXfull(dataset.dataset, hash, nonce)

			if new(big.Int).SetBytes(result).Cmp(target) <= 0 {
				foundedTime := time.Now().Unix()
				foundedElapseTime := time.Duration(uint64(foundedTime)-candidate.KeyCandidate.Time) * time.Second
				// Correct nonce found, create a new header with it
				candidate.KeyCandidate.Nonce = types.EncodeNonce(nonce)
				candidate.KeyCandidate.MixDigest = common.BytesToHash(digest)
				log.Info("mineCandidate", "foundedElapseTime", foundedElapseTime, "nonce", candidate.KeyCandidate.Nonce, "digest", candidate.KeyCandidate.MixDigest)

				// Seal and return a block (if still needed)
				select {
				case found <- candidate:
					log.Info("colossusX nonce found and reported", "attempts", nonce-seed, "nonce", nonce)
				case <-abort:
					logger.Trace("colossusX nonce found but discarded", "attempts", nonce-seed, "nonce", nonce)
				}
				break search
			}
			nonce++
		}
	}
	// Datasets are unmapped in a finalizer. Ensure that the dataset stays live
	// during sealing so it's not unmapped while being read.
	runtime.KeepAlive(dataset)
}
