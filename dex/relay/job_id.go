package relay

import (
	"encoding/binary"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/protocol"
)

// BusinessID excludes relay identity, transaction nonce and proof encoding.
func BusinessID(domain protocol.Domain, custody common.Address, lane Lane, key protocol.Hash) protocol.Hash {
	epoch := domain.EpochKey()
	var b [85]byte
	copy(b[:32], epoch[:])
	copy(b[32:52], custody[:])
	b[52] = byte(lane)
	copy(b[53:], key[:])
	return protocol.Digest("common-dex/relay-job/v1", b[:])
}

func inboxKey(start, end uint64, root protocol.Hash) protocol.Hash {
	var b [48]byte
	binary.BigEndian.PutUint64(b[:8], start)
	binary.BigEndian.PutUint64(b[8:16], end)
	copy(b[16:], root[:])
	return protocol.Digest("common-dex/relay-inbox-key/v1", b[:])
}
