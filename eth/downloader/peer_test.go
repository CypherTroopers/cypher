// Copyright 2020 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package downloader

import (
	"sort"
	"sync/atomic"
	"testing"
)

func TestPeerThroughputSorting(t *testing.T) {
	a := &peerConnection{
		id:               "a",
		headerThroughput: 1.25,
	}
	b := &peerConnection{
		id:               "b",
		headerThroughput: 1.21,
	}
	c := &peerConnection{
		id:               "c",
		headerThroughput: 1.23,
	}

	peers := []*peerConnection{a, b, c}
	tps := []float64{a.headerThroughput,
		b.headerThroughput, c.headerThroughput}
	sortPeers := &peerThroughputSort{peers, tps}
	sort.Sort(sortPeers)
	if got, exp := sortPeers.p[0].id, "a"; got != exp {
		t.Errorf("sort fail, got %v exp %v", got, exp)
	}
	if got, exp := sortPeers.p[1].id, "c"; got != exp {
		t.Errorf("sort fail, got %v exp %v", got, exp)
	}
	if got, exp := sortPeers.p[2].id, "b"; got != exp {
		t.Errorf("sort fail, got %v exp %v", got, exp)
	}

}

func TestIdlePeersAcceptNegotiatedProtocolUpgrades(t *testing.T) {
	peers := newPeerSet()
	for _, peer := range []*peerConnection{
		{id: "eth62", version: 62},
		{id: "eth63", version: 63},
		{id: "eth65", version: 65},
		{id: "eth66", version: 66},
		{id: "eth67", version: 67},
		{id: "busy66", version: 66},
	} {
		peers.peers[peer.id] = peer
	}
	busy := peers.peers["busy66"]
	atomic.StoreInt32(&busy.headerIdle, 1)
	atomic.StoreInt32(&busy.blockIdle, 1)
	atomic.StoreInt32(&busy.receiptIdle, 1)
	atomic.StoreInt32(&busy.stateIdle, 1)

	tests := []struct {
		name string
		idle func() ([]*peerConnection, int)
	}{
		{name: "headers", idle: peers.HeaderIdlePeers},
		{name: "bodies", idle: peers.BodyIdlePeers},
		{name: "receipts", idle: peers.ReceiptIdlePeers},
		{name: "state", idle: peers.NodeDataIdlePeers},
	}
	wantIDs := []string{"eth63", "eth65", "eth66", "eth67"}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			idle, total := test.idle()
			if total != 5 {
				t.Fatalf("eligible peer count mismatch: have %d, want 5", total)
			}
			gotIDs := make([]string, len(idle))
			for i, peer := range idle {
				gotIDs[i] = peer.id
			}
			sort.Strings(gotIDs)
			if len(gotIDs) != len(wantIDs) {
				t.Fatalf("idle peer count mismatch: have %v, want %v", gotIDs, wantIDs)
			}
			for i := range wantIDs {
				if gotIDs[i] != wantIDs[i] {
					t.Fatalf("idle peers mismatch: have %v, want %v", gotIDs, wantIDs)
				}
			}
		})
	}
}
