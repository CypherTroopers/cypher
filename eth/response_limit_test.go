package eth

import "testing"

func TestResponseItemFitsNearNativeFrameLimit(t *testing.T) {
	if !responseItemFits(0, 0, softResponseLimit) {
		t.Fatal("one maximum-size response item was rejected")
	}
	if responseItemFits(softResponseLimit-1, 1, softResponseLimit-1) {
		t.Fatal("two near-limit response items were accepted")
	}
	if !responseItemFits(softResponseLimit/2, 1, softResponseLimit/2) {
		t.Fatal("an exactly full multi-item response was rejected")
	}
	if responseItemFits(0, 0, softResponseLimit+1) {
		t.Fatal("an individually oversized response item was accepted")
	}
}
