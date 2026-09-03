package colossusX

import "testing"

func TestDatasetGrowthSchedule(t *testing.T) {
	const (
		wantEpochLength       = uint64(52_560)
		wantDatasetGrowthSize = uint64(8 << 30)
	)
	if epochLength != wantEpochLength {
		t.Fatalf("epoch length = %d key blocks, want %d", epochLength, wantEpochLength)
	}
	if datasetGrowthBytes != wantDatasetGrowthSize {
		t.Fatalf("dataset growth = %d bytes, want %d", datasetGrowthBytes, wantDatasetGrowthSize)
	}

	tests := []struct {
		block uint64
		want  uint64
	}{
		{block: 0, want: 34_359_728_384},
		{block: 52_559, want: 34_359_728_384},
		{block: 52_560, want: 42_949_659_392},
		{block: 105_119, want: 42_949_659_392},
		{block: 105_120, want: 51_539_598_592},
	}
	for _, test := range tests {
		if got := datasetSize(test.block); got != test.want {
			t.Errorf("dataset size at key block %d = %d bytes, want %d", test.block, got, test.want)
		}
	}
}
