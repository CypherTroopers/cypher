package parallel

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/common"
)

func testResource(value byte) Resource {
	return Resource{Kind: ResourceAccount, Address: common.Address{value}}
}

func generousLimits() Limits {
	return Limits{
		Transactions:        100,
		AccessesPerTx:       10,
		AccessesPerBlock:    100,
		ComputePerTx:        100,
		ComputePerBlock:     1_000,
		CriticalPathCompute: 1_000,
		DependencyDepth:     100,
	}
}

func TestBuildDeterministicReadWriteWaves(t *testing.T) {
	a, b := testResource(1), testResource(2)
	txs := []Transaction{
		{Accesses: []Access{{Resource: a, Mode: AccessRead}}, Compute: 2},
		{Accesses: []Access{{Resource: a, Mode: AccessRead}}, Compute: 3},
		{Accesses: []Access{{Resource: b, Mode: AccessWrite}}, Compute: 5},
		{Accesses: []Access{{Resource: a, Mode: AccessWrite}}, Compute: 7},
		{Accesses: []Access{{Resource: a, Mode: AccessRead}, {Resource: b, Mode: AccessRead}}, Compute: 11},
	}
	want := [][]int{{0, 1, 2}, {3}, {4}}
	for run := 0; run < 100; run++ {
		schedule, err := Build(txs, generousLimits())
		if err != nil {
			t.Fatalf("Build failed: %v", err)
		}
		if !reflect.DeepEqual(schedule.Waves, want) {
			t.Fatalf("run %d waves = %v, want %v", run, schedule.Waves, want)
		}
		if schedule.TotalAccesses != 6 || schedule.TotalCompute != 28 || schedule.CriticalPathCompute != 21 {
			t.Fatalf("unexpected totals: %+v", schedule)
		}
	}
}

func TestBuildRejectsHotKeyCriticalPath(t *testing.T) {
	limits := generousLimits()
	limits.CriticalPathCompute = 15
	hot := testResource(1)
	_, err := Build([]Transaction{
		{Accesses: []Access{{Resource: hot, Mode: AccessWrite}}, Compute: 8},
		{Accesses: []Access{{Resource: hot, Mode: AccessWrite}}, Compute: 8},
	}, limits)
	if !errors.Is(err, ErrWorkLimit) {
		t.Fatalf("hot critical path error = %v, want ErrWorkLimit", err)
	}
}

func TestBuildAllowsIndependentWorkBeyondCriticalPath(t *testing.T) {
	limits := generousLimits()
	limits.CriticalPathCompute = 10
	txs := make([]Transaction, 8)
	for i := range txs {
		txs[i] = Transaction{Accesses: []Access{{Resource: testResource(byte(i + 1)), Mode: AccessWrite}}, Compute: 10}
	}
	schedule, err := Build(txs, limits)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if len(schedule.Waves) != 1 || len(schedule.Waves[0]) != len(txs) {
		t.Fatalf("independent schedule = %v", schedule.Waves)
	}
}

func TestBuildRejectsDuplicateAndMalformedAccesses(t *testing.T) {
	resource := testResource(1)
	tests := []Transaction{
		{Accesses: []Access{{Resource: resource, Mode: AccessRead}, {Resource: resource, Mode: AccessWrite}}, Compute: 1},
		{Accesses: []Access{{Resource: Resource{Kind: ResourceAccount, Address: common.Address{1}, Slot: common.Hash{1}}, Mode: AccessRead}}, Compute: 1},
		{Accesses: []Access{{Resource: resource, Mode: 99}}, Compute: 1},
	}
	for index, tx := range tests {
		if _, err := Build([]Transaction{tx}, generousLimits()); err == nil {
			t.Fatalf("case %d accepted malformed access", index)
		}
	}
}

func TestBuildRejectsEveryWorkDimension(t *testing.T) {
	resource := testResource(1)
	tx := Transaction{Accesses: []Access{{Resource: resource, Mode: AccessRead}}, Compute: 2}
	tests := []Limits{
		{Transactions: 0, AccessesPerTx: 1, AccessesPerBlock: 1, ComputePerTx: 2, ComputePerBlock: 2, CriticalPathCompute: 2, DependencyDepth: 1},
		{Transactions: 1, AccessesPerTx: 0, AccessesPerBlock: 1, ComputePerTx: 2, ComputePerBlock: 2, CriticalPathCompute: 2, DependencyDepth: 1},
		{Transactions: 1, AccessesPerTx: 1, AccessesPerBlock: 0, ComputePerTx: 2, ComputePerBlock: 2, CriticalPathCompute: 2, DependencyDepth: 1},
		{Transactions: 1, AccessesPerTx: 1, AccessesPerBlock: 1, ComputePerTx: 1, ComputePerBlock: 2, CriticalPathCompute: 2, DependencyDepth: 1},
		{Transactions: 1, AccessesPerTx: 1, AccessesPerBlock: 1, ComputePerTx: 2, ComputePerBlock: 1, CriticalPathCompute: 2, DependencyDepth: 1},
		{Transactions: 1, AccessesPerTx: 1, AccessesPerBlock: 1, ComputePerTx: 2, ComputePerBlock: 2, CriticalPathCompute: 1, DependencyDepth: 1},
		{Transactions: 1, AccessesPerTx: 1, AccessesPerBlock: 1, ComputePerTx: 2, ComputePerBlock: 2, CriticalPathCompute: 2, DependencyDepth: 0},
	}
	for index, limits := range tests {
		if _, err := Build([]Transaction{tx}, limits); !errors.Is(err, ErrWorkLimit) {
			t.Fatalf("case %d error = %v, want ErrWorkLimit", index, err)
		}
	}
}

func TestBuildRejectsDependencyDepthEvenWhenComputeFits(t *testing.T) {
	limits := generousLimits()
	limits.DependencyDepth = 2
	hot := testResource(9)
	_, err := Build([]Transaction{
		{Accesses: []Access{{Resource: hot, Mode: AccessWrite}}, Compute: 1},
		{Accesses: []Access{{Resource: hot, Mode: AccessWrite}}, Compute: 1},
		{Accesses: []Access{{Resource: hot, Mode: AccessWrite}}, Compute: 1},
	}, limits)
	if !errors.Is(err, ErrWorkLimit) {
		t.Fatalf("dependency-depth error = %v, want ErrWorkLimit", err)
	}
}

func TestPlannerRejectionDoesNotMutateFrontiers(t *testing.T) {
	limits := generousLimits()
	limits.CriticalPathCompute = 10
	planner := NewPlanner(limits)
	hot := testResource(1)
	independent := testResource(2)
	if err := planner.TryAdd(Transaction{Accesses: []Access{{Resource: hot, Mode: AccessWrite}}, Compute: 8}); err != nil {
		t.Fatal(err)
	}
	if err := planner.TryAdd(Transaction{Accesses: []Access{{Resource: hot, Mode: AccessWrite}}, Compute: 8}); !errors.Is(err, ErrWorkLimit) {
		t.Fatalf("hot rejection = %v, want ErrWorkLimit", err)
	}
	if err := planner.TryAdd(Transaction{Accesses: []Access{{Resource: independent, Mode: AccessWrite}}, Compute: 2}); err != nil {
		t.Fatalf("independent transaction after rejection: %v", err)
	}
	schedule := planner.Schedule()
	want := [][]int{{0, 1}}
	if !reflect.DeepEqual(schedule.Waves, want) || schedule.TotalCompute != 10 || schedule.CriticalPathCompute != 8 {
		t.Fatalf("planner snapshot after rejection = %+v, want waves %v total 10 critical 8", schedule, want)
	}
}
