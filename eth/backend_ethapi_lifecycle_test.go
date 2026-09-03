package eth

import (
	"reflect"
	"testing"
)

func TestTransactionIngressLifecycleDrainsRPCBeforeTransport(t *testing.T) {
	var order []string
	lifecycle := &transactionIngressLifecycle{
		stopAPI: func() { order = append(order, "rpc") },
		stop:    func() { order = append(order, "transport") },
	}
	if err := lifecycle.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Stop(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"rpc", "transport"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("transaction ingress shutdown order = %v, want %v", order, want)
	}
}
