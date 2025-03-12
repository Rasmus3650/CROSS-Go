package test_suite

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/pkg/vanilla"
	"fmt"
	"testing"
)

func TestKeygen(t *testing.T) {
	seed := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	cross, err := vanilla.NewCROSS(common.RSDP_1_BALANCED)
	if err != nil {
		t.Fatalf("Error creating CROSS instance: %v", err)
	}
	keypair, err := cross.DummyKeyGen(seed)
	fmt.Println(keypair)
}
