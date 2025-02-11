package seed_test

import (
	"PQC-Master-Thesis/internal/common"
	seedtree "PQC-Master-Thesis/internal/seed"
	"bytes"
	"crypto/rand"
	"fmt"
	math "math/rand"
	"testing"
)

func TestSeedLeaves(t *testing.T) {
	tree_params, err := seedtree.GetTreeParams("small", "RSDP", 1)
	if err != nil {
		t.Errorf("Error: %s", err)

	}
	proto_params, err := common.GetProtocolConfig("small", "RSDP", 1)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	//seed := []byte{43, 148, 59, 167, 93, 54, 150, 240, 118, 242, 17, 189, 110, 37, 177, 233, 145, 37, 208, 231, 119, 140, 95, 52, 196, 36, 184, 227, 28, 139, 44, 186}
	//salt := []byte{192, 59, 162, 242, 246, 191, 105, 42, 253, 225, 222, 208, 146, 232, 184, 5, 90, 116, 41, 195, 36, 35, 47, 25, 244, 170, 177, 189, 66, 249, 112, 96, 135, 191, 180, 177, 199, 173, 163, 226, 75, 145, 26, 12, 108, 67, 188, 62, 39, 64, 255, 39, 231, 167, 214, 232, 48, 191, 134, 57, 35, 34, 100, 203}
	seed := make([]byte, 32)
	salt := make([]byte, 64)
	rand.Read(seed)
	rand.Read(salt)
	_, err = seedtree.SeedLeaves("small", seed, salt, proto_params, tree_params)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
}

func TestFastSeedLeaves(t *testing.T) {
	tree_params, err := seedtree.GetTreeParams("fast", "RSDP", 1)
	if err != nil {
		t.Errorf("Error: %s", err)

	}
	proto_params, err := common.GetProtocolConfig("fast", "RSDP", 1)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	seed := make([]byte, 32)
	salt := make([]byte, 64)
	rand.Read(seed)
	rand.Read(salt)
	leaves, err := seedtree.SeedLeaves("fast", seed, salt, proto_params, tree_params)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	fmt.Println("leaves: ", leaves)
}

func TestIntegration(t *testing.T) {
	// Run through all configs 10 times, and make sure nothing returns an error
	// Fix LeftChild()
	schemeType := "fast"
	variant := "RSDP"
	securityLevel := 1
	tree_params, err := seedtree.GetTreeParams(schemeType, variant, securityLevel)
	if err != nil {
		t.Errorf("Error: %s", err)

	}
	proto_params, err := common.GetProtocolConfig(schemeType, variant, securityLevel)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	seed := make([]byte, 32)
	salt := make([]byte, 64)
	rand.Read(seed)
	rand.Read(salt)
	leaves, err := seedtree.SeedLeaves(schemeType, seed, salt, proto_params, tree_params)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	chall_2 := make([]bool, proto_params.T)
	chall_2[0] = true
	chall_2[1] = true
	chall_2[2] = true
	chall_2[3] = true
	chall_2[4] = false
	chall_2[5] = true
	chall_2[6] = false
	chall_2[7] = false
	for i := 8; i < proto_params.T; i++ {
		chall_2[i] = math.Intn(2) == 0
	}
	path, err := seedtree.SeedPath(schemeType, seed, salt, chall_2, proto_params, tree_params)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	leaves_prime, err := seedtree.RebuildLeaves(schemeType, path, salt, chall_2, proto_params, tree_params)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	ctr := 0
	for i := 0; i < len(chall_2)-1; i++ {
		if chall_2[i] {
			fmt.Println(bytes.Equal(leaves[i], leaves_prime[ctr]))
			ctr++
		}
	}

}
