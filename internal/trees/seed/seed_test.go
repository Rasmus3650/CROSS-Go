package seed_test

import (
	"PQC-Master-Thesis/internal/common"
	seedtree "PQC-Master-Thesis/internal/trees/seed"
	"bytes"
	"crypto/rand"
	"fmt"
	math "math/rand"
	"testing"
)

func TestSeedLeaves(t *testing.T) {
	tree_params, err := common.GetTreeParams("small", "RSDP", 1)
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
	_, err = seedtree.SeedLeaves(seed, salt, proto_params, tree_params)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
}

func TestFastSeedLeaves(t *testing.T) {
	tree_params, err := common.GetTreeParams("fast", "RSDP", 1)
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
	leaves, err := seedtree.SeedLeaves(seed, salt, proto_params, tree_params)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	fmt.Println("leaves: ", leaves)
}

func TestIntegration(t *testing.T) {
	// Run through all configs 10 times, and make sure nothing returns an error
	types := []string{"small", "balanced", "fast"}
	variants := []string{"RSDP-G", "RSDP"}
	securityLevels := []int{1, 3, 5}
	for xyz := 0; xyz < 100; xyz++ {
		for _, schemeType := range types {
			for _, variant := range variants {
				for _, securityLevel := range securityLevels {
					tree_params, err := common.GetTreeParams(schemeType, variant, securityLevel)
					//fmt.Println("tree_params: ", tree_params)
					//fmt.Println("schemeType: ", schemeType)
					//fmt.Println("variant: ", variant)
					//fmt.Println("securityLevel: ", securityLevel)
					if err != nil {
						t.Errorf("Error: %s", err)

					}
					proto_params, err := common.GetProtocolConfig(schemeType, variant, securityLevel)
					if err != nil {
						t.Errorf("Error: %s", err)
					}
					// TODO: Make seed and salt dependent on the security level
					seed := make([]byte, 32)
					salt := make([]byte, 64)
					rand.Read(seed)
					rand.Read(salt)
					leaves, err := seedtree.SeedLeaves(seed, salt, proto_params, tree_params)
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
					path, err := seedtree.SeedPath(seed, salt, chall_2, proto_params, tree_params)
					if err != nil {
						t.Errorf("Error: %s", err)
					}
					leaves_prime, err := seedtree.RebuildLeaves(path, salt, chall_2, proto_params, tree_params)
					if err != nil {
						t.Errorf("Error: %s", err)
					}
					ctr := 0
					for i := 0; i < len(chall_2)-1; i++ {
						if chall_2[i] {
							if !bytes.Equal(leaves[i], leaves_prime[ctr]) {
								t.Errorf("Error: Leaves do not match")
							}
							ctr++
						}
					}
				}
			}
		}
	}

}

func InSet(set [][]byte, element []byte) bool {
	for _, e := range set {
		if bytes.Equal(e, element) {
			return true
		}
	}
	return false
}

func TestInt(t *testing.T) {
	// Errors: Small-RSDP-3, Small-RSDP-G-5, Balanced-RSDP-G-5
	// Some weird probabilistic edge-case
	// Maybe offset should be accumulated?
	schemeType := "small"
	variant := "RSDP"
	securityLevel := 1
	for xyz := 0; xyz < 1; xyz++ {
		fmt.Println("Iteration: ", xyz)
		tree_params, err := common.GetTreeParams(schemeType, variant, securityLevel)
		/*fmt.Println("tree_params: ", tree_params)
		fmt.Println("schemeType: ", schemeType)
		fmt.Println("variant: ", variant)
		fmt.Println("securityLevel: ", securityLevel)*/
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
		leaves, err := seedtree.SeedLeaves(seed, salt, proto_params, tree_params)
		//fmt.Println("leaves: ", leaves[len(leaves)-1])
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
		chall_2[len(chall_2)-1] = true
		chall_2[len(chall_2)-2] = false
		path, err := seedtree.SeedPath(seed, salt, chall_2, proto_params, tree_params)
		if err != nil {
			t.Errorf("Error: %s", err)
		}
		// EVERYTHING WORKS UNTIL HERE
		leaves_prime, err := seedtree.RebuildLeaves(path, salt, chall_2, proto_params, tree_params)
		if err != nil {
			t.Errorf("Error: %s", err)
		}
		res := [][]byte{}
		for i := 0; i < len(chall_2); i++ {
			if chall_2[i] {
				res = append(res, leaves[i])
			}
		}
		//fmt.Println("Leaves: ", res)
		//fmt.Println("Leaves prime: ", leaves_prime)
		//fmt.Println("Rebuilt leaves: ", leaves_prime)
		//fmt.Println("Len of rebuilt leaves: ", len(leaves))
		//fmt.Println("---------------------------------------------------------")
		//fmt.Println("leaves: ", leaves)
		//fmt.Println("Len of leaves: ", len(leaves))
		for i := 0; i < len(leaves_prime); i++ {
			if !InSet(leaves, leaves_prime[i]) {
				fmt.Println("Error: Leaf ", i, " not in set")
			}
		}
	}
}
