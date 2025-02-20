package merkle_test

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/internal/trees/merkle"
	"bytes"
	"crypto/rand"
	math "math/rand"
	"testing"
)

func TestMerkle(t *testing.T) {
	// Run through all configs 10 times, and make sure nothing returns an error
	types := []string{"small", "balanced", "fast"}
	variants := []string{"RSDP", "RSDP-G"}
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
					commitments := make([][]byte, proto_params.T)
					for i := 0; i < proto_params.T; i++ {
						commitments[i] = make([]byte, (2*proto_params.Lambda)/8)
						rand.Read(commitments[i])
					}
					root, err := merkle.TreeRoot(schemeType, commitments, proto_params, tree_params)
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
					proof, err := merkle.TreeProof(schemeType, commitments, chall_2, proto_params, tree_params)
					if err != nil {
						t.Errorf("Error: %s", err)
					}
					cmt_0 := make([][]byte, len(chall_2))
					for i := 0; i < len(chall_2); i++ {
						if !chall_2[i] {
							cmt_0[i] = commitments[i]
						}
					}
					root_prime, err := merkle.RecomputeRoot(schemeType, cmt_0, proof, chall_2, proto_params, tree_params)
					if err != nil {
						t.Errorf("Error: %s", err)
					}
					if len(root) != len(root_prime) {
						t.Errorf("Error: Length of roots do not match")
					}
					if !bytes.Equal(root, root_prime) {
						t.Errorf("Error: Roots do not match")
					}
				}
			}
		}
	}

}
