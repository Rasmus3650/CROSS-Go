package test_suite

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/pkg/vanilla"
	"bytes"
	"crypto/rand"
	math "math/rand"
	"testing"
)

func TestMerkle(t *testing.T) {
	// Run through all configs 10 times, and make sure nothing returns an error
	configs := common.Configs()
	for _, config := range configs {
		instance, err := vanilla.NewCROSS(config)
		if err != nil {
			t.Errorf("Error: %s", err)
		}
		for xyz := 0; xyz < 100; xyz++ {
			commitments := make([][]byte, instance.ProtocolData.T)
			for i := 0; i < instance.ProtocolData.T; i++ {
				commitments[i] = make([]byte, (2*instance.ProtocolData.Lambda)/8)
				rand.Read(commitments[i])
			}
			root, err := instance.TreeRoot(commitments)
			if err != nil {
				t.Errorf("Error: %s", err)
			}
			chall_2 := make([]bool, instance.ProtocolData.T)
			chall_2[0] = true
			chall_2[1] = true
			chall_2[2] = true
			chall_2[3] = true
			chall_2[4] = false
			chall_2[5] = true
			chall_2[6] = false
			chall_2[7] = false
			for i := 8; i < instance.ProtocolData.T; i++ {
				chall_2[i] = math.Intn(2) == 0
			}
			proof, err := instance.TreeProof(commitments, chall_2)
			if err != nil {
				t.Errorf("Error: %s", err)
			}
			cmt_0 := make([][]byte, len(chall_2))
			for i := 0; i < len(chall_2); i++ {
				if !chall_2[i] {
					cmt_0[i] = commitments[i]
				}
			}
			root_prime, err := instance.RecomputeRoot(cmt_0, proof, chall_2)
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
