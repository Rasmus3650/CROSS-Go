package test_suite

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/Rasmus3650/CROSS-Go/internal"
	"github.com/Rasmus3650/CROSS-Go/pkg/vanilla"
)

const (
	PATH_MERKLE_RSDP_1_FAST = "./data/merkle_rsdp_1_fast"
	PATH_MERKLE_RSDP_3_FAST = "./data/merkle_rsdp_3_fast"
	PATH_MERKLE_RSDP_5_FAST = "./data/merkle_rsdp_5_fast"

	PATH_MERKLE_RSDP_1_SMALL = "./data/merkle_rsdp_1_small"
	PATH_MERKLE_RSDP_3_SMALL = "./data/merkle_rsdp_3_small"
	PATH_MERKLE_RSDP_5_SMALL = "./data/merkle_rsdp_5_small"

	PATH_MERKLE_RSDP_1_BALANCED = "./data/merkle_rsdp_1_balanced"
	PATH_MERKLE_RSDP_3_BALANCED = "./data/merkle_rsdp_3_balanced"
	PATH_MERKLE_RSDP_5_BALANCED = "./data/merkle_rsdp_5_balanced"
)

type MERKLE_STRUCT struct {
	leaves  []byte
	root    []byte
	chall_2 []byte
	proof   []byte
}

func TestMerkle(t *testing.T) {
	// Run through all configs 10 times, and make sure nothing returns an error
	configs := internal.Configs()
	for _, config := range configs {
		instance, err := vanilla.NewCROSS(config)
		if err != nil {
			t.Errorf("Error: %s", err)
		}
		for xyz := 0; xyz < 100; xyz++ {
			commitments := make([][]byte, instance.GetProtocolData().T)
			for i := 0; i < instance.GetProtocolData().T; i++ {
				commitments[i] = make([]byte, (2*instance.GetProtocolData().Lambda)/8)
				rand.Read(commitments[i])
			}
			root := instance.TreeRoot(commitments)
			digest := make([]byte, 32)
			rand.Read(digest)
			chall_2 := instance.Expand_digest_to_fixed_weight(digest)
			proof := instance.TreeProof(commitments, chall_2)
			cmt_0 := make([][]byte, len(chall_2))
			for i := 0; i < len(chall_2); i++ {
				if !chall_2[i] {
					cmt_0[i] = commitments[i]
				}
			}
			root_prime, _ := instance.RecomputeRoot(cmt_0, proof, chall_2)
			if len(root) != len(root_prime) {
				t.Errorf("Error: Length of roots do not match")
			}
			if !bytes.Equal(root, root_prime) {
				t.Errorf("Error: Roots do not match")
			}
		}
	}
}

// Convert []byte to [][]byte based on T
func convertLeavesTo2DByte(T, lambda int, data []byte) [][]byte {
	result := make([][]byte, T)
	for i := 0; i < T; i++ {
		result[i] = data[i*2*(lambda/8) : (i+1)*2*(lambda/8)]
	}
	return result
}

func read(file string, t *testing.T) []byte {
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("Error reading file %s: %v", file, err)
	}
	return b
}

func base(base string, n int) string {
	return fmt.Sprintf("%s/%d", base, n)
}

func path(base, file string) string {
	return fmt.Sprintf("%s/%s", base, file)
}

func save(prefix string, tests []MERKLE_STRUCT) {
	file_path := func(i int, name string) string {
		return fmt.Sprintf("%s/%d/%s", prefix, i, name)
	}

	for i, test := range tests {
		path := fmt.Sprintf("%s/%d", prefix, i)
		os.MkdirAll(path, 0700)
		os.WriteFile(file_path(i, "leaves"), test.leaves, 0700)
		os.WriteFile(file_path(i, "root"), test.root, 0700)
		os.WriteFile(file_path(i, "chall_2"), test.chall_2, 0700)
		os.WriteFile(file_path(i, "proof"), test.proof, 0700)
	}
}

func load(prefix string, count int, t *testing.T) []MERKLE_STRUCT {

	test_vectors := make([]MERKLE_STRUCT, count)

	for i := range count {
		_base := base(prefix, i)

		test_vectors[i] = MERKLE_STRUCT{
			leaves:  read(path(_base, "leaves"), t),
			root:    read(path(_base, "root"), t),
			chall_2: read(path(_base, "chall_2"), t),
			proof:   read(path(_base, "proof"), t),
		}
	}
	return test_vectors
}

func run(cross vanilla.CROSSAllMethods, test_vectors []MERKLE_STRUCT, t *testing.T) {
	for _, test := range test_vectors {
		commitments := convertLeavesTo2DByte(cross.GetProtocolData().T, cross.GetProtocolData().Lambda, test.leaves)
		root := cross.TreeRoot(commitments)
		if !bytes.Equal(root, test.root) {
			t.Fatalf("Computed root does not match expected root")
		}
		chall_2 := make([]bool, len(test.chall_2))
		for i := 0; i < len(test.chall_2); i++ {
			if test.chall_2[i] == 1 {
				chall_2[i] = true
			} else {
				chall_2[i] = false
			}
		}
		proof := cross.TreeProof(commitments, chall_2)
		//Test proof was copied without trailing zeroes
		new_proof := make([]byte, len(internal.Flatten(proof)))
		copy(new_proof, test.proof)
		if !bytes.Equal(internal.Flatten(proof), new_proof) {
			t.Fatalf("Computed proof does not match expected proof")
		}
	}
}

func TestMerkleRSDPFast(t *testing.T) {
	test_vectors := []MERKLE_STRUCT{}

	cross, err := vanilla.NewCROSS(internal.RSDP_1_FAST)
	if err != nil {
		t.Fatalf("Error creating CROSS instance: %v", err)
	}

	test_vectors = load(PATH_MERKLE_RSDP_1_FAST, 3, t)

	run(cross, test_vectors, t)

	cross, err = vanilla.NewCROSS(internal.RSDP_3_FAST)
	if err != nil {
		t.Fatalf("Error creating CROSS instance: %v", err)
	}

	test_vectors = load(PATH_MERKLE_RSDP_3_FAST, 3, t)

	run(cross, test_vectors, t)

	cross, err = vanilla.NewCROSS(internal.RSDP_5_FAST)
	if err != nil {
		t.Fatalf("Error creating CROSS instance: %v", err)
	}

	test_vectors = load(PATH_MERKLE_RSDP_5_FAST, 3, t)

	run(cross, test_vectors, t)
}

func TestMerkleRSDPSmall(t *testing.T) {
	var test_vectors []MERKLE_STRUCT

	// Level 1
	cross, err := vanilla.NewCROSS(internal.RSDP_1_SMALL)
	if err != nil {
		t.Fatalf("Error creating CROSS instance: %v", err)
	}

	test_vectors = load(PATH_MERKLE_RSDP_1_SMALL, 3, t)

	run(cross, test_vectors, t)

	// Level 3
	cross, err = vanilla.NewCROSS(internal.RSDP_3_SMALL)
	if err != nil {
		t.Fatalf("Error creating CROSS instance: %v", err)
	}

	test_vectors = load(PATH_MERKLE_RSDP_3_SMALL, 3, t)

	run(cross, test_vectors, t)

	// Level 5
	cross, err = vanilla.NewCROSS(internal.RSDP_5_SMALL)
	if err != nil {
		t.Fatalf("Error creating CROSS instance: %v", err)
	}

	test_vectors = load(PATH_MERKLE_RSDP_5_SMALL, 3, t)

	run(cross, test_vectors, t)

}

func TestMerkleRSDPBalanced(t *testing.T) {
	var test_vectors []MERKLE_STRUCT

	// Level 1
	cross, err := vanilla.NewCROSS(internal.RSDP_1_BALANCED)
	if err != nil {
		t.Fatalf("Error creating CROSS instance: %v", err)
	}

	test_vectors = load(PATH_MERKLE_RSDP_1_BALANCED, 3, t)

	run(cross, test_vectors, t)

	// Level 3
	cross, err = vanilla.NewCROSS(internal.RSDP_3_BALANCED)
	if err != nil {
		t.Fatalf("Error creating CROSS instance: %v", err)
	}

	test_vectors = load(PATH_MERKLE_RSDP_3_BALANCED, 3, t)

	run(cross, test_vectors, t)

	// Level 5
	cross, err = vanilla.NewCROSS(internal.RSDP_5_BALANCED)
	if err != nil {
		t.Fatalf("Error creating CROSS instance: %v", err)
	}

	test_vectors = load(PATH_MERKLE_RSDP_5_BALANCED, 3, t)

	run(cross, test_vectors, t)
}
