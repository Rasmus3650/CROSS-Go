package test

import (
	"PQC-Master-Thesis/internal/merkle"
	"bytes"
	"strconv"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestNewNode(t *testing.T) {
	node := merkle.NewNode([]byte("test"), true)
	hash := make([]byte, 32)
	sha3.ShakeSum128(hash, []byte("test"))
	if !bytes.Equal(node.Hash, hash) {
		t.Errorf("Hash mismatch: got %x, expected %x", node.Hash, hash)
	}
}

func TestInvalidInput(t *testing.T) {
	data := make([][]byte, 0)
	_, err := merkle.NewMerkleTree(data)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
	data2 := make([][]byte, 5)
	for i := range data2 {
		data2[i] = []byte("test" + strconv.Itoa(i))
	}
	_, err2 := merkle.NewMerkleTree(data)
	if err2 == nil {
		t.Errorf("Expected error, got nil")
	}

	data3 := make([][]byte, 1)
	data3[0] = []byte("test")
	_, err3 := merkle.NewMerkleTree(data3)
	if err3 != nil {
		t.Errorf("Root should be equal to Leaf node, for tree of size 1")
	}
}

func TestCreateTree(t *testing.T) {
	data := make([][]byte, 8)
	for i := range data {
		data[i] = []byte("test" + strconv.Itoa(i))
	}
	tree, err := merkle.NewMerkleTree(data)
	if err != nil {
		t.Errorf("Error creating tree: %v", err)
	}
	trueHashes := make([][]byte, 15)
	for i := range data {
		hash := make([]byte, 32)
		sha3.ShakeSum128(hash, data[i])
		trueHashes[i] = hash
	}
	for i := 0; i < 4; i++ {
		hash := make([]byte, 32)
		conc_hash := append(trueHashes[i*2], trueHashes[i*2+1]...)
		sha3.ShakeSum128(hash, conc_hash)
		trueHashes[8+i] = hash
	}
	for i := 0; i < 2; i++ {
		hash := make([]byte, 32)
		conc_hash := append(trueHashes[8+i*2], trueHashes[9+i*2]...)
		sha3.ShakeSum128(hash, conc_hash)
		trueHashes[12+i] = hash
	}
	hash := make([]byte, 32)
	conc_hash := append(trueHashes[12], trueHashes[13]...)
	sha3.ShakeSum128(hash, conc_hash)
	trueHashes[14] = hash

	// Verify leaves
	for i := range tree.Leaves {
		if !bytes.Equal(tree.Leaves[i].Hash, trueHashes[i]) {
			t.Errorf("Leaf hash mismatch: got %x, expected %x", tree.Leaves[i].Hash, trueHashes[i])
		}
	}
	// Verify root - Assumption is that if root and leaves are valid nothing can have gone wrong in between
	if !bytes.Equal(tree.Root.Hash, trueHashes[14]) {
		t.Errorf("Leaf hash mismatch: got %x, expected %x", tree.Root.Hash, trueHashes[14])
	}
}
