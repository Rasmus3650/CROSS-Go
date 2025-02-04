package merkle

import (
	"fmt"

	"golang.org/x/crypto/sha3"
)

// TODO: RecomputeMerkleRoot, MerkleProof, VerifyMerkleRoot
// SeedTreePaths, SeedTreeLeaves, RebuildSeedTreeLeaves

type Node struct {
	Left   *Node
	Right  *Node
	Hash   []byte
	Data   []byte
	IsLeaf bool
}

type MerkleTree struct {
	Root   *Node
	Leaves []*Node
}

func NewNode(data []byte, isLeaf bool) *Node {
	node := &Node{
		Data:   data,
		IsLeaf: isLeaf,
	}
	if isLeaf {
		node.Hash = calculateHash(data)
	}
	return node
}

func calculateHash(data []byte) []byte {
	hash := make([]byte, 32)
	sha3.ShakeSum128(hash, data)
	return hash
}

func isPowerOfTwo(n int) bool {
	if n <= 0 {
		return false
	}
	return (n & (n - 1)) == 0
}

// NewMerkleTree creates a new Merkle Tree from the given data blocks
func NewMerkleTree(dataBlocks [][]byte) (*MerkleTree, error) {
	if len(dataBlocks) == 0 {
		return nil, fmt.Errorf("no data provided")
	}

	// Verify that the number of data blocks is a power of 2
	if !isPowerOfTwo(len(dataBlocks)) {
		return nil, fmt.Errorf("length of data must be a power of 2")
	}
	leafCount := len(dataBlocks)
	tree := &MerkleTree{
		Leaves: make([]*Node, leafCount),
	}

	// Create leaf nodes
	for i := 0; i < leafCount; i++ {
		tree.Leaves[i] = NewNode(dataBlocks[i], true)
	}

	// Build the tree from leaves up
	tree.Root = tree.buildTree(tree.Leaves)
	return tree, nil
}

func (m *MerkleTree) buildTree(nodes []*Node) *Node {
	if len(nodes) == 1 {
		return nodes[0]
	}

	var parents []*Node
	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		right := nodes[i+1]

		parent := NewNode(nil, false)
		parent.Left = left
		parent.Right = right

		// Concatenate and hash children's hashes
		combinedHash := append(left.Hash, right.Hash...)
		parent.Hash = calculateHash(combinedHash)

		parents = append(parents, parent)
	}

	return m.buildTree(parents)
}

func (m *MerkleTree) MerkleProof(index int) ([][]byte, error) {

}
