package seedtree

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"golang.org/x/crypto/sha3"
)

type SeedTree struct {
	Root       *Node
	Nodes      map[int]*Node // Store all nodes by their index
	LeafNodes  []*Node       // Store leaf nodes separately
	UseSalt    bool
	DataLength int
}

type Node struct {
	Left   *Node
	Right  *Node
	Data   []byte
	IsLeaf bool
	Parent *Node
	Index  int
}

// Implement String method for Node to pretty print the node structure
func (n *Node) String() string {
	var sb strings.Builder
	printNode(n, &sb, "")
	return sb.String()
}

// Helper function to recursively print nodes
func printNode(node *Node, sb *strings.Builder, prefix string) {
	if node == nil {
		return
	}

	// Print the current node
	sb.WriteString(fmt.Sprintf("%s- Node Index: %d, IsLeaf: %t, DataLength: %d\n", prefix, node.Index, node.IsLeaf, len(node.Data)))

	// Recursively print left and right children
	if node.Left != nil || node.Right != nil {
		if node.Left != nil {
			printNode(node.Left, sb, prefix+"|   ")
		} else {
			sb.WriteString(fmt.Sprintf("%s|   - No Left Child\n", prefix))
		}
		if node.Right != nil {
			printNode(node.Right, sb, prefix+"|   ")
		} else {
			sb.WriteString(fmt.Sprintf("%s|   - No Right Child\n", prefix))
		}
	}
}

// Implement String method for SeedTree to pretty print the entire tree structure
func (st *SeedTree) String() string {
	var sb strings.Builder
	if st.Root != nil {
		sb.WriteString("SeedTree Structure:\n")
		sb.WriteString(st.Root.String()) // Print the tree starting from root
	}
	return sb.String()
}

func NewSeedTree(mseed, salt []byte, t int, useSalt bool) *SeedTree {
	tree := &SeedTree{
		Nodes:   make(map[int]*Node),
		UseSalt: useSalt,
	}

	// Calculate tree depth needed for t leaves
	treeDepth := int(math.Ceil(math.Log2(float64(t))))

	// Create root node
	var rootData []byte
	if useSalt {
		rootData = append(append(mseed, salt...), byte(0))
	} else {
		rootData = append(mseed, byte(0))
	}

	tree.Root = &Node{
		Data:   rootData,
		IsLeaf: false,
		Index:  0,
	}
	tree.DataLength = len(rootData) - 1
	tree.Nodes[0] = tree.Root

	// Build the tree
	tree.buildTree(tree.Root, salt, 0, treeDepth, 0)

	// Collect leaves
	tree.collectLeaves(t)

	return tree
}

func (st *SeedTree) generateChildData(parentData, salt []byte, index int) []byte {
	output := make([]byte, st.DataLength)

	var input []byte
	if st.UseSalt {
		input = append(append(parentData, salt...), IntToBytes(index)...)
	} else {
		input = append(parentData, IntToBytes(index)...)
	}

	sha3.ShakeSum128(output, input)
	return output
}

func (st *SeedTree) buildTree(parent *Node, salt []byte, currentDepth, maxDepth, index int) {
	if parent == nil {
		return
	}

	if currentDepth == maxDepth {
		parent.IsLeaf = true
		return
	}

	// Create left child
	leftIdx := 2*index + 1
	leftData := st.generateChildData(parent.Data, salt, leftIdx)
	parent.Left = &Node{
		Data:   leftData,
		IsLeaf: false,
		Parent: parent,
		Index:  leftIdx,
	}
	st.Nodes[leftIdx] = parent.Left

	// Create right child
	rightIdx := 2*index + 2
	rightData := st.generateChildData(parent.Data, salt, rightIdx)
	parent.Right = &Node{
		Data:   rightData,
		IsLeaf: false,
		Parent: parent,
		Index:  rightIdx,
	}
	st.Nodes[rightIdx] = parent.Right

	// Recursively build subtrees
	st.buildTree(parent.Left, salt, currentDepth+1, maxDepth, leftIdx)
	st.buildTree(parent.Right, salt, currentDepth+1, maxDepth, rightIdx)
}

func (st *SeedTree) collectLeaves(t int) {
	st.LeafNodes = make([]*Node, 0, t)
	remainingLeaves := t
	st.collectLeavesRecursive(st.Root, &remainingLeaves)
	st.LeafNodes = st.LeafNodes[:t]
}

func (st *SeedTree) collectLeavesRecursive(node *Node, remainingLeaves *int) {
	if node == nil || *remainingLeaves <= 0 {
		return
	}

	if node.IsLeaf {
		if *remainingLeaves > 0 {
			st.LeafNodes = append(st.LeafNodes, node)
			*remainingLeaves--
		}
		return
	}

	st.collectLeavesRecursive(node.Left, remainingLeaves)
	st.collectLeavesRecursive(node.Right, remainingLeaves)
}

// Helper function
func IntToBytes(n int) []byte {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, uint16(n))
	return bytes
}

func SeedTreeLeaves(t int, mseed, salt []byte, useSalt bool) []*Node {
	tree := NewSeedTree(mseed, salt, t, useSalt)
	return tree.LeafNodes[:t]
}

func contains(nodes []*Node, target *Node) bool {
	for _, node := range nodes {
		if node == target {
			return true
		}
	}
	return false
}
func remove(nodes []*Node, target *Node) []*Node {
	for i, node := range nodes {
		if node == target {
			// Remove the node by slicing around it
			return append(nodes[:i], nodes[i+1:]...)
		}
	}
	return nodes
}

func SeedTreePaths(mseed []byte, b []bool, t int) ([]*Node, *SeedTree) {
	tree := NewSeedTree(mseed, nil, t, false)
	reveal_nodes := make([]*Node, 0)
	for i := range b {
		if b[i] == true {
			reveal_nodes = append(reveal_nodes, tree.LeafNodes[i])
		}
	}
	// Run through tree.Nodes in reverse, and check if both children are in reveal_leaves, if they are replace 2 children with 1 parent
	for i := len(tree.Nodes) - 1; i >= 0; i-- {
		node := tree.Nodes[i]
		if node.Left != nil && node.Right != nil {
			if contains(reveal_nodes, node.Left) && contains(reveal_nodes, node.Right) {
				reveal_nodes = remove(reveal_nodes, node.Left)
				reveal_nodes = remove(reveal_nodes, node.Right)
				reveal_nodes = append(reveal_nodes, node)
			}
		}
	}
	return reveal_nodes, tree
}
