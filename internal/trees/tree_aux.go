package trees

import (
	"PQC-Master-Thesis/internal/common"
	"encoding/binary"
)

func LeftChild(node_index, level int, tree_params common.TreeParams) int {
	return (2*node_index + 1) - tree_params.Off[level]
}

func Sibling(node_index, level int, tree_params common.TreeParams) int {
	if node_index%2 == 1 {
		return node_index + 1
	} else {
		return node_index - 1
	}
}
func Parent(node_index, level int, tree_params common.TreeParams) int {
	if node_index%2 == 1 {
		return (node_index-1)/2 + (tree_params.Off[level-1] / 2)
	} else {
		return (node_index-2)/2 + (tree_params.Off[level-1] / 2)

	}

}
func ParentIndex(index int) []byte {
	data := make([]byte, 2)
	// Convert to little-endian
	binary.LittleEndian.PutUint16(data, uint16(index))
	return data
}

func GetLevelOfNode(node_index int, tree_params common.TreeParams) int {
	acc := node_index
	for i := 0; i < len(tree_params.NPL); i++ {
		acc -= tree_params.NPL[i]
		if acc < 0 {
			return i
		}
	}
	return -1
}

func Contains(slice []int, elem int) bool {
	for _, v := range slice {
		if v == elem {
			return true
		}
	}
	return false
}
