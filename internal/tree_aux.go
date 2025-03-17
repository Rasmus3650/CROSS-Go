package internal

import (
	"encoding/binary"
)

func (c *CROSS) LeftChild(node_index, level int) int {
	return (2*node_index + 1) - c.TreeParams.Off[level]
}

func (c *CROSS) Sibling(node_index, level int) int {
	if node_index%2 == 1 {
		return node_index + 1
	} else {
		return node_index - 1
	}
}
func (c *CROSS) Parent(node_index, level int) int {
	if node_index%2 == 1 {
		return (node_index-1)/2 + (c.TreeParams.Off[level-1] / 2)
	} else {
		return (node_index-2)/2 + (c.TreeParams.Off[level-1] / 2)

	}

}
func (c *CROSS) ParentIndex(index int) []byte {
	data := make([]byte, 2)
	// Convert to little-endian
	binary.LittleEndian.PutUint16(data, uint16(index))
	return data
}

func (c *CROSS) GetLevelOfNode(node_index int) int {
	acc := node_index
	for i := 0; i < len(c.TreeParams.NPL); i++ {
		acc -= c.TreeParams.NPL[i]
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
