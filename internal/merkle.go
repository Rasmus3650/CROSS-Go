package internal

import (
	"PQC-Master-Thesis/internal/common"
	"bytes"
	"fmt"
	"math"
)

func (c *CROSS[T, P]) TreeRoot(commitments [][]byte) ([]byte, error) {
	t, err := c.ComputeMerkleTree(commitments)
	if err != nil {
		return nil, err
	}
	return t[0], nil
}

func (c *CROSS[T, P]) ComputeMerkleTree(commitments [][]byte) ([][]byte, error) {
	if c.ProtocolData.IsType(common.TYPE_BALANCED, common.TYPE_SMALL) {
		T := c.placeOnLeaves(commitments)
		startNode := c.TreeParams.LSI[0]
		for level := len(c.TreeParams.NPL) - 1; level >= 1; level-- {
			for i := c.TreeParams.NPL[level] - 2; i >= 0; i -= 2 {
				left_child := startNode + i
				right_child := left_child + 1
				parent := c.Parent(left_child, level)
				hash, err := c.CSPRNG(append(T[left_child], T[right_child]...), (2*c.ProtocolData.Lambda)/8, uint16(32768))
				if err != nil {
					return nil, err
				}
				T[parent] = hash
			}
			startNode -= c.TreeParams.NPL[level-1]
		}
		return T, nil
	} else if c.ProtocolData.IsType(common.TYPE_FAST) {
		T := make([][]byte, c.ProtocolData.T+5)
		copy(T[5:c.ProtocolData.T+5], commitments)
		children := make([]int, 4)
		if c.ProtocolData.T%4 == 0 {
			for i := 0; i < len(children); i++ {
				children[i] = int(math.Floor(float64(c.ProtocolData.T) / 4))
			}

		} else if c.ProtocolData.T%4 == 1 {
			for i := 0; i < len(children); i++ {
				if i == 0 {
					children[i] = int(math.Floor(float64(c.ProtocolData.T)/4)) + 1
				} else {
					children[i] = int(math.Floor(float64(c.ProtocolData.T) / 4))
				}
			}
		} else if c.ProtocolData.T%4 == 2 {
			for i := 0; i < len(children); i++ {
				if i == 0 || i == 1 {
					children[i] = int(math.Floor(float64(c.ProtocolData.T)/4)) + 1
				} else {
					children[i] = int(math.Floor(float64(c.ProtocolData.T) / 4))
				}
			}
		} else if c.ProtocolData.T%4 == 3 {
			for i := 0; i < len(children); i++ {
				if i == 0 || i == 1 || i == 2 {
					children[i] = int(math.Floor(float64(c.ProtocolData.T)/4)) + 1
				} else {
					children[i] = int(math.Floor(float64(c.ProtocolData.T) / 4))
				}
			}
		}
		children_offset := 0
		for i := 0; i <= 3; i++ {
			prephash := []byte{}
			for j := 0; j < children[i]; j++ {
				prephash = append(prephash, T[5+j+children_offset]...)
			}
			children_offset += children[i]
			hash, err := c.CSPRNG(prephash, (2*c.ProtocolData.Lambda)/8, uint16(32768))
			if err != nil {
				return nil, err
			}
			T[i+1] = hash
		}
		data := bytes.Join(T[1:5], nil)
		hash, err := c.CSPRNG(data, 2*c.ProtocolData.Lambda/8, uint16(32768))
		if err != nil {
			return nil, err
		}
		T[0] = hash
		return T, nil

	} else {
		return nil, fmt.Errorf("Invalid scheme type")
	}
}

func (c *CROSS[T, P]) label_leaves(chall_2 []bool) []bool {
	T_prime := make([]bool, c.TreeParams.Total_nodes)
	C := 0
	for i := 0; i < len(c.TreeParams.LSI); i++ {
		for j := 0; j < c.TreeParams.NCL[i]; j++ {
			if !chall_2[C] {
				T_prime[(c.TreeParams.LSI[i] + j)] = true
			}
			C++
		}
	}
	return T_prime
}

func (c *CROSS[T, P]) placeOnLeaves(cmt_0 [][]byte) [][]byte {
	t := make([][]byte, c.TreeParams.Total_nodes)
	C := 0
	for i := 0; i < len(c.TreeParams.LSI); i++ {
		for j := 0; j < c.TreeParams.NCL[i]; j++ {
			t[(c.TreeParams.LSI[i] + j)] = cmt_0[C]
			C++
		}
	}
	return t
}

func (c *CROSS[T, P]) TreeProof(commitments [][]byte, chall_2 []bool) ([][]byte, error) {
	if c.ProtocolData.IsType(common.TYPE_BALANCED, common.TYPE_SMALL) {
		T, err := c.ComputeMerkleTree(commitments)
		if err != nil {
			return nil, err
		}
		T_prime := c.label_leaves(chall_2)
		start_node := c.TreeParams.LSI[0]
		proof := make([][]byte, c.TreeParams.Total_nodes)
		for level := len(c.TreeParams.NPL) - 1; level >= 1; level-- {
			for i := c.TreeParams.NPL[level] - 2; i >= 0; i -= 2 {
				node := start_node + i
				parent := c.Parent(node, level)
				sibling := c.Sibling(node, level)
				if T_prime[node] || T_prime[sibling] {
					T_prime[parent] = true
				}
				if !T_prime[node] && T_prime[sibling] {
					proof[node] = T[node]
				}
				if T_prime[node] && !T_prime[sibling] {
					proof[sibling] = T[sibling]
				}
			}
			start_node -= c.TreeParams.NPL[level-1]
		}
		return proof, nil
	} else if c.ProtocolData.IsType(common.TYPE_FAST) {
		if len(chall_2) != len(commitments) {
			return nil, fmt.Errorf("Length mismatch between commitments (len: %d) and challenge (len: %d)", len(commitments), len(chall_2))
		}
		var result [][]byte
		for i, elem := range chall_2 {
			if elem {
				result = append(result, commitments[i])
			}
		}
		return result, nil
	} else {
		return nil, fmt.Errorf("Invalid scheme type")
	}
}

func (c *CROSS[T, P]) RecomputeRoot(cmt_0, proof [][]byte, chall_2 []bool) ([]byte, error) {
	if c.ProtocolData.IsType(common.TYPE_BALANCED, common.TYPE_SMALL) {
		T := c.placeOnLeaves(cmt_0)
		// End of PlaceCMTonLeaves
		T_prime := c.label_leaves(chall_2)
		start_node := c.TreeParams.LSI[0]
		for level := len(c.TreeParams.NPL) - 1; level >= 1; level-- {
			for i := c.TreeParams.NPL[level] - 2; i >= 0; i -= 2 {
				node := start_node + i
				parent := c.Parent(node, level)
				sibling := c.Sibling(node, level)
				var left_child []byte
				var right_child []byte
				if !T_prime[node] && !T_prime[sibling] {
					continue
				}
				if T_prime[node] {
					left_child = T[node]
				} else {
					left_child = proof[node]
					T[node] = left_child
				}
				if T_prime[sibling] {
					right_child = T[sibling]
				} else {
					right_child = proof[sibling]
					T[sibling] = right_child
				}
				if left_child == nil || right_child == nil {
					return nil, fmt.Errorf("Left or right child is nil")
				}
				hash, err := c.CSPRNG(append(left_child, right_child...), (2*c.ProtocolData.Lambda)/8, uint16(32768))
				if err != nil {
					return nil, err
				}
				T[parent] = hash
				T_prime[parent] = true
			}
			start_node -= c.TreeParams.NPL[level-1]
		}
		return T[0], nil
	} else if c.ProtocolData.IsType(common.TYPE_FAST) {
		pub_nodes := 0
		for i := 0; i <= c.ProtocolData.T-1; i++ {
			if chall_2[i] {
				cmt_0[i] = proof[pub_nodes]
				pub_nodes++
			}
		}
		return c.TreeRoot(cmt_0)
	} else {
		return nil, fmt.Errorf("Invalid scheme type")
	}
}
