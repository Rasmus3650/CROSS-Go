package internal

import (
	"PQC-Master-Thesis/internal/common"
	"bytes"
	"math"
)

func (c *CROSS[T, P]) TreeRoot(commitments [][]byte) []byte {
	t := c.ComputeMerkleTree(commitments)
	return t[0]
}

func (c *CROSS[T, P]) ComputeMerkleTree(commitments [][]byte) [][]byte {
	if c.ProtocolData.IsType(common.TYPE_BALANCED, common.TYPE_SMALL) {
		T := c.placeOnLeaves(commitments)
		startNode := c.TreeParams.LSI[0]
		for level := len(c.TreeParams.NPL) - 1; level > 0; level-- {
			for i := c.TreeParams.NPL[level] - 2; i >= 0; i -= 2 {
				current_node := startNode + i
				parent_node := c.Parent(current_node, level)
				hash_input := make([]byte, 2*((2*c.ProtocolData.Lambda)/8))
				copy(hash_input, T[current_node])
				copy(hash_input[2*c.ProtocolData.Lambda/8:], T[current_node+1])
				hash := c.CSPRNG(hash_input, (2*c.ProtocolData.Lambda)/8, uint16(32768))
				T[parent_node] = hash
			}
			startNode -= c.TreeParams.NPL[level-1]
		}
		return T
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
			hash := c.CSPRNG(prephash, (2*c.ProtocolData.Lambda)/8, uint16(32768))
			T[i+1] = hash
		}
		data := bytes.Join(T[1:5], nil)
		hash := c.CSPRNG(data, 2*c.ProtocolData.Lambda/8, uint16(32768))
		T[0] = hash
		return T

	} else {
		return nil
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

func (c *CROSS[T, P]) TreeProof(commitments [][]byte, chall_2 []bool) [][]byte {
	if c.ProtocolData.IsType(common.TYPE_BALANCED, common.TYPE_SMALL) {
		T := c.ComputeMerkleTree(commitments)
		mtp := make([][]byte, c.ProtocolData.TREE_NODES_TO_STORE)
		for i := 0; i < len(mtp); i++ {
			mtp[i] = make([]byte, 2*c.ProtocolData.Lambda/8)
		}
		flag_tree := c.label_leaves(chall_2)
		published := 0
		start_node := c.TreeParams.LSI[0]
		// -1 in len?
		for level := len(c.TreeParams.NPL) - 1; level > 0; level-- {
			for i := c.TreeParams.NPL[level] - 2; i >= 0; i -= 2 {
				current_node := start_node + i
				parent_node := c.Parent(current_node, level)
				flag_tree[parent_node] = flag_tree[current_node] || flag_tree[current_node+1]
				/* Add left sibling only if right one was computed but left wasn't */
				if !flag_tree[current_node] && flag_tree[current_node+1] {
					copy(mtp[published], T[current_node])
					published++
				}
				/* Add right sibling only if left was computed but right wasn't */
				if flag_tree[current_node] && !flag_tree[current_node+1] {
					copy(mtp[published], T[current_node+1])
					published++
				}
			}
			start_node -= c.TreeParams.NPL[level-1]
		}
		return mtp
	} else if c.ProtocolData.IsType(common.TYPE_FAST) {
		if len(chall_2) != len(commitments) {
			return nil
		}
		var result [][]byte
		for i, elem := range chall_2 {
			if elem {
				result = append(result, commitments[i])
			}
		}
		return result
	} else {
		return nil
	}
}

func (c *CROSS[T, P]) RecomputeRoot(cmt_0, proof [][]byte, chall_2 []bool) ([]byte, bool) {
	/*Their terms:
	recomputed_leaves = cmt_0
	mtp = proof
	leaves_to_reveal = chall_2*/
	if c.ProtocolData.IsType(common.TYPE_BALANCED, common.TYPE_SMALL) {
		T := c.placeOnLeaves(cmt_0)
		T_prime := c.label_leaves(chall_2)
		published := 0
		start_node := c.TreeParams.LSI[0]
		for level := len(c.TreeParams.NPL) - 1; level > 0; level-- {
			for i := c.TreeParams.NPL[level] - 2; i >= 0; i -= 2 {
				current_node := start_node + i
				parent_node := c.Parent(current_node, level)
				hash_input := make([]byte, 2*((2*c.ProtocolData.Lambda)/8))
				if !T_prime[current_node] && !T_prime[current_node+1] {
					continue
				}
				if T_prime[current_node] {
					copy(hash_input, T[current_node])
				} else {
					copy(hash_input, proof[published])
					published++
				}
				if T_prime[current_node+1] {
					copy(hash_input[2*c.ProtocolData.Lambda/8:], T[current_node+1])
				} else {
					copy(hash_input[2*c.ProtocolData.Lambda/8:], proof[published])
					published++
				}
				hash := c.CSPRNG(hash_input, (2*c.ProtocolData.Lambda)/8, uint16(32768))
				T[parent_node] = hash
				T_prime[parent_node] = true
			}
			start_node -= c.TreeParams.NPL[level-1]
		}
		error_rate := uint8(0)
		for i := published; i < c.ProtocolData.TREE_NODES_TO_STORE; i++ {
			// Check each byte in the row
			for j := 0; j < 2*c.ProtocolData.Lambda/8; j++ {
				error_rate |= proof[i][j]
			}
		}

		return T[0], error_rate == 0
	} else if c.ProtocolData.IsType(common.TYPE_FAST) {
		pub_nodes := 0
		for i := 0; i < c.ProtocolData.T; i++ {
			if chall_2[i] {
				cmt_0[i] = proof[pub_nodes]
				pub_nodes++
			}
		}
		root := c.TreeRoot(cmt_0)
		return root, true
	} else {
		return nil, false
	}
}
