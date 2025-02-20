package merkle

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/internal/seed"
	"bytes"
	"fmt"
	"math"

	"golang.org/x/crypto/sha3"
)

// TODO: RecomputeMerkleRoot, MerkleProof, VerifyMerkleRoot

func TreeRoot(schemeType string, commitments [][]byte, proto_params common.ProtocolData, tree_params common.TreeParams) ([]byte, error) {
	T, err := ComputeMerkleTree(schemeType, commitments, proto_params, tree_params)
	if err != nil {
		return nil, err
	}
	return T[0], nil
}

func byteContains(tree [][]byte, elem []byte) bool {
	for _, value := range tree {
		if bytes.Equal(value, elem) {
			return true
		}
	}
	return false
}

func ComputeMerkleTree(schemeType string, commitments [][]byte, proto_params common.ProtocolData, tree_params common.TreeParams) ([][]byte, error) {
	if schemeType == "small" || schemeType == "balanced" {
		T := make([][]byte, tree_params.Total_nodes)
		commitment_offset := 0
		// Place leaves on Tree (PlaceOnLeaves())
		for i := 0; i < len(tree_params.LSI); i++ {
			remainder := tree_params.NCL[i]
			for j := 0; j < len(commitments); j++ {
				T[tree_params.LSI[i]+j+commitment_offset] = commitments[j+commitment_offset]
				remainder--
				if remainder == 0 {
					commitment_offset += j
					break
				}
			}
		}
		startNode := tree_params.LSI[0]
		for level := len(tree_params.NPL) - 1; level >= 1; level-- {
			for i := tree_params.NPL[level] - 2; i >= 0; i -= 2 {
				left_child := startNode + i
				right_child := left_child + 1
				parent := seed.Parent(left_child, level, tree_params)
				hash := make([]byte, (2*proto_params.Lambda)/8)
				sha3.ShakeSum128(hash, append(T[left_child], T[right_child]...))
				T[parent] = hash
			}
			startNode -= tree_params.NPL[level-1]
		}
		fmt.Println("Tree error: ", byteContains(T, nil))
		return T, nil
	} else if schemeType == "fast" {
		T := make([][]byte, proto_params.T+5)
		copy(T[5:proto_params.T+5], commitments)
		children := make([]int, 4)
		if proto_params.T%4 == 0 {
			for i := 0; i < len(children); i++ {
				children[i] = int(math.Floor(float64(proto_params.T) / 4))
			}

		} else if proto_params.T%4 == 1 {
			for i := 0; i < len(children); i++ {
				if i == 0 {
					children[i] = int(math.Floor(float64(proto_params.T)/4)) + 1
				} else {
					children[i] = int(math.Floor(float64(proto_params.T) / 4))
				}
			}
		} else if proto_params.T%4 == 2 {
			for i := 0; i < len(children); i++ {
				if i == 0 || i == 1 {
					children[i] = int(math.Floor(float64(proto_params.T)/4)) + 1
				} else {
					children[i] = int(math.Floor(float64(proto_params.T) / 4))
				}
			}
		} else if proto_params.T%4 == 3 {
			for i := 0; i < len(children); i++ {
				if i == 0 || i == 1 || i == 2 {
					children[i] = int(math.Floor(float64(proto_params.T)/4)) + 1
				} else {
					children[i] = int(math.Floor(float64(proto_params.T) / 4))
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
			hash := make([]byte, (2*proto_params.Lambda)/8)
			sha3.ShakeSum128(hash, prephash)
			T[i+1] = hash
		}
		hash := make([]byte, (2*proto_params.Lambda)/8)
		data := bytes.Join(T[1:4], nil)
		sha3.ShakeSum128(hash, data)
		T[0] = hash
		return T, nil

	} else {
		return nil, fmt.Errorf("Invalid scheme type")
	}
}

func Label_leaves(chall_2 []bool, tree_params common.TreeParams) []bool {
	T_prime := make([]bool, tree_params.Total_nodes)
	counter2 := 0
	for i := 0; i < len(tree_params.LSI); i++ {
		for j := 0; j < tree_params.NCL[i]; j++ {
			if !chall_2[counter2] {
				T_prime[(tree_params.LSI[i] + j)] = true
			}
			counter2++
		}
	}
	return T_prime
}

func TreeProof(schemeType string, commitments [][]byte, chall_2 []bool, proto_params common.ProtocolData, tree_params common.TreeParams) ([][]byte, error) {
	if schemeType == "small" || schemeType == "balanced" {
		T, err := ComputeMerkleTree(schemeType, commitments, proto_params, tree_params)
		if err != nil {
			return nil, err
		}
		T_prime := Label_leaves(chall_2, tree_params)
		start_node := tree_params.LSI[0]
		proof := make([][]byte, tree_params.Total_nodes)
		for level := len(tree_params.NPL) - 1; level >= 1; level-- {
			for i := tree_params.NPL[level] - 2; i >= 0; i -= 2 {
				node := start_node + i
				parent := seed.Parent(node, level, tree_params)
				sibling := seed.Sibling(node, level, tree_params)
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
			start_node -= tree_params.NPL[level-1]
		}
		return proof, nil
	} else if schemeType == "fast" {
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

func RecomputeRoot(schemeType string, cmt_0, proof [][]byte, chall_2 []bool, proto_params common.ProtocolData, tree_params common.TreeParams) ([]byte, error) {
	if schemeType == "small" || schemeType == "balanced" {
		T := make([][]byte, tree_params.Total_nodes)
		cnt := 0
		for i := 0; i < len(tree_params.LSI); i++ {
			for j := 0; j < tree_params.NCL[i]; j++ {
				T[(tree_params.LSI[i] + j)] = cmt_0[cnt]
				cnt++
			}
		}
		// End of PlaceCMTonLeaves
		T_prime := Label_leaves(chall_2, tree_params)
		start_node := tree_params.LSI[0]
		for level := len(tree_params.NPL) - 1; level >= 1; level-- {
			for i := tree_params.NPL[level] - 2; i >= 0; i -= 2 {
				node := start_node + i
				parent := seed.Parent(node, level, tree_params)
				sibling := seed.Sibling(node, level, tree_params)
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
				hash := make([]byte, (2*proto_params.Lambda)/8)
				if left_child == nil || right_child == nil {
					fmt.Println("Node: ", node)
					fmt.Println("proof node: ", proof[node])
					fmt.Println("proof sibling: ", proof[sibling])
					fmt.Println("Left child: ", left_child)
					fmt.Println("Right child: ", right_child)
					return nil, fmt.Errorf("Left or right child is nil")
				}
				sha3.ShakeSum128(hash, append(left_child, right_child...))
				T[parent] = hash
				T_prime[parent] = true
			}
			start_node -= tree_params.NPL[level-1]
		}
		//fmt.Println("Recreated tree: ", T)
		return T[0], nil
	} else if schemeType == "fast" {
		pub_nodes := 0
		for i := 0; i <= proto_params.T-1; i++ {
			if chall_2[i] {
				cmt_0[i] = proof[pub_nodes]
				pub_nodes++
			}
		}
		return TreeRoot(schemeType, cmt_0, proto_params, tree_params)
	} else {
		return nil, fmt.Errorf("Invalid scheme type")
	}
}
