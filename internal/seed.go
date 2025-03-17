package internal

import (
	"PQC-Master-Thesis/internal/common"
	"fmt"
	"math"

	"golang.org/x/crypto/sha3"
)

func (c *CROSS) Leaves(tree [][]byte) [][]byte {
	result := [][]byte{}
	for i := 0; i < len(c.TreeParams.LSI); i++ {
		index := c.TreeParams.LSI[i]
		for j := 0; j < c.TreeParams.NCL[i]; j++ {
			result = append(result, tree[index+j])
		}
	}
	return result
}

func (c *CROSS) BuildTree(seed, salt []byte) ([][]byte, error) {
	if c.ProtocolData.IsType(common.TYPE_BALANCED, common.TYPE_SMALL) {
		T := make([][]byte, c.TreeParams.Total_nodes)
		T[0] = seed
		start_node := 0
		res := make([][]byte, c.TreeParams.Total_nodes)
		ctr := 0
		for level := 0; level <= len(c.TreeParams.NPL)-1; level++ {
			for i := 0; i <= c.TreeParams.NPL[level]-c.TreeParams.LPL[level]-1; i++ {
				node := start_node + i
				left_child := c.LeftChild(node, level)
				right_child := left_child + 1
				// Expand parent seed, salt and parent index
				res[ctr] = append(append(T[node], salt...), c.ParentIndex(node)...)
				ctr++
				hash := make([]byte, (2*c.ProtocolData.Lambda)/8)
				sha3.ShakeSum128(hash, append(append(T[node], salt...), c.ParentIndex(node)...))
				T[left_child] = hash[:c.ProtocolData.Lambda/8]
				T[right_child] = hash[c.ProtocolData.Lambda/8:]
			}
			start_node += c.TreeParams.NPL[level]

		}
		return T, nil
	} else if c.ProtocolData.IsType(common.TYPE_FAST) {
		T := make([][]byte, c.TreeParams.Total_nodes)
		T[0] = seed
		hash := make([]byte, (4*c.ProtocolData.Lambda)/8)
		sha3.ShakeSum128(hash, append(append(T[0], salt...), c.ParentIndex(0)...))
		for i := 1; i <= 4; i++ {
			T[i] = hash[(i-1)*c.ProtocolData.Lambda/8 : i*c.ProtocolData.Lambda/8]
		}
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
		result := [][]byte{}
		for i := 0; i <= 3; i++ {
			hash := make([]byte, (children[i]*c.ProtocolData.Lambda)/8)
			sha3.ShakeSum128(hash, append(append(T[i+1], salt...), c.ParentIndex(i+1)...))
			for j := 0; j < children[i]; j++ {
				result = append(result, hash[j*c.ProtocolData.Lambda/8:(j+1)*c.ProtocolData.Lambda/8])
			}
		}
		return result, nil
	} else {
		return nil, fmt.Errorf("Scheme type not supported only balanced, small and fast are supported")
	}
}
func (c *CROSS) SeedLeaves(seed, salt []byte) ([][]byte, error) {
	if c.ProtocolData.IsType(common.TYPE_BALANCED, common.TYPE_SMALL) {
		T, err := c.BuildTree(seed, salt)
		if err != nil {
			return nil, fmt.Errorf("Error: %s", err)
		}
		return c.Leaves(T), nil
	} else if c.ProtocolData.IsType(common.TYPE_FAST) {
		return c.BuildTree(seed, salt)
	} else {
		return nil, fmt.Errorf("Scheme type not supported only balanced, small and fast are supported")
	}
}

// List of all leaf indices for the tree
func (c *CROSS) leafSet() []int {
	var result []int
	for i := 0; i < len(c.TreeParams.LSI); i++ {
		count := c.TreeParams.NCL[i]
		start := c.TreeParams.LSI[i]
		for j := 0; j < count; j++ {
			result = append(result, start+j)
		}
	}
	return result
}

func (c *CROSS) computeNodesToPublish(chall_2 []bool) []bool {
	result := make([]bool, c.TreeParams.Total_nodes)
	ctr := 0
	for i := 0; i < len(c.TreeParams.LSI); i++ {
		for j := 0; j < c.TreeParams.NCL[i]; j++ {
			if chall_2[ctr] {
				result[c.TreeParams.LSI[i]+j] = chall_2[ctr]
			}
			ctr++
		}
	}
	leafset := c.leafSet()
	for i := len(result) - 1; i >= 0; i-- {
		level := c.GetLevelOfNode(i)
		if !Contains(leafset, i) && result[c.LeftChild(i, level)] && result[c.LeftChild(i, level)+1] {
			result[i] = true
			result[c.LeftChild(i, level)] = false
			result[c.LeftChild(i, level)+1] = false
		}
	}
	return result
}

func (c *CROSS) SeedPath(seed, salt []byte, chall_2 []bool) ([][]byte, error) {
	if c.ProtocolData.IsType(common.TYPE_BALANCED, common.TYPE_SMALL) {
		T, err := c.BuildTree(seed, salt)
		if err != nil {
			return nil, err
		}
		path := c.computeNodesToPublish(chall_2)
		seedPath := [][]byte{}
		for i := 0; i < len(path); i++ {
			if path[i] {
				seedPath = append(seedPath, T[i])
			}
		}
		return seedPath, nil
	} else if c.ProtocolData.IsType(common.TYPE_FAST) {
		leaves, err := c.SeedLeaves(seed, salt)
		if err != nil {
			return nil, err
		}
		var result [][]byte
		for i := 0; i < len(chall_2); i++ {
			if chall_2[i] {
				result = append(result, leaves[i])
			}
		}
		return result, nil
	} else {
		return nil, fmt.Errorf("Scheme type not supported only balanced, small and fast are supported")
	}
}

func (c *CROSS) RebuildLeaves(path [][]byte, salt []byte, chall_2 []bool) ([][]byte, error) {
	if c.ProtocolData.IsType(common.TYPE_BALANCED, common.TYPE_SMALL) {
		T_prime := c.computeNodesToPublish(chall_2)
		T := make([][]byte, c.TreeParams.Total_nodes)
		start_node := 1
		pub_nodes := 0
		res := make([][]byte, c.TreeParams.Total_nodes)
		ctr := 0
		for level := 1; level <= len(c.TreeParams.NPL)-1; level++ {
			for i := 0; i <= c.TreeParams.NPL[level]-1; i++ {
				node := start_node + i
				parent := c.Parent(node, level)
				left_child := c.LeftChild(node, level)
				right_child := left_child + 1
				if T_prime[node] && !T_prime[parent] {
					T[node] = path[pub_nodes]
					pub_nodes++
				}
				if T_prime[node] && i < c.TreeParams.NPL[level]-c.TreeParams.LPL[level] {
					hash := make([]byte, (2*c.ProtocolData.Lambda)/8)
					res[ctr] = append(append(T[node], salt...), c.ParentIndex(node)...)
					ctr++
					sha3.ShakeSum128(hash, append(append(T[node], salt...), c.ParentIndex(node)...))
					T[left_child] = hash[:c.ProtocolData.Lambda/8]
					T[right_child] = hash[c.ProtocolData.Lambda/8:]
					T_prime[left_child] = true
					T_prime[right_child] = true
				}
			}
			start_node += c.TreeParams.NPL[level]
		}
		res_prime := [][]byte{}
		result := [][]byte{}
		leaves := c.Leaves(T)
		for i := 0; i < len(leaves); i++ {
			if chall_2[i] {
				result = append(result, leaves[i])
				res_prime = append(res_prime, res[i])
			}
		}
		return result, nil
	} else if c.ProtocolData.IsType(common.TYPE_FAST) {
		return path, nil
	} else {
		return nil, fmt.Errorf("Scheme type not supported only balanced, small and fast are supported")
	}
}
