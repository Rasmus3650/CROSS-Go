package test

import (
	seedtree "PQC-Master-Thesis/internal/seed"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestLeaves(t *testing.T) {
	salt := make([]byte, 64)
	mseed := make([]byte, 32)
	rand.Read(mseed)
	rand.Read(salt)
	leaves := seedtree.SeedTreeLeaves(8, mseed, salt, true)
	for i, leaf := range leaves {
		fmt.Printf("Leaf %d: %+v\n", i, leaf)
	}
}

func TestSeedPath(t *testing.T) {
	mseed := make([]byte, 32)
	salt := make([]byte, 64)
	rand.Read(mseed)
	rand.Read(salt)
	b := []bool{true, true, true, true, true, false, true, false}
	leaves, _ := seedtree.SeedTreePaths(salt, mseed, b, 8)
	for _, leaf := range leaves {
		fmt.Println("Leaf:", leaf.String())
	}
	tree2 := seedtree.NewSeedTree(mseed, salt, 8)
	fmt.Println("tree", tree2.String())
}
