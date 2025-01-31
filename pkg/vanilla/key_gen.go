package vanilla

import (
	"crypto/rand"
	"fmt"

	common "github.com/rasmus3650/PQC-Master-Thesis/internal/common"
	"golang.org/x/crypto/sha3"
)

func listToMatrix(list []byte, rows, cols, p int) [][]byte {
	if len(list) != rows*cols {
		panic("The size of the list does not match the matrix dimensions.")
	}

	// Create the matrix
	matrix := make([][]byte, rows)
	for i := 0; i < rows; i++ {
		matrix[i] = make([]byte, cols) // Initialize each row
		for j := 0; j < cols; j++ {
			// Compute modulo for each element
			matrix[i][j] = list[i*cols+j] % byte(p)
		}
	}
	return matrix
}

func KeyGen(params common.SecurityData) {
	// Generate seed_sk
	seed_sk := make([]byte, (2*params.Lambda)/8)
	_, err := rand.Read(seed_sk)
	if err != nil {
		panic(err)
	}
	// Generate seede and seed_pk
	seede_seed_pub := make([]byte, (4*params.Lambda)/8)
	sha3.ShakeSum128(seede_seed_pub, seed_sk)
	_, seed_pk := seede_seed_pub[:2*params.Lambda/8], seede_seed_pub[2*params.Lambda/8:]

	// Generate V (USIKKER!)
	entries := (params.Params.N - params.Params.K) * params.Params.K
	temp := make([]byte, entries)
	sha3.ShakeSum128(temp, seed_pk)
	V := listToMatrix(temp, params.Params.N-params.Params.K, params.Params.K, params.Params.P)
	fmt.Println(V)
	fmt.Println(len(V))
}
