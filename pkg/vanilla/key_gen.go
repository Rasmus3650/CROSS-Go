package vanilla

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/internal/matrix"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/sha3"
)

func KeyGen(params common.SchemeData) {
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
	V := matrix.ListToMatrix(temp, params.Params.N-params.Params.K, params.Params.K, params.Params.P)
	fmt.Println(V)
	fmt.Println(len(V))
}
