package vanilla

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/internal/matrix"
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

type Pub struct {
	SeedPK []byte
	S      []byte
}

type KeyPair struct {
	Pri []byte
	Pub
}

func ExpandPrivateSeed(params common.SchemeData, seed_sk []byte) ([]byte, [][]byte, []byte) {
	// Generate seede and seed_pk
	seede_seed_pub := make([]byte, (4*params.Lambda)/8)
	sha3.ShakeSum128(seede_seed_pub, seed_sk)
	seede, seed_pk := seede_seed_pub[:2*params.Lambda/8], seede_seed_pub[2*params.Lambda/8:]
	entries := (params.N - params.K) * params.K
	temp := make([]byte, entries)
	sha3.ShakeSum128(temp, seed_pk)
	V := matrix.ListToMatrix(temp, params.N-params.K, params.K, params.P)
	// ???
	I_nk := matrix.CreateIdentityMatrix(params.N - params.K)
	H := matrix.AppendMatrices(V, I_nk)
	// We know what is happening again here
	eta := make([]byte, params.N)
	sha3.ShakeSum128(eta, seede)
	for i := 0; i < params.N; i++ {
		eta[i] = eta[i] % byte(params.Z)
	}
	return eta, H, seed_pk
}

func KeyGen(g int, params common.SchemeData) KeyPair {
	// Generate seed_sk
	seed_sk := make([]byte, (2*params.Lambda)/8)
	_, err := rand.Read(seed_sk)
	if err != nil {
		panic(err)
	}
	eta, H, seed_pk := ExpandPrivateSeed(params, seed_sk)
	e := make([]byte, params.N)
	for j := 0; j < params.N-1; j++ {
		e[j] = byte(g) ^ eta[j]
	}
	// Matrix multiplication and transpose, is S supposed to be a vector????
	s := matrix.MultiplyVectorMatrix(e, matrix.Transpose(H))
	return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: s}}
}
