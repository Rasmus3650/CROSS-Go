package vanilla

import (
	"PQC-Master-Thesis/internal/common"
	"crypto/rand"
	"math/big"

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

func transposeByteMatrix(matrix [][]byte) [][]byte {
	if len(matrix) == 0 {
		return [][]byte{}
	}

	m, n := len(matrix), len(matrix[0])
	transposed := make([][]byte, n)
	for i := range transposed {
		transposed[i] = make([]byte, m)
	}

	for i := 0; i < m; i++ {
		for j := 0; j < n; j++ {
			transposed[j][i] = matrix[i][j]
		}
	}

	return transposed
}

func multiplyVectorMatrix(vector []byte, matrix [][]byte) []byte {
	if len(vector) == 0 || len(matrix) == 0 || len(vector) != len(matrix) {
		panic("Invalid dimensions: vector length must match matrix row count")
	}

	m := len(matrix[0]) // Number of columns in the matrix
	result := make([]byte, m)

	for j := 0; j < m; j++ {
		var sum byte
		for i := 0; i < len(vector); i++ {
			sum += vector[i] * matrix[i][j] // Byte-wise multiplication
		}
		result[j] = sum
	}

	return result
}

// TODO: Implement the switch case for RSDP-G, along with setting the correct CSPRNG
func KeyGen(g int, proto_params common.ProtocolData) KeyPair {
	seed_sk := make([]byte, (2*proto_params.Lambda)/8)
	_, err := rand.Read(seed_sk)
	if err != nil {
		panic(err)
	}
	seed_e_pk := make([]byte, (4*proto_params.Lambda)/8)
	sha3.ShakeSum128(seed_e_pk, append(seed_sk, byte(3*proto_params.T+1)))
	seed_e := seed_e_pk[:2*proto_params.Lambda/8]
	seed_pk := seed_e_pk[2*proto_params.Lambda/8:]
	n_minus_k := proto_params.N - proto_params.K
	V := make([][]byte, n_minus_k)
	for i := range V {
		V[i] = make([]byte, proto_params.K)
	}
	buffer := make([]byte, n_minus_k*proto_params.K)

	// Security probably dies here since p=509 in RSDP-G, might be fine for RSDP
	sha3.ShakeSum128(buffer, append(seed_pk, byte(3*proto_params.T+2)))
	idx := 0
	for i := 0; i < n_minus_k; i++ {
		for j := 0; j < proto_params.K; j++ {
			// Ensure values are in Fp
			V[i][j] = buffer[idx]%byte(proto_params.P-1) + 1
			if V[i][j] > byte(proto_params.P) {
				panic("V[i][j] > P")
			}
			idx++
		}
	}
	// This will generate trailing zeros in each row, might be wrong?
	H := make([][]byte, n_minus_k)
	for i := range H {
		H[i] = make([]byte, proto_params.N)
		// Copy V part
		copy(H[i][:proto_params.K], V[i])
		// Add identity matrix part
		H[i][proto_params.K+i] = 1
	}
	e_bar := make([]byte, proto_params.N)
	sha3.ShakeSum128(e_bar, append(seed_e, byte(3*proto_params.T+3)))
	for i, v := range e_bar {
		e_bar[i] = v%byte(proto_params.Z-1) + 1
	}
	e := make([]byte, proto_params.N)
	for j := 1; j <= proto_params.N; j++ {
		// Probably a better way to do this
		e[j] = byte(new(big.Int).Exp(big.NewInt(int64(g)), big.NewInt(int64(e_bar[j])), nil).Int64())
	}

	s := multiplyVectorMatrix(e, transposeByteMatrix(H))
	return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: s}}
}
