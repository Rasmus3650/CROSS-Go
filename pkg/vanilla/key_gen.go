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

/*func ExpandPrivateSeed(params common.SchemeData, seed_sk []byte) ([]byte, [][]byte, []byte) {
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
*/

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
