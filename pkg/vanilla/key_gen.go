package vanilla

import (
	"PQC-Master-Thesis/internal/common"
	"crypto/rand"
	"fmt"
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

// TODO: Implement the switch case for RSDP-G, along with setting the correct CSPRNG
func (c *CROSS) KeyGen() (KeyPair, error) {
	seed_sk := make([]byte, (2*c.ProtocolData.Lambda)/8)
	_, err := rand.Read(seed_sk)
	if err != nil {
		panic(err)
	}
	seed_e_pk := make([]byte, (4*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(seed_e_pk, append(seed_sk, byte(3*c.ProtocolData.T+1)))
	seed_e := seed_e_pk[:2*c.ProtocolData.Lambda/8]
	seed_pk := seed_e_pk[2*c.ProtocolData.Lambda/8:]
	n_minus_k := c.ProtocolData.N - c.ProtocolData.K
	V := make([][]byte, n_minus_k)
	for i := range V {
		V[i] = make([]byte, c.ProtocolData.K)
	}
	buffer := make([]byte, n_minus_k*c.ProtocolData.K)

	// Security probably dies here since p=509 in RSDP-G, might be fine for RSDP
	sha3.ShakeSum128(buffer, append(seed_pk, byte(3*c.ProtocolData.T+2)))
	idx := 0
	for i := 0; i < n_minus_k; i++ {
		for j := 0; j < c.ProtocolData.K; j++ {
			// Ensure values are in Fp
			V[i][j] = buffer[idx]%byte(c.ProtocolData.P-1) + 1
			if V[i][j] > byte(c.ProtocolData.P) {
				return KeyPair{}, fmt.Errorf("V[i][j] > P")
			}
			idx++
		}
	}
	// This will generate trailing zeros in each row, might be wrong?
	H := make([][]byte, n_minus_k)
	for i := range H {
		H[i] = make([]byte, c.ProtocolData.N)
		// Copy V part
		copy(H[i][:c.ProtocolData.K], V[i])
		// Add identity matrix part
		H[i][c.ProtocolData.K+i] = 1
	}
	e_bar := make([]byte, c.ProtocolData.N)
	sha3.ShakeSum128(e_bar, append(seed_e, byte(3*c.ProtocolData.T+3)))
	for i, v := range e_bar {
		e_bar[i] = v%byte(c.ProtocolData.Z-1) + 1
	}
	e := make([]byte, c.ProtocolData.N)
	for j := 1; j <= c.ProtocolData.N; j++ {
		// Probably a better way to do this
		e[j] = byte(new(big.Int).Exp(big.NewInt(int64(c.ProtocolData.G)), big.NewInt(int64(e_bar[j])), nil).Int64())
	}

	s := common.MultiplyVectorMatrix(e, common.TransposeByteMatrix(H))
	return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: s}}, nil
}

// Dummy KeyGen function for testing purposes ONLY
func (c *CROSS) DummyKeyGen(seed_sk []byte) (KeyPair, error) {
	seed_e_pk := make([]byte, (4*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(seed_e_pk, append(seed_sk, byte(3*c.ProtocolData.T+1)))
	seed_e := seed_e_pk[:2*c.ProtocolData.Lambda/8]
	seed_pk := seed_e_pk[2*c.ProtocolData.Lambda/8:]
	n_minus_k := c.ProtocolData.N - c.ProtocolData.K
	V := make([][]byte, n_minus_k)
	for i := range V {
		V[i] = make([]byte, c.ProtocolData.K)
	}
	buffer := make([]byte, n_minus_k*c.ProtocolData.K)

	// Security probably dies here since p=509 in RSDP-G, might be fine for RSDP
	sha3.ShakeSum128(buffer, append(seed_pk, byte(3*c.ProtocolData.T+2)))
	idx := 0
	for i := 0; i < n_minus_k; i++ {
		for j := 0; j < c.ProtocolData.K; j++ {
			// Ensure values are in Fp
			V[i][j] = buffer[idx]%byte(c.ProtocolData.P-1) + 1
			if V[i][j] > byte(c.ProtocolData.P) {
				return KeyPair{}, fmt.Errorf("V[i][j] > P")
			}
			idx++
		}
	}
	// This will generate trailing zeros in each row, might be wrong?
	H := make([][]byte, n_minus_k)
	for i := range H {
		H[i] = make([]byte, c.ProtocolData.N)
		// Copy V part
		copy(H[i][:c.ProtocolData.K], V[i])
		// Add identity matrix part
		H[i][c.ProtocolData.K+i] = 1
	}
	e_bar := make([]byte, c.ProtocolData.N)
	sha3.ShakeSum128(e_bar, append(seed_e, byte(3*c.ProtocolData.T+3)))
	for i, v := range e_bar {
		e_bar[i] = v%byte(c.ProtocolData.Z-1) + 1
	}
	e := make([]byte, c.ProtocolData.N)
	for j := 1; j <= c.ProtocolData.N; j++ {
		// Probably a better way to do this
		e[j] = byte(new(big.Int).Exp(big.NewInt(int64(c.ProtocolData.G)), big.NewInt(int64(e_bar[j])), nil).Int64())
	}

	s := common.MultiplyVectorMatrix(e, common.TransposeByteMatrix(H))
	return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: s}}, nil
}
