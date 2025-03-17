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

func FZRED_SINGLE_RSDPG(x int) int {
	return (x & 0x7F) + (x >> 7)
}

func FZRED_OPPOSITE_RSDPG(x int) int {
	return x ^ 0x7F
}

func FZRED_DOUBLE_RSDPG(x int) int {
	return FZRED_SINGLE_RSDPG(FZRED_SINGLE_RSDPG(x))
}
func FZ_DOUBLE_ZERO_NORM_RSDPG(x int) int {
	return (x + ((x + 1) >> 7)) & 0x7F
}

func (c *CROSSInstance) fz_inf_w_by_fz_matrix(fz_vec_e, W_mat []byte) []byte {
	if len(fz_vec_e) != c.ProtocolData.M || len(W_mat) != c.ProtocolData.M*(c.ProtocolData.N-c.ProtocolData.M) {
		panic("Invalid input dimensions")
	}
	fz_vec_res := make([]byte, c.ProtocolData.N)

	// Initialize the result vector
	for i := 0; i < c.ProtocolData.N-c.ProtocolData.M; i++ {
		fz_vec_res[i] = 0
	}
	copy(fz_vec_res[c.ProtocolData.N-c.ProtocolData.M:], fz_vec_e)

	// Convert W_mat (flat array) into a 2D matrix representation
	for i := 0; i < c.ProtocolData.M; i++ {
		for j := 0; j < c.ProtocolData.N-c.ProtocolData.M; j++ {
			index := i*(c.ProtocolData.N-c.ProtocolData.M) + j
			fz_vec_res[j] = byte(float64(fz_vec_res[j]) +
				float64(fz_vec_e[i])*float64(W_mat[index])) // FZRED_DOUBLE equivalent
		}
	}

	return fz_vec_res
}

func (c *CROSSInstance) fz_dz_norm_n(v []byte) []int {
	res := make([]int, c.ProtocolData.N)
	for i := 0; i < c.ProtocolData.N; i++ {
		res[i] = FZ_DOUBLE_ZERO_NORM_RSDPG(int(v[i]))
	}
	return res
}

func (c *CROSSInstance) Expand_pk(seed_pk []byte) ([]int, []byte, error) {
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		V_tr, err := c.CSPRNG_fp_mat(seed_pk)
		if err != nil {
			return nil, nil, err
		}
		return V_tr, nil, nil
	} else if c.ProtocolData.Variant() == common.VARIANT_RSDP_G {
		W_mat, state, err := c.CSPRNG_fz_mat(seed_pk)
		if err != nil {
			return nil, nil, err
		}
		V_tr, err := c.CSPRNG_fp_mat_prime(state)
		if err != nil {
			return nil, nil, err
		}
		return V_tr, W_mat, nil
	}
	return nil, nil, fmt.Errorf("Invalid variant")
}

func (c *CROSSInstance) Expand_sk(seed_sk []byte) ([]int, []byte, []byte, []int, error) {
	dsc := uint16(0 + 3*c.ProtocolData.T + 1)
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {

		seed_e_seed_pk, err := c.CSPRNG(seed_sk, (4*c.ProtocolData.Lambda)/8, dsc)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		V_tr, _, err := c.Expand_pk(seed_e_seed_pk[2*c.ProtocolData.Lambda/8:])
		if err != nil {
			return nil, nil, nil, nil, err
		}
		e_bar, err := c.CSPRNG_fz_vec(seed_e_seed_pk[:2*c.ProtocolData.Lambda/8])
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return V_tr, e_bar, nil, nil, nil
	} else if c.ProtocolData.Variant() == common.VARIANT_RSDP_G {
		seed_e_seed_pk, err := c.CSPRNG(seed_sk, (4*c.ProtocolData.Lambda)/8, dsc)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		V_tr, W_mat, err := c.Expand_pk(seed_e_seed_pk[2*c.ProtocolData.Lambda/8:])
		if err != nil {
			return nil, nil, nil, nil, err
		}
		e_G_bar, err := c.CSPRNG_fz_inf_w(seed_e_seed_pk[:2*c.ProtocolData.Lambda/8])
		if err != nil {
			return nil, nil, nil, nil, err
		}
		e_bar := c.fz_inf_w_by_fz_matrix(e_G_bar, W_mat)
		norm_e_bar := c.fz_dz_norm_n(e_bar)
		return V_tr, W_mat, e_G_bar, norm_e_bar, nil
	}
	return nil, nil, nil, nil, fmt.Errorf("Invalid variant")
}

// TODO: Implement the switch case for RSDP-G, along with setting the correct CSPRNG
func (c *CROSSInstance) KeyGen() (KeyPair, error) {
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
func (c *CROSSInstance) DummyKeyGen(seed_sk []byte) (KeyPair, error) {
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
	for j := 0; j < c.ProtocolData.N; j++ {
		// Probably a better way to do this
		e[j] = byte(new(big.Int).Exp(big.NewInt(int64(c.ProtocolData.G)), big.NewInt(int64(e_bar[j])), nil).Int64())
	}

	s := common.MultiplyVectorMatrix(e, common.TransposeByteMatrix(H))
	return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: s}}, nil
}
