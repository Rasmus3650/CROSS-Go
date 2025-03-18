package vanilla

import (
	"PQC-Master-Thesis/internal"
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

func FPRED_SINGLE(x uint16) uint16 {
	return (x & 0x7F) + (x >> 7)
}

// Implement FPRED_DOUBLE
func FPRED_DOUBLE(x uint16) uint16 {
	return FPRED_SINGLE(FPRED_SINGLE(x))
}
func FP_DOUBLE_ZERO_NORM(x uint16) uint16 {
	return (x + ((x + 1) >> 7)) & 0x7F
}

const RESTR_G_TABLE uint64 = 0x0140201008040201

// Function to implement RESTR_TO_VAL
func RESTR_TO_VAL(x uint8) uint8 {
	return uint8((RESTR_G_TABLE >> (8 * x)) & 0xFF)
}

func (c *CROSSInstance) generic_pack_7_bit(in []uint8, outlen, inlen int) []uint8 {
	out := make([]byte, outlen) // Allocate the output array

	// Process full 8-byte blocks
	for i := 0; i < inlen/8; i++ {
		out[i*7] = in[i*8] | (in[i*8+1] << 7)
		out[i*7+1] = (in[i*8+1] >> 1) | (in[i*8+2] << 6)
		out[i*7+2] = (in[i*8+2] >> 2) | (in[i*8+3] << 5)
		out[i*7+3] = (in[i*8+3] >> 3) | (in[i*8+4] << 4)
		out[i*7+4] = (in[i*8+4] >> 4) | (in[i*8+5] << 3)
		out[i*7+5] = (in[i*8+5] >> 5) | (in[i*8+6] << 2)
		out[i*7+6] = (in[i*8+6] >> 6) | (in[i*8+7] << 1)
	}

	// Process remaining bytes
	remainder := inlen % 8
	i := inlen / 8
	if remainder > 0 {
		out[i*7] = in[i*8]
		if remainder > 1 {
			out[i*7] |= in[i*8+1] << 7
			out[i*7+1] = in[i*8+1] >> 1
		}
		if remainder > 2 {
			out[i*7+1] |= in[i*8+2] << 6
			out[i*7+2] = in[i*8+2] >> 2
		}
		if remainder > 3 {
			out[i*7+2] |= in[i*8+3] << 5
			out[i*7+3] = in[i*8+3] >> 3
		}
		if remainder > 4 {
			out[i*7+3] |= in[i*8+4] << 4
			out[i*7+4] = in[i*8+4] >> 4
		}
		if remainder > 5 {
			out[i*7+4] |= in[i*8+5] << 3
			out[i*7+5] = in[i*8+5] >> 5
		}
		if remainder > 6 {
			out[i*7+5] |= in[i*8+6] << 2
			out[i*7+6] = in[i*8+6] >> 6
		}
	}

	return out
}

func (c *CROSSInstance) generic_pack_9_bit(in []uint8, outlen, inlen int) []uint8 {
	out := make([]uint8, outlen)
	for i := range out {
		out[i] = 0
	}
	// Process the input in chunks of 8 elements
	for i := 0; i < inlen/8; i++ {
		out[i*9] = uint8(in[i*8])
		out[i*9+1] |= uint8(in[i*8]) >> 8
		out[i*9+1] |= uint8(in[i*8+1]) << 1
		out[i*9+2] |= uint8(in[i*8+1]) >> 7
		out[i*9+2] |= uint8(in[i*8+2]) << 2
		out[i*9+3] |= uint8(in[i*8+2]) >> 6
		out[i*9+3] |= uint8(in[i*8+3]) << 3
		out[i*9+4] |= uint8(in[i*8+3]) >> 5
		out[i*9+4] |= uint8(in[i*8+4]) << 4
		out[i*9+5] |= uint8(in[i*8+4]) >> 4
		out[i*9+5] |= uint8(in[i*8+5]) << 5
		out[i*9+6] |= uint8(in[i*8+5]) >> 3
		out[i*9+6] |= uint8(in[i*8+6]) << 6
		out[i*9+7] |= uint8(in[i*8+6]) >> 2
		out[i*9+8] |= uint8(in[i*8+7]) >> 1
	}

	// Handle the remaining elements if any
	nRemainder := inlen % 8
	if nRemainder == 1 {
		out[(inlen/8)*9] = uint8(in[(inlen/8)*8])
		out[(inlen/8)*9+1] |= uint8(in[(inlen/8)*8]) >> 8
	} else if nRemainder == 2 {
		out[(inlen/8)*9] = uint8(in[(inlen/8)*8])
		out[(inlen/8)*9+1] |= uint8(in[(inlen/8)*8]) >> 8
		out[(inlen/8)*9+1] |= uint8(in[(inlen/8)*8+1]) << 1
		out[(inlen/8)*9+2] |= uint8(in[(inlen/8)*8+1]) >> 7
	} else if nRemainder == 3 {
		out[(inlen/8)*9] = uint8(in[(inlen/8)*8])
		out[(inlen/8)*9+1] |= uint8(in[(inlen/8)*8]) >> 8
		out[(inlen/8)*9+1] |= uint8(in[(inlen/8)*8+1]) << 1
		out[(inlen/8)*9+2] |= uint8(in[(inlen/8)*8+1]) >> 7
		out[(inlen/8)*9+2] |= uint8(in[(inlen/8)*8+2]) << 2
		out[(inlen/8)*9+3] |= uint8(in[(inlen/8)*8+2]) >> 6
	} else if nRemainder == 4 {
		out[(inlen/8)*9] = uint8(in[(inlen/8)*8])
		out[(inlen/8)*9+1] |= uint8(in[(inlen/8)*8]) >> 8
		out[(inlen/8)*9+1] |= uint8(in[(inlen/8)*8+1]) << 1
		out[(inlen/8)*9+2] |= uint8(in[(inlen/8)*8+1]) >> 7
		out[(inlen/8)*9+2] |= uint8(in[(inlen/8)*8+2]) << 2
		out[(inlen/8)*9+3] |= uint8(in[(inlen/8)*8+2]) >> 6
		out[(inlen/8)*9+4] |= uint8(in[(inlen/8)*8+3]) << 3
	} else if nRemainder == 5 {
		out[(inlen/8)*9] = uint8(in[(inlen/8)*8])
		out[(inlen/8)*9+1] |= uint8(in[(inlen/8)*8]) >> 8
		out[(inlen/8)*9+1] |= uint8(in[(inlen/8)*8+1]) << 1
		out[(inlen/8)*9+2] |= uint8(in[(inlen/8)*8+1]) >> 7
		out[(inlen/8)*9+2] |= uint8(in[(inlen/8)*8+2]) << 2
		out[(inlen/8)*9+3] |= uint8(in[(inlen/8)*8+2]) >> 6
		out[(inlen/8)*9+4] |= uint8(in[(inlen/8)*8+3]) << 3
		out[(inlen/8)*9+5] |= uint8(in[(inlen/8)*8+4]) << 4
	} else if nRemainder == 6 {
		out[(inlen/8)*9] = uint8(in[(inlen/8)*8])
		out[(inlen/8)*9+1] |= uint8(in[(inlen/8)*8]) >> 8
		out[(inlen/8)*9+1] |= uint8(in[(inlen/8)*8+1]) << 1
		out[(inlen/8)*9+2] |= uint8(in[(inlen/8)*8+1]) >> 7
		out[(inlen/8)*9+2] |= uint8(in[(inlen/8)*8+2]) << 2
		out[(inlen/8)*9+3] |= uint8(in[(inlen/8)*8+2]) >> 6
		out[(inlen/8)*9+4] |= uint8(in[(inlen/8)*8+3]) << 3
		out[(inlen/8)*9+5] |= uint8(in[(inlen/8)*8+4]) << 4
		out[(inlen/8)*9+6] |= uint8(in[(inlen/8)*8+5]) << 5
	} else if nRemainder == 7 {
		out[(inlen/8)*9] = uint8(in[(inlen/8)*8])
		out[(inlen/8)*9+1] |= uint8(in[(inlen/8)*8]) >> 8
		out[(inlen/8)*9+1] |= uint8(in[(inlen/8)*8+1]) << 1
		out[(inlen/8)*9+2] |= uint8(in[(inlen/8)*8+1]) >> 7
		out[(inlen/8)*9+2] |= uint8(in[(inlen/8)*8+2]) << 2
		out[(inlen/8)*9+3] |= uint8(in[(inlen/8)*8+2]) >> 6
		out[(inlen/8)*9+4] |= uint8(in[(inlen/8)*8+3]) << 3
		out[(inlen/8)*9+5] |= uint8(in[(inlen/8)*8+4]) << 4
		out[(inlen/8)*9+6] |= uint8(in[(inlen/8)*8+5]) << 5
		out[(inlen/8)*9+7] |= uint8(in[(inlen/8)*8+6]) << 6
	}

	return out
}

func (c *CROSSInstance) generic_pack_fp(input_arr []uint8, out_len, in_len int) []uint8 {
	var res []uint8
	if c.ProtocolData.P == 127 {
		res = c.generic_pack_7_bit(input_arr, out_len, in_len)
	} else if c.ProtocolData.P == 509 {
		res = c.generic_pack_9_bit(input_arr, out_len, in_len)
	}
	return res
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

func (c *CROSSInstance) restr_vec_by_fp_matrix(e_bar []byte, V_tr []int) []uint8 {
	res := make([]uint8, c.ProtocolData.N-c.ProtocolData.K)
	for i := c.ProtocolData.K; i < c.ProtocolData.N; i++ {
		res[i-c.ProtocolData.K] = RESTR_TO_VAL(uint8(e_bar[i]))
	}
	for i := 0; i < c.ProtocolData.K; i++ {
		for j := 0; j < c.ProtocolData.N-c.ProtocolData.K; j++ {
			res[j] = uint8(FPRED_DOUBLE(uint16(res[j]) + uint16(RESTR_TO_VAL(uint8(e_bar[i]))) + uint16(V_tr[i*(c.ProtocolData.N-c.ProtocolData.K)+j])))
		}
	}
	return res
}

func (c *CROSSInstance) fp_dz_norm_synd(s []uint8) []uint8 {
	for i := 0; i < c.ProtocolData.N-c.ProtocolData.K; i++ {
		s[i] = uint8(FP_DOUBLE_ZERO_NORM(uint16(s[i])))
	}
	return s
}

func (c *CROSSInstance) denselyPackedFpSynSize() uint {
	// Calculate the number of bits required to represent P-1
	bits := internal.BitsToRepresent(uint(c.ProtocolData.P - 1))

	// First part of the formula: ((N-K)/8) * BITS_TO_REPRESENT(P-1)
	part1 := uint((c.ProtocolData.N - c.ProtocolData.K) / 8 * bits)

	// Second part: ROUND_UP(((N-K)%8) * BITS_TO_REPRESENT(P-1), 8) / 8
	part2 := internal.RoundUp(uint(((c.ProtocolData.N-c.ProtocolData.K)%8)*bits), 8) / 8

	// Total size
	return part1 + part2
}

func (c *CROSSInstance) pack_fp_syn(s []uint8) []byte {
	return c.generic_pack_fp(s, int(c.denselyPackedFpSynSize()), c.ProtocolData.N-c.ProtocolData.K)
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
		return KeyPair{}, err
	}
	seed_e_pk, err := c.CSPRNG(seed_sk, (4*c.ProtocolData.Lambda)/8, uint16(0+3*c.ProtocolData.T+1))
	if err != nil {
		return KeyPair{}, err
	}
	seed_e := seed_e_pk[:2*c.ProtocolData.Lambda/8]
	seed_pk := seed_e_pk[2*c.ProtocolData.Lambda/8:]
	V_tr, _, err := c.Expand_pk(seed_pk)
	if err != nil {
		return KeyPair{}, err
	}
	var e_bar []byte
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		e_bar, err = c.CSPRNG_fz_vec(seed_e)
		if err != nil {
			return KeyPair{}, err
		}
	} else {
		//TODO: Implement e_G_bar for RSDP-G, requires correct fz_inf_w, and fx_dz_norm_n
		_, err := c.CSPRNG_fz_inf_w(seed_e)
		if err != nil {
			return KeyPair{}, err
		}
	}
	temp_s := c.restr_vec_by_fp_matrix(e_bar, V_tr)
	s := c.fp_dz_norm_synd(temp_s)
	S := c.pack_fp_syn(s)
	return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: S}}, nil
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
