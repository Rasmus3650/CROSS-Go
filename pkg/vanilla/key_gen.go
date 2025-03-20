package vanilla

import (
	"PQC-Master-Thesis/internal"
	"PQC-Master-Thesis/internal/common"
	"crypto/rand"
	"fmt"
)

type Pub struct {
	SeedPK []byte
	S      []byte
}

type KeyPair struct {
	Pri []byte
	Pub
}
type FP_ELEM interface {
	~uint8 | ~uint16
}

func FZRED_SINGLE_RSDPG[t FP_ELEM](x t) t {
	return (x & 0x7F) + (x >> 7)
}

func FZRED_OPPOSITE_RSDPG[t FP_ELEM](x t) t {
	return x ^ 0x7F
}

func FZRED_DOUBLE_RSDPG[t FP_ELEM](x t) t {
	return FZRED_SINGLE_RSDPG(FZRED_SINGLE_RSDPG(x))
}
func FZ_DOUBLE_ZERO_NORM_RSDPG(x int) int {
	return (x + ((x + 1) >> 7)) & 0x7F
}

func FPRED_SINGLE[t uint16 | uint32](x t) t {
	return (x & 0x7F) + (x >> 7)
}
func (c *CROSSInstance) FPRED_SINGLE_RSDPG(x uint32) uint32 {
	return uint32(uint64(x) - (((uint64(x) * 2160140723) >> 40) * uint64(c.ProtocolData.P)))
}

// Implement FPRED_DOUBLE
func FPRED_DOUBLE(x uint16) uint16 {
	return FPRED_SINGLE(FPRED_SINGLE(x))
}
func (c *CROSSInstance) FPRED_DOUBLE_RSDPG(x uint32) uint32 {
	return c.FPRED_SINGLE_RSDPG(uint32(x))
}
func FP_DOUBLE_ZERO_NORM(x uint16) uint16 {
	return (x + ((x + 1) >> 7)) & 0x7F
}

func FP_DOUBLE_ZERO_NORM_RSDPG(x uint16) uint16 {
	return x
}

const (
	RESTR_G_TABLE  uint64 = 0x0140201008040201
	RESTR_G_GEN           = 16
	RESTR_G_GEN_1  uint16 = uint16(RESTR_G_GEN)
	RESTR_G_GEN_2  uint16 = 256
	RESTR_G_GEN_4  uint16 = 384
	RESTR_G_GEN_8  uint16 = 355
	RESTR_G_GEN_16 uint16 = 302
	RESTR_G_GEN_32 uint16 = 93
	RESTR_G_GEN_64 uint16 = 505
)

func FP_ELEM_CMOV(bit, trueV, falseV uint16) uint32 {
	mask := uint32(0) - uint32(bit) // 0xFFFF if bit == 1, 0x0000 if bit == 0
	return uint32((mask & uint32(trueV)) | ((^(mask & uint32(bit))) & uint32(falseV)))
}

func (c *CROSSInstance) RESTR_TO_VAL_RSDPG(x uint16) uint32 {
	res1 := (FP_ELEM_CMOV(((x >> 0) & 1), RESTR_G_GEN_1, 1)) *
		(FP_ELEM_CMOV(((x >> 1) & 1), RESTR_G_GEN_2, 1))
	res2 := (FP_ELEM_CMOV(((x >> 2) & 1), RESTR_G_GEN_4, 1)) *
		(FP_ELEM_CMOV(((x >> 3) & 1), RESTR_G_GEN_8, 1))
	res3 := (FP_ELEM_CMOV(((x >> 4) & 1), RESTR_G_GEN_16, 1)) *
		(FP_ELEM_CMOV(((x >> 5) & 1), RESTR_G_GEN_32, 1))
	res4 := FP_ELEM_CMOV(((x >> 6) & 1), RESTR_G_GEN_64, 1)
	return c.FPRED_SINGLE_RSDPG(c.FPRED_SINGLE_RSDPG(uint32(res1)*uint32(res2)) * c.FPRED_SINGLE_RSDPG(uint32(res3)*uint32(res4)))
}

func RESTR_TO_VAL[t FP_ELEM](x t) t {
	return t((RESTR_G_TABLE >> (8 * uint64(x))))
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

func (c *CROSSInstance) generic_pack_9_bit(in []uint16, outlen, inlen int) []uint8 {
	out := make([]uint8, outlen)
	var i int
	for i = range out {
		out[i] = 0
	}
	// Process the input in chunks of 8 elements
	for i = 0; i < inlen/8; i++ {
		out[i*9] = uint8(in[i*8])
		out[i*9+1] = uint8(in[i*8]>>8) | uint8(in[i*8+1]<<1)
		out[i*9+2] = uint8(in[i*8+1]>>7) | uint8(in[i*8+2]<<2)
		out[i*9+3] = uint8(in[i*8+2]>>6) | uint8(in[i*8+3]<<3)
		out[i*9+4] = uint8(in[i*8+3]>>5) | uint8(in[i*8+4]<<4)
		out[i*9+5] = uint8(in[i*8+4]>>4) | uint8(in[i*8+5]<<5)
		out[i*9+6] = uint8(in[i*8+5]>>3) | uint8(in[i*8+6]<<6)
		out[i*9+7] = uint8(in[i*8+6]>>2) | uint8(in[i*8+7]<<7)
		out[i*9+8] = uint8(in[i*8+7] >> 1)
	}

	// Handle the remaining elements if any
	nRemainder := inlen & 0x7
	if nRemainder == 1 {
		out[i*9] = uint8(in[i*8])
		out[i*9+1] |= uint8(in[i*8] >> 8)
	} else if nRemainder == 2 {
		out[i*9] = uint8(in[i*8])
		out[i*9+1] |= uint8(in[i*8] >> 8)
		out[i*9+1] |= uint8(in[i*8+1] << 1)
		out[i*9+2] |= uint8(in[i*8+1] >> 7)
	} else if nRemainder == 3 {
		out[i*9] = uint8(in[i*8])
		out[i*9+1] |= uint8(in[i*8]>>8) | uint8(in[i*8+1]<<1)
		out[i*9+2] |= uint8(in[i*8+1]>>7) | uint8(in[i*8+2]<<2)
		out[i*9+3] |= uint8(in[i*8+2] >> 6)
	} else if nRemainder == 4 {
		out[i*9] = uint8(in[i*8])
		out[i*9+1] |= uint8(in[i*8]>>8) | uint8(in[i*8+1]<<1)
		out[i*9+2] |= uint8(in[i*8+1]>>7) | uint8(in[i*8+2]<<2)
		out[i*9+3] |= uint8(in[i*8+2]>>6) | uint8(in[i*8+3]<<3)
		out[i*9+4] |= uint8(in[i*8+3] >> 5)
	} else if nRemainder == 5 {
		out[i*9] = uint8(in[i*8])
		out[i*9+1] |= uint8(in[i*8]>>8) | uint8(in[i*8+1]<<1)
		out[i*9+2] |= uint8(in[i*8+1]>>7) | uint8(in[i*8+2]<<2)
		out[i*9+3] |= uint8(in[i*8+2]>>6) | uint8(in[i*8+3]<<3)
		out[i*9+4] |= uint8(in[i*8+3]>>5) | uint8(in[i*8+4]<<4)
		out[i*9+5] |= uint8(in[i*8+4] >> 4)
	} else if nRemainder == 6 {
		out[i*9] = uint8(in[i*8])
		out[i*9+1] |= uint8(in[i*8]>>8) | uint8(in[i*8+1]<<1)
		out[i*9+2] |= uint8(in[i*8+1]>>7) | uint8(in[i*8+2]<<2)
		out[i*9+3] |= uint8(in[i*8+2]>>6) | uint8(in[i*8+3]<<3)
		out[i*9+4] |= uint8(in[i*8+3]>>5) | uint8(in[i*8+4]<<4)
		out[i*9+5] |= uint8(in[i*8+4]>>4) | uint8(in[i*8+5]<<5)
		out[i*9+6] |= uint8(in[i*8+5] >> 3)
	} else if nRemainder == 7 {
		out[i*9] = uint8(in[i*8])
		out[i*9+1] |= uint8(in[i*8]>>8) | uint8(in[i*8+1]<<1)
		out[i*9+2] |= uint8(in[i*8+1]>>7) | uint8(in[i*8+2]<<2)
		out[i*9+3] |= uint8(in[i*8+2]>>6) | uint8(in[i*8+3]<<3)
		out[i*9+4] |= uint8(in[i*8+3]>>5) | uint8(in[i*8+4]<<4)
		out[i*9+5] |= uint8(in[i*8+4]>>4) | uint8(in[i*8+5]<<5)
		out[i*9+6] |= uint8(in[i*8+5]>>3) | uint8(in[i*8+6]<<6)
		out[i*9+7] |= uint8(in[i*8+6] >> 2)
	}

	return out
}

func (c *CROSSInstance) generic_pack_fp(input_arr []uint8, out_len, in_len int) []uint8 {
	var res []uint8
	res = c.generic_pack_7_bit(input_arr, out_len, in_len)
	return res
}

func (c *CROSSInstance) generic_pack_fp_RSDPG(input_arr []uint16, out_len, in_len int) []uint8 {
	var res []uint8
	res = c.generic_pack_9_bit(input_arr, out_len, in_len)
	return res
}
func (c *CROSSInstance) Fz_inf_w_by_fz_matrix(fz_vec_e, W_mat []byte) []byte {
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
			fz_vec_res[j] = uint8(FZRED_DOUBLE_RSDPG(uint16(fz_vec_res[j]) + uint16(fz_vec_e[i])*uint16(W_mat[index])))
		}
	}

	return fz_vec_res
}

func (c *CROSSInstance) Fz_dz_norm_n(v []byte) []byte {
	res := make([]byte, c.ProtocolData.N)
	for i := 0; i < c.ProtocolData.N; i++ {
		res[i] = byte(FZ_DOUBLE_ZERO_NORM_RSDPG(int(v[i])))
	}
	return res
}

func (c *CROSSInstance) Restr_vec_by_fp_matrix_RSDPG(e_bar []byte, V_tr []int) []uint16 {
	res := make([]uint16, c.ProtocolData.N-c.ProtocolData.K)
	for i := c.ProtocolData.K; i < c.ProtocolData.N; i++ {
		res[i-c.ProtocolData.K] = uint16(c.RESTR_TO_VAL_RSDPG(uint16(e_bar[i])))
	}
	for i := 0; i < c.ProtocolData.K; i++ {
		for j := 0; j < c.ProtocolData.N-c.ProtocolData.K; j++ {
			res[j] = uint16(c.FPRED_DOUBLE_RSDPG(uint32(res[j]) + uint32(c.RESTR_TO_VAL_RSDPG(uint16(e_bar[i])))*uint32(V_tr[i*(c.ProtocolData.N-c.ProtocolData.K)+j])))

		}
	}
	return res
}

func (c *CROSSInstance) Restr_vec_by_fp_matrix(e_bar []byte, V_tr []int) []uint8 {
	res := make([]uint8, c.ProtocolData.N-c.ProtocolData.K)
	for i := c.ProtocolData.K; i < c.ProtocolData.N; i++ {
		res[i-c.ProtocolData.K] = RESTR_TO_VAL(uint8(e_bar[i]))
	}
	for i := 0; i < c.ProtocolData.K; i++ {
		for j := 0; j < c.ProtocolData.N-c.ProtocolData.K; j++ {
			//TODO: Fix this tomorrow
			res[j] = uint8(FPRED_DOUBLE(uint16(res[j]) + uint16(RESTR_TO_VAL(uint8(e_bar[i])))*uint16(V_tr[i*(c.ProtocolData.N-c.ProtocolData.K)+j])))
		}
	}
	return res
}

func (c *CROSSInstance) Fp_dz_norm_synd(s []uint8) []uint8 {
	result := make([]uint8, c.ProtocolData.N-c.ProtocolData.K)
	for i := 0; i < c.ProtocolData.N-c.ProtocolData.K; i++ {
		result[i] = uint8(FP_DOUBLE_ZERO_NORM(uint16(s[i])))
	}
	return result
}

func (c *CROSSInstance) Fp_dz_norm_synd_RSDPG(s []uint16) []uint16 {
	result := make([]uint16, c.ProtocolData.N-c.ProtocolData.K)
	for i := 0; i < c.ProtocolData.N-c.ProtocolData.K; i++ {
		result[i] = uint16(FP_DOUBLE_ZERO_NORM_RSDPG(s[i]))
	}
	return result
}

func (c *CROSSInstance) denselyPackedFpSynSize() uint {
	// Calculate the number of bits required to represent P-1
	bits := internal.BitsToRepresent(uint(c.ProtocolData.P - 1))

	// First part of the formula: ((N-K)/8) * BITS_TO_REPRESENT(P-1)
	part1 := uint(((c.ProtocolData.N - c.ProtocolData.K) / 8) * bits)

	// Second part: ROUND_UP(((N-K)%8) * BITS_TO_REPRESENT(P-1), 8) / 8
	part2 := internal.RoundUp(uint(((c.ProtocolData.N-c.ProtocolData.K)%8)*bits), 8) / 8

	// Total size
	return part1 + part2
}

func (c *CROSSInstance) Pack_fp_syn(s []uint8) []byte {
	return c.generic_pack_fp(s, int(c.denselyPackedFpSynSize()), c.ProtocolData.N-c.ProtocolData.K)
}

func (c *CROSSInstance) Pack_fp_syn_RSDPG(s []uint16) []byte {
	return c.generic_pack_fp_RSDPG(s, int(c.denselyPackedFpSynSize()), c.ProtocolData.N-c.ProtocolData.K)
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

func (c *CROSSInstance) Expand_sk(seed_sk []byte) ([]int, []byte, []byte, []byte, error) {
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
		e_bar := c.Fz_inf_w_by_fz_matrix(e_G_bar, W_mat)
		norm_e_bar := c.Fz_dz_norm_n(e_bar)
		return V_tr, W_mat, e_G_bar, norm_e_bar, nil
	}
	return nil, nil, nil, nil, fmt.Errorf("Invalid variant")
}

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
	V_tr, W_mat, err := c.Expand_pk(seed_pk)
	if err != nil {
		return KeyPair{}, err
	}
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		e_bar, err := c.CSPRNG_fz_vec(seed_e)
		if err != nil {
			return KeyPair{}, err
		}
		temp_s := c.Restr_vec_by_fp_matrix(e_bar, V_tr)
		s := c.Fp_dz_norm_synd(temp_s)
		S := c.Pack_fp_syn(s)
		return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: S}}, nil

	} else {
		e_G_bar, err := c.CSPRNG_fz_inf_w(seed_e)
		if err != nil {
			return KeyPair{}, err
		}
		e_bar := c.Fz_inf_w_by_fz_matrix(e_G_bar, W_mat)
		e_bar = c.Fz_dz_norm_n(e_bar)
		temp_s := c.Restr_vec_by_fp_matrix_RSDPG(e_bar, V_tr)
		s := c.Fp_dz_norm_synd_RSDPG(temp_s)
		S := c.Pack_fp_syn_RSDPG(s)
		return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: S}}, nil
	}
}

// Dummy KeyGen function for testing purposes ONLY
func (c *CROSSInstance) DummyKeyGen(seed_sk []byte) (KeyPair, error) {

	seed_e_pk, err := c.CSPRNG(seed_sk, (4*c.ProtocolData.Lambda)/8, uint16(0+3*c.ProtocolData.T+1))
	seed_e := seed_e_pk[:2*c.ProtocolData.Lambda/8]
	seed_pk := seed_e_pk[2*c.ProtocolData.Lambda/8:]
	V_tr, W_mat, err := c.Expand_pk(seed_pk)
	if err != nil {
		return KeyPair{}, err
	}
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		e_bar, err := c.CSPRNG_fz_vec(seed_e)
		if err != nil {
			return KeyPair{}, err
		}
		temp_s := c.Restr_vec_by_fp_matrix(e_bar, V_tr)
		s := c.Fp_dz_norm_synd(temp_s)
		S := c.Pack_fp_syn(s)
		return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: S}}, nil

	} else {
		e_G_bar, err := c.CSPRNG_fz_inf_w(seed_e)
		if err != nil {
			return KeyPair{}, err
		}
		e_bar := c.Fz_inf_w_by_fz_matrix(e_G_bar, W_mat)
		e_bar = c.Fz_dz_norm_n(e_bar)
		temp_s := c.Restr_vec_by_fp_matrix_RSDPG(e_bar, V_tr)
		s := c.Fp_dz_norm_synd_RSDPG(temp_s)
		S := c.Pack_fp_syn_RSDPG(s)
		return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: S}}, nil
	}
}
