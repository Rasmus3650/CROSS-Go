package internal

import "PQC-Master-Thesis/internal/common"

func FPRED_SINGLE[t uint16 | uint32](x t) t {
	return (x & 0x7F) + (x >> 7)
}
func (c *CROSS) FPRED_SINGLE_RSDPG(x uint32) uint32 {
	return uint32(uint64(x) - (((uint64(x) * 2160140723) >> 40) * uint64(c.ProtocolData.P)))
}

func FPRED_DOUBLE(x uint16) uint16 {
	return FPRED_SINGLE(FPRED_SINGLE(x))
}
func (c *CROSS) FPRED_DOUBLE_RSDPG(x uint32) uint32 {
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

func (c *CROSS) RESTR_TO_VAL_RSDPG(x uint16) uint32 {
	res1 := (FP_ELEM_CMOV(((x >> 0) & 1), RESTR_G_GEN_1, 1)) *
		(FP_ELEM_CMOV(((x >> 1) & 1), RESTR_G_GEN_2, 1))
	res2 := (FP_ELEM_CMOV(((x >> 2) & 1), RESTR_G_GEN_4, 1)) *
		(FP_ELEM_CMOV(((x >> 3) & 1), RESTR_G_GEN_8, 1))
	res3 := (FP_ELEM_CMOV(((x >> 4) & 1), RESTR_G_GEN_16, 1)) *
		(FP_ELEM_CMOV(((x >> 5) & 1), RESTR_G_GEN_32, 1))
	res4 := FP_ELEM_CMOV(((x >> 6) & 1), RESTR_G_GEN_64, 1)
	return c.FPRED_SINGLE_RSDPG(c.FPRED_SINGLE_RSDPG(uint32(res1)*uint32(res2)) * c.FPRED_SINGLE_RSDPG(uint32(res3)*uint32(res4)))
}

func RESTR_TO_VAL(x uint8) uint8 {
	return uint8((RESTR_G_TABLE >> (8 * uint64(x))))
}

func (c *CROSS) Fp_dz_norm_synd(s []uint8) []uint8 {
	result := make([]uint8, c.ProtocolData.N-c.ProtocolData.K)
	for i := 0; i < c.ProtocolData.N-c.ProtocolData.K; i++ {
		result[i] = uint8(FP_DOUBLE_ZERO_NORM(uint16(s[i])))
	}
	return result
}

func (c *CROSS) Fp_dz_norm_synd_RSDPG(s []uint16) []uint16 {
	result := make([]uint16, c.ProtocolData.N-c.ProtocolData.K)
	for i := 0; i < c.ProtocolData.N-c.ProtocolData.K; i++ {
		result[i] = uint16(FP_DOUBLE_ZERO_NORM_RSDPG(s[i]))
	}
	return result
}

func (c *CROSS) Convert_restr_vec_to_fp(in []byte) []byte {
	result := make([]byte, c.ProtocolData.N)
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		for i := 0; i < c.ProtocolData.N; i++ {
			result[i] = byte(RESTR_TO_VAL(uint8(in[i])))
		}
	} else {
		for i := 0; i < c.ProtocolData.N; i++ {
			result[i] = byte(c.RESTR_TO_VAL_RSDPG(uint16(in[i])))
		}
	}
	return result
}

func (c *CROSS) Fp_vec_by_fp_vec_pointwise(a, b []byte) []byte {
	//TODO: Probably needs to be generic types instead of bytes
	result := make([]byte, c.ProtocolData.N)
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		for i := 0; i < c.ProtocolData.N; i++ {
			result[i] = byte(c.FPRED_DOUBLE_RSDPG(uint32(RESTR_TO_VAL(a[i])) * uint32(b[i])))
		}
	} else {
		for i := 0; i < c.ProtocolData.N; i++ {
			result[i] = byte(FPRED_DOUBLE(uint16(RESTR_TO_VAL(a[i])) * uint16(b[i])))
		}
	}
	return result
}

func (c *CROSS) Fp_vec_by_fp_matrix(e, V_tr []byte) []byte {
	result := make([]byte, c.ProtocolData.N-c.ProtocolData.K)
	copy(result, e[c.ProtocolData.K:])
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		for i := 0; i < c.ProtocolData.K; i++ {
			for j := 0; j < c.ProtocolData.N-c.ProtocolData.K; j++ {
				result[j] = byte(FPRED_DOUBLE(uint16(result[j]) + uint16(e[i])*uint16(V_tr[i*(c.ProtocolData.N-c.ProtocolData.K)+j])))
			}
		}
	} else {
		//TODO: Probably needs to be generic types instead of bytes
		for i := 0; i < c.ProtocolData.K; i++ {
			for j := 0; j < c.ProtocolData.N-c.ProtocolData.K; j++ {
				result[j] = byte(c.FPRED_DOUBLE_RSDPG(uint32(result[j]) + uint32(e[i])*uint32(V_tr[i*(c.ProtocolData.N-c.ProtocolData.K)+j])))
			}
		}
	}
	return result
}
