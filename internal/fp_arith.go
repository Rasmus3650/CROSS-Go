package internal

import (
	"github.com/Rasmus3650/CROSS-Go/internal/common"
)

func (c *CROSS[T, P]) FPRED_SINGLE(x P) P {
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		return (x & 0x7F) + (x >> 7)
	} else {
		return P(uint64(x) - (((uint64(x) * 2160140723) >> 40) * uint64(c.ProtocolData.P)))
	}
}

func (c *CROSS[T, P]) FPRED_DOUBLE(x P) P {
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		return c.FPRED_SINGLE(c.FPRED_SINGLE(x))
	} else {
		return c.FPRED_SINGLE(x)
	}
}
func (c *CROSS[T, P]) FP_DOUBLE_ZERO_NORM(x P) P {
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		return (x + ((x + 1) >> 7)) & 0x7F
	} else {
		return x
	}
}

func (c *CROSS[T, P]) FPRED_OPPOSITE(x P) P {
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		return (x ^ 0x7F)
	} else {
		return c.FPRED_SINGLE(FP_DOUBLE_PREC[T, P](T(c.ProtocolData.P)) - x)
	}
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

func (c *CROSS[T, P]) FP_ELEM_CMOV(bit T, trueV, falseV uint16) uint32 {
	mask := uint32(0) - uint32(bit) // 0xFFFF if bit == 1, 0x0000 if bit == 0
	return uint32((mask & uint32(trueV)) | ((^(mask & uint32(bit))) & uint32(falseV)))
}

// Might be returning uint16 instead of 8 in RSDP
func (c *CROSS[T, P]) RESTR_TO_VAL(x T) P {
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		return P((RESTR_G_TABLE >> (8 * uint64(x))))
	} else {
		res1 := (c.FP_ELEM_CMOV(((x >> 0) & 1), RESTR_G_GEN_1, 1)) *
			(c.FP_ELEM_CMOV(((x >> 1) & 1), RESTR_G_GEN_2, 1))
		res2 := (c.FP_ELEM_CMOV(((x >> 2) & 1), RESTR_G_GEN_4, 1)) *
			(c.FP_ELEM_CMOV(((x >> 3) & 1), RESTR_G_GEN_8, 1))
		res3 := (c.FP_ELEM_CMOV(((x >> 4) & 1), RESTR_G_GEN_16, 1)) *
			(c.FP_ELEM_CMOV(((x >> 5) & 1), RESTR_G_GEN_32, 1))
		res4 := c.FP_ELEM_CMOV(((x >> 6) & 1), RESTR_G_GEN_64, 1)
		return c.FPRED_SINGLE(c.FPRED_SINGLE(P(uint32(res1)*uint32(res2))) * c.FPRED_SINGLE(P(uint32(res3)*uint32(res4))))
	}
}

func (c *CROSS[T, P]) Fp_dz_norm_synd(s []T) []T {
	result := make([]T, c.ProtocolData.N-c.ProtocolData.K)
	for i := 0; i < c.ProtocolData.N-c.ProtocolData.K; i++ {
		result[i] = T(c.FP_DOUBLE_ZERO_NORM(FP_DOUBLE_PREC[T, P](s[i])))
	}
	return result
}

func (c *CROSS[T, P]) Fp_dz_norm(s []T) []T {
	result := make([]T, c.ProtocolData.N)
	for i := 0; i < c.ProtocolData.N; i++ {
		result[i] = T(c.FP_DOUBLE_ZERO_NORM(FP_DOUBLE_PREC[T, P](s[i])))
	}
	return result
}

func (c *CROSS[T, P]) Convert_restr_vec_to_fp(in []byte) []T {
	result := make([]T, c.ProtocolData.N)
	for i := 0; i < c.ProtocolData.N; i++ {
		result[i] = T(c.RESTR_TO_VAL(T(in[i])))
	}
	return result
}

func (c *CROSS[T, P]) Fp_vec_by_fp_vec_pointwise(a, b []T) []P {
	result := make([]P, c.ProtocolData.N)
	for i := 0; i < c.ProtocolData.N; i++ {
		result[i] = P(c.FPRED_DOUBLE(FP_DOUBLE_PREC[T, P](T(a[i])) * FP_DOUBLE_PREC[T, P](b[i])))
	}
	return result
}

func (c *CROSS[T, P]) Fp_vec_by_restr_vec_scaled(e, u_prime []T, chall_1 T) []T {
	result := make([]T, c.ProtocolData.N)
	for i := 0; i < c.ProtocolData.N; i++ {
		result[i] = T(c.FPRED_DOUBLE(FP_DOUBLE_PREC[T, P](u_prime[i]) + FP_DOUBLE_PREC[T, P](T(c.RESTR_TO_VAL(e[i])))*FP_DOUBLE_PREC[T, P](chall_1)))
	}
	return result
}

func (c *CROSS[T, P]) Restr_vec_by_fp_matrix(e_bar []byte, V_tr []P) []T {
	res := make([]T, c.ProtocolData.N-c.ProtocolData.K)
	for i := c.ProtocolData.K; i < c.ProtocolData.N; i++ {
		res[i-c.ProtocolData.K] = T(c.RESTR_TO_VAL(T(e_bar[i])))
	}
	for i := 0; i < c.ProtocolData.K; i++ {
		for j := 0; j < c.ProtocolData.N-c.ProtocolData.K; j++ {
			res[j] = T(c.FPRED_DOUBLE(FP_DOUBLE_PREC[T, P](res[j]) + FP_DOUBLE_PREC[T, P](T(c.RESTR_TO_VAL(T(e_bar[i]))))*V_tr[i*(c.ProtocolData.N-c.ProtocolData.K)+j]))
		}
	}
	return res
}

/*
	 Original version
		func (c *CROSS[T, P]) Fp_vec_by_fp_matrix(e, V_tr []T) []T {
				result := make([]T, c.ProtocolData.N-c.ProtocolData.K)
				copy(result, e[c.ProtocolData.K:])
				for i := 0; i < c.ProtocolData.K; i++ {
					e_i := FP_DOUBLE_PREC[T, P](e[i])
					for j := 0; j < c.ProtocolData.N-c.ProtocolData.K; j++ {
						result[j] = T(c.FPRED_DOUBLE(FP_DOUBLE_PREC[T, P](result[j]) + e_i*FP_DOUBLE_PREC[T, P](V_tr[i * (c.ProtocolData.N - c.ProtocolData.K)+j])))
					}
				}

				return result
			}

		Optimized version but fails tests

	func (c *CROSS[T, P]) Fp_vec_by_fp_matrix(e, V_tr []T) []T {
		result := make([]T, c.ProtocolData.N-c.ProtocolData.K)
		copy(result, e[c.ProtocolData.K:])

		// Precompute values outside the loop that don't change
		nMinusK := c.ProtocolData.N - c.ProtocolData.K
		var wg sync.WaitGroup

		for i := 0; i < c.ProtocolData.K; i++ {
			// Using a closure to capture 'i' and pass it to the goroutine
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				e_i := FP_DOUBLE_PREC[T, P](e[i])

				// We calculate the base index once per iteration of i to avoid redundant multiplication
				baseIdx := i * nMinusK
				for j := 0; j < nMinusK; j++ {
					// Fetch value from V_tr and apply the computation
					VtrValue := FP_DOUBLE_PREC[T, P](V_tr[baseIdx+j])
					result[j] = T(c.FPRED_DOUBLE(FP_DOUBLE_PREC[T, P](result[j]) + e_i*VtrValue))
				}
			}(i)
		}
		wg.Wait()

		return result
	}

	func (c *CROSS[T, P]) Fp_vec_by_fp_matrix(e, V_tr []T) []T {
		result := make([]T, c.ProtocolData.N-c.ProtocolData.K)
		first_val := (c.ProtocolData.N - c.ProtocolData.K)
		copy(result, e[c.ProtocolData.K:])
		for i := 0; i < c.ProtocolData.K; i++ {
			idx := i * first_val
			e_i := FP_DOUBLE_PREC[T, P](e[i])
			for j := 0; j < first_val; j++ {
				result[j] = T(c.FPRED_DOUBLE(FP_DOUBLE_PREC[T, P](result[j]) + e_i*FP_DOUBLE_PREC[T, P](V_tr[idx+j])))
			}
		}

		return result
	}
*/
func (c *CROSS[T, P]) Fp_vec_by_fp_matrix(e, V_tr []P) []T {
	n_minus_k := c.ProtocolData.N - c.ProtocolData.K
	res_dprec := make([]P, n_minus_k)
	for i := 0; i < n_minus_k; i++ {
		res_dprec[i] = e[c.ProtocolData.K+i]
	}
	for i := 0; i < c.ProtocolData.K; i++ {
		idx := i * (n_minus_k)
		for j := 0; j < n_minus_k; j++ {
			res_dprec[j] += c.FPRED_SINGLE(e[i] * V_tr[idx+j])
			if i == c.ProtocolData.P-1 {
				res_dprec[j] = c.FPRED_SINGLE(res_dprec[j])
			}
		}
	}
	res := make([]T, c.ProtocolData.N-c.ProtocolData.K)
	for i := 0; i < c.ProtocolData.N-c.ProtocolData.K; i++ {
		res[i] = T(c.FPRED_SINGLE(res_dprec[i]))
	}
	return res
}

func (c *CROSS[T, P]) Fp_synd_minus_fp_vec_scaled(y_prime_H []T, chall_1 T, s []T) []T {
	result := make([]T, c.ProtocolData.N-c.ProtocolData.K)
	for j := 0; j < c.ProtocolData.N-c.ProtocolData.K; j++ {
		tmp := c.FPRED_DOUBLE(FP_DOUBLE_PREC[T, P](s[j]) * FP_DOUBLE_PREC[T, P](chall_1))
		tmp = c.FP_DOUBLE_ZERO_NORM(tmp)
		result[j] = T(c.FPRED_SINGLE(FP_DOUBLE_PREC[T, P](y_prime_H[j]) + c.FPRED_OPPOSITE(tmp)))
	}
	return result
}
