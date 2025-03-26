package internal

import "PQC-Master-Thesis/internal/common"

func (c *CROSS[T, P]) FZRED_SINGLE(x T) T {
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		return (x & 0x07) + (x >> 3)
	} else {
		return (x & 0x7F) + (x >> 7)
	}
}

func (c *CROSS[T, P]) FZRED_OPPOSITE(x T) T {
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		return x ^ 0x07
	} else {
		return x ^ 0x7F
	}
}

func (c *CROSS[T, P]) FZRED_DOUBLE(x T) T {
	return c.FZRED_SINGLE(c.FZRED_SINGLE(x))
}
func (c *CROSS[T, P]) FZ_DOUBLE_ZERO_NORM(x int) int {
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		return (((x) + (((x) + 1) >> 3)) & 0x07)
	} else {
		return (((x) + (((x) + 1) >> 7)) & 0x7f)
	}

}

func (c *CROSS[T, P]) DenselyPackedFzVecSize() int {
	return (c.ProtocolData.N/8)*BitsToRepresent(uint(c.ProtocolData.Z-1)) + int(RoundUp(uint((c.ProtocolData.N%8)*BitsToRepresent(uint(c.ProtocolData.Z-1))), 8)/8)
}

func (c *CROSS[T, P]) DenselyPackedFpVecSize() int {
	return (c.ProtocolData.N/8)*BitsToRepresent(uint(c.ProtocolData.P-1)) + int(RoundUp(uint((c.ProtocolData.N%8)*BitsToRepresent(uint(c.ProtocolData.P-1))), 8)/8)
}
func (c *CROSS[T, P]) DenselyPackedFzRSDPGVecSize() int {
	return (c.ProtocolData.M/8)*BitsToRepresent(uint(c.ProtocolData.Z-1)) + int(RoundUp(uint((c.ProtocolData.M%8)*BitsToRepresent(uint(c.ProtocolData.Z-1))), 8)/8)
	//((M/8)*BITS_TO_REPRESENT(Z-1) + ROUND_UP( ((M%8)*BITS_TO_REPRESENT(Z-1)),8)/8)
}

func (c *CROSS[T, P]) Fz_inf_w_by_fz_matrix(fz_vec_e, W_mat []byte) []byte {
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
			fz_vec_res[j] = byte(c.FZRED_DOUBLE(T(uint16(fz_vec_res[j]) + uint16(fz_vec_e[i])*uint16(W_mat[index]))))
		}
	}
	return fz_vec_res
}

func (c *CROSS[T, P]) Fz_dz_norm_n(v []byte) []byte {
	res := make([]byte, c.ProtocolData.N)
	for i := 0; i < c.ProtocolData.N; i++ {
		res[i] = byte(c.FZ_DOUBLE_ZERO_NORM(int(v[i])))
	}
	return res
}
func (c *CROSS[T, P]) Fz_dz_norm_m(v []byte) []byte {
	res := make([]byte, c.ProtocolData.M)
	for i := 0; i < c.ProtocolData.M; i++ {
		res[i] = byte(c.FZ_DOUBLE_ZERO_NORM(int(v[i])))
	}
	return res
}
func (c *CROSS[T, P]) Fz_vec_sub_n(a []int, b []byte) []byte {
	result := make([]byte, c.ProtocolData.N)
	for i := 0; i < c.ProtocolData.N; i++ {
		//TODO: TEST AND MAYBE FIX, SHOULD PROBABLY BE uint8
		result[i] = byte(c.FZRED_SINGLE(T(a[i]) + c.FZRED_OPPOSITE(T(b[i]))))
	}
	return result
}

func (c *CROSS[T, P]) Fz_vec_sub_m(a, b []byte) []byte {
	result := make([]byte, c.ProtocolData.M)
	for i := 0; i < c.ProtocolData.M; i++ {
		result[i] = byte(c.FZRED_SINGLE(T(a[i]) + c.FZRED_OPPOSITE(T(b[i]))))
	}
	return result
}
