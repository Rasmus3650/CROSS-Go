package internal

func FZRED_SINGLE_RSDPG(x uint16) uint16 {
	return (x & 0x7F) + (x >> 7)
}

func FZRED_OPPOSITE_RSDPG(x uint16) uint16 {
	return x ^ 0x7F
}

func FZRED_DOUBLE_RSDPG(x uint16) uint16 {
	return FZRED_SINGLE_RSDPG(FZRED_SINGLE_RSDPG(x))
}
func FZ_DOUBLE_ZERO_NORM_RSDPG(x int) int {
	return (x + ((x + 1) >> 7)) & 0x7F
}

func (c *CROSS) Fz_inf_w_by_fz_matrix(fz_vec_e, W_mat []byte) []byte {
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

func (c *CROSS) Fz_dz_norm_n(v []byte) []byte {
	res := make([]byte, c.ProtocolData.N)
	for i := 0; i < c.ProtocolData.N; i++ {
		res[i] = byte(FZ_DOUBLE_ZERO_NORM_RSDPG(int(v[i])))
	}
	return res
}
func (c *CROSS) Fz_dz_norm_m(v []byte) []byte {
	res := make([]byte, c.ProtocolData.M)
	for i := 0; i < c.ProtocolData.M; i++ {
		res[i] = byte(FZ_DOUBLE_ZERO_NORM_RSDPG(int(v[i])))
	}
	return res
}
func (c *CROSS) Fz_vec_sub_n(a []int, b []byte) []byte {
	result := make([]byte, c.ProtocolData.N)
	for i := 0; i < c.ProtocolData.N; i++ {
		//TODO: TEST AND MAYBE FIX, SHOULD PROBABLY BE uint8
		result[i] = byte(FZRED_SINGLE_RSDPG(uint16(a[i]) + FZRED_OPPOSITE_RSDPG(uint16(b[i]))))
	}
	return result
}

func (c *CROSS) Fz_vec_sub_m(a, b []byte) []byte {
	result := make([]byte, c.ProtocolData.M)
	for i := 0; i < c.ProtocolData.M; i++ {
		//TODO: TEST AND MAYBE FIX, SHOULD PROBABLY BE uint8
		result[i] = byte(FZRED_SINGLE_RSDPG(uint16(a[i]) + FZRED_OPPOSITE_RSDPG(uint16(b[i]))))
	}
	return result
}

func (c *CROSS) Restr_vec_by_fp_matrix_RSDPG(e_bar []byte, V_tr []int) []uint16 {
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

func (c *CROSS) Restr_vec_by_fp_matrix(e_bar []byte, V_tr []int) []uint8 {
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
