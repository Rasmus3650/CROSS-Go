package internal

func (c *CROSS) generic_pack_7_bit(in []uint8, outlen, inlen int) []uint8 {
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

func (c *CROSS) generic_pack_9_bit(in []uint16, outlen, inlen int) []uint8 {
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

func (c *CROSS) generic_pack_fp(input_arr []uint8, out_len, in_len int) []uint8 {
	var res []uint8
	res = c.generic_pack_7_bit(input_arr, out_len, in_len)
	return res
}

func (c *CROSS) generic_pack_fp_RSDPG(input_arr []uint16, out_len, in_len int) []uint8 {
	var res []uint8
	res = c.generic_pack_9_bit(input_arr, out_len, in_len)
	return res
}

func (c *CROSS) denselyPackedFpSynSize() uint {
	// Calculate the number of bits required to represent P-1
	bits := BitsToRepresent(uint(c.ProtocolData.P - 1))

	// First part of the formula: ((N-K)/8) * BITS_TO_REPRESENT(P-1)
	part1 := uint(((c.ProtocolData.N - c.ProtocolData.K) / 8) * bits)

	// Second part: ROUND_UP(((N-K)%8) * BITS_TO_REPRESENT(P-1), 8) / 8
	part2 := RoundUp(uint(((c.ProtocolData.N-c.ProtocolData.K)%8)*bits), 8) / 8

	// Total size
	return part1 + part2
}

func (c *CROSS) Pack_fp_syn(s []uint8) []byte {
	return c.generic_pack_fp(s, int(c.denselyPackedFpSynSize()), c.ProtocolData.N-c.ProtocolData.K)
}

func (c *CROSS) Pack_fp_syn_RSDPG(s []uint16) []byte {
	return c.generic_pack_fp_RSDPG(s, int(c.denselyPackedFpSynSize()), c.ProtocolData.N-c.ProtocolData.K)
}

func (c *CROSS) Pack_fz_vec(input []byte) []byte{
	return c.generic_pack_fz(input, c.DenselyPackedFzVecSize(), c.ProtocolData.N)
}

func (c *CROSS) generic_pack_3_bit(in []byte, out_len, in_len int) []byte {
	out := make([]byte, out_len)
	var i int
	for i = 0; i < out_len; i++ {
		out[i] = 0
	}
	for i = 0; i < in_len/8; i++ {
		out[i*3]   = in[i*8] | (in[i*8+1] << 3) | (in[i*8+2] << 6)
    	out[i*3+1]  = (in[i*8+2] >> 2) | (in[i*8+3] << 1) | (in[i*8+4] << 4) | (in[i*8+5] << 7)
    	out[i*3+2]  = (in[i*8+5] >> 1) | (in[i*8+6] << 2) | (in[i*8+7] << 5)
	}
	n_remainder := uint(in_len) & 0x7
	if n_remainder == 1 {
		out[i*3] = in[i*8]
	} else if n_remainder == 2 {
		out[i*3] = in[i*8] | (in[i*8+1] << 3)
	} else if n_remainder == 3 {
		out[i*3] = in[i*8] | (in[i*8+1] << 3) | (in[i*8+2] << 6)
		out[i*3+1] = (in[i*8+2] >> 2)
	} else if n_remainder == 4{
		out[i*3]   = in[i*8] | (in[i*8+1] << 3) | (in[i*8+2] << 6)
    	out[i*3+1] = (in[i*8+2] >> 2)  | (in[i*8+3] << 1)
	} else if n_remainder == 5 {
		out[i*3]   = in[i*8] | (in[i*8+1] << 3) | (in[i*8+2] << 6)
    	out[i*3+1] = (in[i*8+2] >> 2)  | (in[i*8+3] << 1) | (in[i*8+4] << 4)
	} else if n_remainder == 6 {
		out[i*3]   = in[i*8] | (in[i*8+1] << 3) | (in[i*8+2] << 6)
   		out[i*3+1] = (in[i*8+2] >> 2) | (in[i*8+3] << 1) | (in[i*8+4] << 4) | (in[i*8+5] << 7)
    	out[i*3+2] = (in[i*8+5] >> 1)
	} else if n_remainder == 7 {
		out[i*3]   = in[i*8] | (in[i*8+1] << 3) | (in[i*8+2] << 6)
    	out[i*3+1] = (in[i*8+2] >> 2) | (in[i*8+3] << 1) | (in[i*8+4] << 4) | (in[i*8+5] << 7)
    	out[i*3+2] = (in[i*8+5] >> 1) | (in[i*8+6] << 2)
	}
	return out
}

func (c *CROSS) generic_pack_fz(input_arr []byte, out_len, in_len int) []byte {
	if c.ProtocolData.Z == 127{
		return c.generic_pack_7_bit(input_arr, out_len, in_len)
	} else if c.ProtocolData.Z == 7 {
		return c.generic_pack_3_bit(input_arr, out_len, in_len)
	} else {
		panic("Unsupported Z value")
	}
}

func (c *CROSS) Pack_fz_rsdpg_vec(in []byte) []byte{
	return c.generic_pack_fz(in, c.DenselyPackedFzRSDPGVecSize(), c.ProtocolData.M)
}
func (c *CROSS) Pack_fp_vec (in []byte) []byte{
	return c.generic_pack_fp(in, c.DenselyPackedFpVecSize(), c.ProtocolData.N)
}