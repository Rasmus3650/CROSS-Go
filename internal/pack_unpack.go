package internal

import (
	"PQC-Master-Thesis/internal/common"
)

func (c *CROSS[T, P]) generic_pack_7_bit(in []T, outlen, inlen int) []uint8 {
	out := make([]byte, outlen) // Allocate the output array

	// Process full 8-byte blocks
	for i := 0; i < inlen/8; i++ {
		out[i*7] = uint8(in[i*8]) | (uint8(in[i*8+1]) << 7)
		out[i*7+1] = (uint8(in[i*8+1]) >> 1) | (uint8(in[i*8+2]) << 6)
		out[i*7+2] = (uint8(in[i*8+2]) >> 2) | (uint8(in[i*8+3]) << 5)
		out[i*7+3] = (uint8(in[i*8+3]) >> 3) | (uint8(in[i*8+4]) << 4)
		out[i*7+4] = (uint8(in[i*8+4]) >> 4) | (uint8(in[i*8+5]) << 3)
		out[i*7+5] = (uint8(in[i*8+5]) >> 5) | (uint8(in[i*8+6]) << 2)
		out[i*7+6] = (uint8(in[i*8+6]) >> 6) | (uint8(in[i*8+7]) << 1)
	}

	// Process remaining bytes
	remainder := inlen % 8
	i := inlen / 8
	if remainder > 0 {
		out[i*7] = uint8(in[i*8])
		if remainder > 1 {
			out[i*7] |= uint8(in[i*8+1]) << 7
			out[i*7+1] = uint8(in[i*8+1]) >> 1
		}
		if remainder > 2 {
			out[i*7+1] |= uint8(in[i*8+2]) << 6
			out[i*7+2] = uint8(in[i*8+2]) >> 2
		}
		if remainder > 3 {
			out[i*7+2] |= uint8(in[i*8+3]) << 5
			out[i*7+3] = uint8(in[i*8+3]) >> 3
		}
		if remainder > 4 {
			out[i*7+3] |= uint8(in[i*8+4]) << 4
			out[i*7+4] = uint8(in[i*8+4]) >> 4
		}
		if remainder > 5 {
			out[i*7+4] |= uint8(in[i*8+5]) << 3
			out[i*7+5] = uint8(in[i*8+5]) >> 5
		}
		if remainder > 6 {
			out[i*7+5] |= uint8(in[i*8+6]) << 2
			out[i*7+6] = uint8(in[i*8+6]) >> 6
		}
	}

	return out
}

func (c *CROSS[T, P]) generic_pack_9_bit(in []T, outlen, inlen int) []uint8 {
	//TODO: Figure out why this works????
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

func (c *CROSS[T, P]) generic_pack_fp(input_arr []T, out_len, in_len int) []uint8 {
	var res []uint8
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		res = c.generic_pack_7_bit(input_arr, out_len, in_len)
	} else {
		res = c.generic_pack_9_bit(input_arr, out_len, in_len)

	}
	return res
}

func (c *CROSS[T, P]) DenselyPackedFpSynSize() uint {
	// Calculate the number of bits required to represent P-1
	bits := BitsToRepresent(uint(c.ProtocolData.P - 1))

	// First part of the formula: ((N-K)/8) * BITS_TO_REPRESENT(P-1)
	part1 := uint(((c.ProtocolData.N - c.ProtocolData.K) / 8) * bits)

	// Second part: ROUND_UP(((N-K)%8) * BITS_TO_REPRESENT(P-1), 8) / 8
	part2 := RoundUp(uint(((c.ProtocolData.N-c.ProtocolData.K)%8)*bits), 8) / 8

	// Total size
	return part1 + part2
}

func (c *CROSS[T, P]) Pack_fp_syn(s []T) []byte {
	return c.generic_pack_fp(s, int(c.DenselyPackedFpSynSize()), c.ProtocolData.N-c.ProtocolData.K)
}

func (c *CROSS[T, P]) Pack_fz_vec(input []T) []byte {
	return c.generic_pack_fz(input, c.DenselyPackedFzVecSize(), c.ProtocolData.N)
}

func (c *CROSS[T, P]) generic_pack_3_bit(in []T, out_len, in_len int) []byte {
	out := make([]byte, out_len)
	var i int
	for i = 0; i < out_len; i++ {
		out[i] = 0
	}
	for i = 0; i < in_len/8; i++ {
		out[i*3] = uint8(in[i*8]) | (uint8(in[i*8+1]) << 3) | (uint8(in[i*8+2]) << 6)
		out[i*3+1] = (uint8(in[i*8+2]) >> 2) | (uint8(in[i*8+3]) << 1) | (uint8(in[i*8+4]) << 4) | (uint8(in[i*8+5]) << 7)
		out[i*3+2] = (uint8(in[i*8+5]) >> 1) | (uint8(in[i*8+6]) << 2) | (uint8(in[i*8+7]) << 5)
	}
	n_remainder := uint(in_len) & 0x7
	if n_remainder == 1 {
		out[i*3] = uint8(in[i*8])
	} else if n_remainder == 2 {
		out[i*3] = uint8(in[i*8]) | (uint8(in[i*8+1]) << 3)
	} else if n_remainder == 3 {
		out[i*3] = uint8(in[i*8]) | (uint8(in[i*8+1]) << 3) | (uint8(in[i*8+2]) << 6)
		out[i*3+1] = (uint8(in[i*8+2]) >> 2)
	} else if n_remainder == 4 {
		out[i*3] = uint8(in[i*8]) | (uint8(in[i*8+1]) << 3) | (uint8(in[i*8+2]) << 6)
		out[i*3+1] = (uint8(in[i*8+2]) >> 2) | (uint8(in[i*8+3]) << 1)
	} else if n_remainder == 5 {
		out[i*3] = uint8(in[i*8]) | (uint8(in[i*8+1]) << 3) | (uint8(in[i*8+2]) << 6)
		out[i*3+1] = (uint8(in[i*8+2]) >> 2) | (uint8(in[i*8+3]) << 1) | (uint8(in[i*8+4]) << 4)
	} else if n_remainder == 6 {
		out[i*3] = uint8(in[i*8]) | (uint8(in[i*8+1]) << 3) | (uint8(in[i*8+2]) << 6)
		out[i*3+1] = (uint8(in[i*8+2]) >> 2) | (uint8(in[i*8+3]) << 1) | (uint8(in[i*8+4]) << 4) | (uint8(in[i*8+5]) << 7)
		out[i*3+2] = (uint8(in[i*8+5]) >> 1)
	} else if n_remainder == 7 {
		out[i*3] = uint8(in[i*8]) | (uint8(in[i*8+1]) << 3) | (uint8(in[i*8+2]) << 6)
		out[i*3+1] = (uint8(in[i*8+2]) >> 2) | (uint8(in[i*8+3]) << 1) | (uint8(in[i*8+4]) << 4) | (uint8(in[i*8+5]) << 7)
		out[i*3+2] = (uint8(in[i*8+5]) >> 1) | (uint8(in[i*8+6]) << 2)
	}
	return out
}

func (c *CROSS[T, P]) generic_pack_fz(input_arr []T, out_len, in_len int) []byte {
	if c.ProtocolData.Z == 127 {
		return c.generic_pack_7_bit(input_arr, out_len, in_len)
	} else if c.ProtocolData.Z == 7 {
		return c.generic_pack_3_bit(input_arr, out_len, in_len)
	} else {
		panic("Unsupported Z value")
	}
}

func (c *CROSS[T, P]) Pack_fz_rsdpg_vec(in []T) []byte {
	return c.generic_pack_fz(in, c.DenselyPackedFzRSDPGVecSize(), c.ProtocolData.M)
}
func (c *CROSS[T, P]) Pack_fp_vec(in []T) []byte {
	return c.generic_pack_fp(in, c.DenselyPackedFpVecSize(), c.ProtocolData.N)
}

func (c *CROSS[T, P]) generic_unpack_9_bit(inp []byte, outlen int, inlen uint) ([]T, bool) {
	is_packed_padd_ok := true
	var i int
	in := make([]uint16, inlen)
	for i, val := range inp {
		in[i] = uint16(val)
	}

	out := make([]uint16, outlen)
	for i = 0; i < outlen; i++ {
		out[i] = 0
	}
	for i = 0; i < int(inlen)/9; i++ {
		out[i*8] = (in[i*9] | (in[i*9+1] << 8)) & 0x1FF
		out[i*8+1] = ((in[i*9+1] >> 1) | (in[i*9+2] << 7)) & 0x1FF
		out[i*8+2] = ((in[i*9+2] >> 2) | (in[i*9+3] << 6)) & 0x1FF
		out[i*8+3] = ((in[i*9+3] >> 3) | (in[i*9+4] << 5)) & 0x1FF
		out[i*8+4] = ((in[i*9+4] >> 4) | (in[i*9+5] << 4)) & 0x1FF
		out[i*8+5] = ((in[i*9+5] >> 5) | (in[i*9+6] << 3)) & 0x1FF
		out[i*8+6] = ((in[i*9+6] >> 6) | (in[i*9+7] << 2)) & 0x1FF
		out[i*8+7] = ((in[i*9+7] >> 7) | (in[i*9+8] << 1)) & 0x1FF
	}
	n_remainder := outlen & 0x7
	switch n_remainder {
	case 1:
		out[i*8] = (in[i*9] | (in[i*9+1] << 8)) & 0x1FF
	case 2:
		out[i*8] = (in[i*9] | (in[i*9+1] << 8)) & 0x1FF
		out[i*8+1] = ((in[i*9+1] >> 1) | (in[i*9+2] << 7)) & 0x1FF
	case 3:
		out[i*8] = (in[i*9] | (in[i*9+1] << 8)) & 0x1FF
		out[i*8+1] = ((in[i*9+1] >> 1) | (in[i*9+2] << 7)) & 0x1FF
		out[i*8+2] = ((in[i*9+2] >> 2) | (in[i*9+3] << 6)) & 0x1FF
	case 4:
		out[i*8] = (in[i*9] | (in[i*9+1] << 8)) & 0x1FF
		out[i*8+1] = ((in[i*9+1] >> 1) | (in[i*9+2] << 7)) & 0x1FF
		out[i*8+2] = ((in[i*9+2] >> 2) | (in[i*9+3] << 6)) & 0x1FF
		out[i*8+3] = ((in[i*9+3] >> 3) | (in[i*9+4] << 5)) & 0x1FF
	case 5:
		out[i*8] = (in[i*9] | (in[i*9+1] << 8)) & 0x1FF
		out[i*8+1] = ((in[i*9+1] >> 1) | (in[i*9+2] << 7)) & 0x1FF
		out[i*8+2] = ((in[i*9+2] >> 2) | (in[i*9+3] << 6)) & 0x1FF
		out[i*8+3] = ((in[i*9+3] >> 3) | (in[i*9+4] << 5)) & 0x1FF
		out[i*8+4] = ((in[i*9+4] >> 4) | (in[i*9+5] << 4)) & 0x1FF
	case 6:
		out[i*8] = (in[i*9] | (in[i*9+1] << 8)) & 0x1FF
		out[i*8+1] = ((in[i*9+1] >> 1) | (in[i*9+2] << 7)) & 0x1FF
		out[i*8+2] = ((in[i*9+2] >> 2) | (in[i*9+3] << 6)) & 0x1FF
		out[i*8+3] = ((in[i*9+3] >> 3) | (in[i*9+4] << 5)) & 0x1FF
		out[i*8+4] = ((in[i*9+4] >> 4) | (in[i*9+5] << 4)) & 0x1FF
		out[i*8+5] = ((in[i*9+5] >> 5) | (in[i*9+6] << 3)) & 0x1FF
	case 7:
		out[i*8] = (in[i*9] | (in[i*9+1] << 8)) & 0x1FF
		out[i*8+1] = ((in[i*9+1] >> 1) | (in[i*9+2] << 7)) & 0x1FF
		out[i*8+2] = ((in[i*9+2] >> 2) | (in[i*9+3] << 6)) & 0x1FF
		out[i*8+3] = ((in[i*9+3] >> 3) | (in[i*9+4] << 5)) & 0x1FF
		out[i*8+4] = ((in[i*9+4] >> 4) | (in[i*9+5] << 4)) & 0x1FF
		out[i*8+5] = ((in[i*9+5] >> 5) | (in[i*9+6] << 3)) & 0x1FF
		out[i*8+6] = ((in[i*9+6] >> 6) | (in[i*9+7] << 2)) & 0x1FF
	}
	if n_remainder > 0 {
		is_packed_padd_ok = ((in[inlen-1] & (0xFF << n_remainder)) == 0)
	}
	result := make([]T, outlen)
	for i := range out {
		result[i] = T(out[i])
	}
	return result, is_packed_padd_ok
}
func (c *CROSS[T, P]) generic_unpack_3_bit(in []byte, outlen int, inlen uint) ([]byte, bool) {
	is_packed_padd_ok := true
	var i int
	out := make([]byte, outlen)
	for i = 0; i < outlen; i++ {
		out[i] = 0
	}
	for i = 0; i < outlen/8; i++ {
		out[i*8] = in[i*3] & 0x7
		out[i*8+1] = (in[i*3] >> 3) & 0x7
		out[i*8+2] = ((in[i*3] >> 6) | (in[i*3+1] << 2)) & 0x7
		out[i*8+3] = (in[i*3+1] >> 1) & 0x7
		out[i*8+4] = (in[i*3+1] >> 4) & 0x7
		out[i*8+5] = ((in[i*3+1] >> 7) | (in[i*3+2] << 1)) & 0x7
		out[i*8+6] = (in[i*3+2] >> 2) & 0x7
		out[i*8+7] = (in[i*3+2] >> 5) & 0x7
	}
	n_remainder := outlen & 0x7
	switch n_remainder {
	case 1:
		out[i*8] = in[i*3] & 0x7

	case 2:
		out[i*8] = in[i*3] & 0x7
		out[i*8+1] = (in[i*3] >> 3) & 0x7
	case 3:
		out[i*8] = in[i*3] & 0x7
		out[i*8+1] = (in[i*3] >> 3) & 0x7
		out[i*8+2] = ((in[i*3] >> 6) | (in[i*3+1] << 2)) & 0x7
	case 4:
		out[i*8] = in[i*3] & 0x7
		out[i*8+1] = (in[i*3] >> 3) & 0x7
		out[i*8+2] = ((in[i*3] >> 6) | (in[i*3+1] << 2)) & 0x7
		out[i*8+3] = (in[i*3+1] >> 1) & 0x7
	case 5:
		out[i*8] = in[i*3] & 0x7
		out[i*8+1] = (in[i*3] >> 3) & 0x7
		out[i*8+2] = ((in[i*3] >> 6) | (in[i*3+1] << 2)) & 0x7
		out[i*8+3] = (in[i*3+1] >> 1) & 0x7
		out[i*8+4] = (in[i*3+1] >> 4) & 0x7
	case 6:
		out[i*8] = in[i*3] & 0x7
		out[i*8+1] = (in[i*3] >> 3) & 0x7
		out[i*8+2] = ((in[i*3] >> 6) | (in[i*3+1] << 2)) & 0x7
		out[i*8+3] = (in[i*3+1] >> 1) & 0x7
		out[i*8+4] = (in[i*3+1] >> 4) & 0x7
		out[i*8+5] = ((in[i*3+1] >> 7) | (in[i*3+2] << 1)) & 0x7
	case 7:
		out[i*8] = in[i*3] & 0x7
		out[i*8+1] = (in[i*3] >> 3) & 0x7
		out[i*8+2] = ((in[i*3] >> 6) | (in[i*3+1] << 2)) & 0x7
		out[i*8+3] = (in[i*3+1] >> 1) & 0x7
		out[i*8+4] = (in[i*3+1] >> 4) & 0x7
		out[i*8+5] = ((in[i*3+1] >> 7) | (in[i*3+2] << 1)) & 0x7
		out[i*8+6] = (in[i*3+2] >> 2) & 0x7
	}
	if n_remainder > 0 {
		is_packed_padd_ok = ((in[inlen-1] & (0xFF << (n_remainder * 3) & 0x7)) == 0)
	}
	return out, is_packed_padd_ok
}

func (c *CROSS[T, P]) generic_unpack_7_bit(in []byte, outlen int, inlen uint) ([]byte, bool) {
	is_packed_padd_ok := true
	var i int
	out := make([]byte, outlen)
	for i = 0; i < outlen; i++ {
		out[i] = 0
	}
	for i = 0; i < outlen/8; i++ {
		out[i*8] = in[i*7] & 0x7F
		out[i*8+1] = (in[i*7] >> 7) | ((in[i*7+1] << 1) & 0x7F)
		out[i*8+2] = (in[i*7+1] >> 6) | ((in[i*7+2] << 2) & 0x7F)
		out[i*8+3] = (in[i*7+2] >> 5) | ((in[i*7+3] << 3) & 0x7F)
		out[i*8+4] = (in[i*7+3] >> 4) | ((in[i*7+4] << 4) & 0x7F)
		out[i*8+5] = (in[i*7+4] >> 3) | ((in[i*7+5] << 5) & 0x7F)
		out[i*8+6] = (in[i*7+5] >> 2) | ((in[i*7+6] << 6) & 0x7F)
		out[i*8+7] = in[i*7+6] >> 1
	}
	n_remainder := outlen & 0x7
	switch n_remainder {
	case 1:
		out[i*8] = in[i*7] & 0x7F
	case 2:
		out[i*8] = in[i*7] & 0x7F
		out[i*8+1] = (in[i*7] >> 7) | ((in[i*7+1] << 1) & 0x7F)
	case 3:
		out[i*8] = in[i*7] & 0x7F
		out[i*8+1] = (in[i*7] >> 7) | ((in[i*7+1] << 1) & 0x7F)
		out[i*8+2] = (in[i*7+1] >> 6) | ((in[i*7+2] << 2) & 0x7F)
	case 4:
		out[i*8] = in[i*7] & 0x7F
		out[i*8+1] = (in[i*7] >> 7) | ((in[i*7+1] << 1) & 0x7F)
		out[i*8+2] = (in[i*7+1] >> 6) | ((in[i*7+2] << 2) & 0x7F)
		out[i*8+3] = (in[i*7+2] >> 5) | ((in[i*7+3] << 3) & 0x7F)
	case 5:
		out[i*8] = in[i*7] & 0x7F
		out[i*8+1] = (in[i*7] >> 7) | ((in[i*7+1] << 1) & 0x7F)
		out[i*8+2] = (in[i*7+1] >> 6) | ((in[i*7+2] << 2) & 0x7F)
		out[i*8+3] = (in[i*7+2] >> 5) | ((in[i*7+3] << 3) & 0x7F)
		out[i*8+4] = (in[i*7+3] >> 4) | ((in[i*7+4] << 4) & 0x7F)
	case 6:
		out[i*8] = in[i*7] & 0x7F
		out[i*8+1] = (in[i*7] >> 7) | ((in[i*7+1] << 1) & 0x7F)
		out[i*8+2] = (in[i*7+1] >> 6) | ((in[i*7+2] << 2) & 0x7F)
		out[i*8+3] = (in[i*7+2] >> 5) | ((in[i*7+3] << 3) & 0x7F)
		out[i*8+4] = (in[i*7+3] >> 4) | ((in[i*7+4] << 4) & 0x7F)
		out[i*8+5] = (in[i*7+4] >> 3) | ((in[i*7+5] << 5) & 0x7F)
	case 7:
		out[i*8] = in[i*7] & 0x7F
		out[i*8+1] = (in[i*7] >> 7) | ((in[i*7+1] << 1) & 0x7F)
		out[i*8+2] = (in[i*7+1] >> 6) | ((in[i*7+2] << 2) & 0x7F)
		out[i*8+3] = (in[i*7+2] >> 5) | ((in[i*7+3] << 3) & 0x7F)
		out[i*8+4] = (in[i*7+3] >> 4) | ((in[i*7+4] << 4) & 0x7F)
		out[i*8+5] = (in[i*7+4] >> 3) | ((in[i*7+5] << 5) & 0x7F)
		out[i*8+6] = (in[i*7+5] >> 2) | ((in[i*7+6] << 6) & 0x7F)
	}
	if n_remainder > 0 {
		is_packed_padd_ok = ((in[inlen-1] & (0xFF << (8 - n_remainder))) == 0)
	}
	return out, is_packed_padd_ok
}
func (c *CROSS[T, P]) byteToT(arr []byte) []T {
	res := make([]T, len(arr))
	for i := range arr {
		res[i] = T(arr[i])
	}
	return res
}

func (c *CROSS[T, P]) generic_unpack_fp(in []byte, outlen int, inlen uint) ([]T, bool) {
	is_packed_padd_ok := true
	var result []T
	var temp []byte
	if c.ProtocolData.P == 127 {
		temp, is_packed_padd_ok = c.generic_unpack_7_bit(in, outlen, inlen)
		result = c.byteToT(temp)
	} else if c.ProtocolData.P == 509 {
		result, is_packed_padd_ok = c.generic_unpack_9_bit(in, outlen, inlen)
	}
	return result, is_packed_padd_ok
}

func (c *CROSS[T, P]) Unpack_fp_syn(s []byte) ([]T, bool) {
	return c.generic_unpack_fp(s, c.ProtocolData.N-c.ProtocolData.K, c.DenselyPackedFpSynSize())
}

func (c *CROSS[T, P]) Unpack_fp_vec(vec []byte) ([]T, bool) {
	return c.generic_unpack_fp(vec, c.ProtocolData.N, uint(c.DenselyPackedFpVecSize()))
}

func (c *CROSS[T, P]) generic_unpack_fz(in []byte, outlen int, inlen uint) ([]byte, bool) {
	is_packed_padd_ok := true
	var result []byte
	if c.ProtocolData.Z == 127 {
		result, is_packed_padd_ok = c.generic_unpack_7_bit(in, outlen, inlen)
	} else if c.ProtocolData.Z == 7 {
		result, is_packed_padd_ok = c.generic_unpack_3_bit(in, outlen, inlen)
	}
	return result, is_packed_padd_ok
}

func (c *CROSS[T, P]) Unpack_fz_vec(vec []byte) ([]byte, bool) {
	return c.generic_unpack_fz(vec, c.ProtocolData.N, uint(c.DenselyPackedFzVecSize()))
}

func (c *CROSS[T, P]) Unpack_fz_rsdp_g_vec(vec []byte) ([]byte, bool) {
	return c.generic_unpack_fz(vec, c.ProtocolData.M, uint(c.DenselyPackedFzRSDPGVecSize()))
}
