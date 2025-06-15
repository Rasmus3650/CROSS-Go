package common

import (
	"math"

	"golang.org/x/crypto/sha3"
)

func (c *CROSS[T, P]) CSPRNG_state(state sha3.ShakeHash, output_len int) ([]byte, sha3.ShakeHash) {
	output := make([]byte, output_len)
	state.Read(output)
	return output, state
}

func (c *CROSS[T, P]) CSPRNG(seed []byte, output_len int, dsc uint16) []byte {
	var shake sha3.ShakeHash
	if c.ProtocolData.Level() == 1 {
		shake = sha3.NewShake128()
	} else {
		shake = sha3.NewShake256()
	}
	shake.Write(seed)
	// Prepare the dsc value in little-endian byte order
	dscOrdered := []byte{
		byte(dsc & 0xff),        // low byte
		byte((dsc >> 8) & 0xff), // high byte
	}

	shake.Write(dscOrdered)
	output := make([]byte, output_len)
	shake.Read(output)
	return output
}

func (c *CROSS[T, P]) CSPRNG_prime(seed []byte, output_len int, dsc uint16) ([]byte, sha3.ShakeHash) {
	var shake sha3.ShakeHash
	if c.ProtocolData.Level() == 1 {
		shake = sha3.NewShake128()
	} else {
		shake = sha3.NewShake256()
	}
	shake.Write(seed)
	// Prepare the dsc value in little-endian byte order
	dscOrdered := []byte{
		byte(dsc & 0xff),        // low byte
		byte((dsc >> 8) & 0xff), // high byte
	}

	shake.Write(dscOrdered)
	output := make([]byte, output_len)
	shake.Read(output)
	return output, shake
}

func (c *CROSS[T, P]) CSPRNG_init(seed []byte, dsc uint16) sha3.ShakeHash {
	var shake sha3.ShakeHash
	if c.ProtocolData.Level() == 1 {
		shake = sha3.NewShake128()
	} else {
		shake = sha3.NewShake256()
	}
	shake.Write(seed)
	// Prepare the dsc value in little-endian byte order
	dscOrdered := []byte{
		byte(dsc & 0xff),        // low byte
		byte((dsc >> 8) & 0xff), // high byte
	}

	shake.Write(dscOrdered)
	return shake
}

func isRepresentableInDBits(d, n uint) int {
	if n >= (1<<(d-1)) && n < (1<<d) {
		return int(d)
	}
	return -1
}

func BitsToRepresent(n uint) int {
	if n == 0 {
		return 1
	}

	result := 15
	for d := uint(1); d <= 16; d++ {
		result += isRepresentableInDBits(d, n)
	}
	return result
}
func RoundUp(amount, roundAmt uint) uint {
	return ((amount + roundAmt - 1) / roundAmt) * roundAmt
}

func (c *CROSS[T, P]) CSPRNG_fp_mat(seed []byte) []P {
	res := make([]P, c.ProtocolData.K*(c.ProtocolData.N-c.ProtocolData.K))
	// TODO: uint16 for RSDP-G, uint8 for RSDP
	FP_ELEM_mask := (uint(1) << BitsToRepresent(uint(c.ProtocolData.P-1))) - 1
	//CSPRNG_buffer := make([]uint8, RoundUp(uint(bitsVCTRng), 8)/8)
	BITS_FOR_P := BitsToRepresent(uint(c.ProtocolData.P - 1))
	//TODO: Switch case on the dsc + the real value
	dsc := uint16(3*c.ProtocolData.T + 2)
	CSPRNG_buffer := c.CSPRNG(seed, int(RoundUp(uint(c.ProtocolData.BITS_V_CT_RNG), 8)/8), dsc)
	placed := 0
	sub_buffer := uint64(0)
	for i := 0; i < 8; i++ {
		sub_buffer |= uint64(CSPRNG_buffer[i]) << uint64(8*i)
	}
	bits_in_sub_buf := 64
	pos_in_buf := 8
	pos_remaining := len(CSPRNG_buffer) - pos_in_buf
	for placed < c.ProtocolData.K*(c.ProtocolData.N-c.ProtocolData.K) {
		if bits_in_sub_buf <= 32 && pos_remaining > 0 {
			refresh_amount := int(math.Min(4, float64(pos_remaining)))
			refresh_buf := uint32(0)
			for i := 0; i < refresh_amount; i++ {
				refresh_buf |= uint32(CSPRNG_buffer[pos_in_buf+i]) << byte(8*i)
			}
			pos_in_buf += refresh_amount
			sub_buffer |= uint64(refresh_buf) << uint64(bits_in_sub_buf)
			bits_in_sub_buf += 8 * refresh_amount
			pos_remaining -= refresh_amount
		}
		res[placed] = P(sub_buffer & uint64(FP_ELEM_mask))
		if res[placed] < P(c.ProtocolData.P) {
			placed++
		}
		sub_buffer >>= BITS_FOR_P
		bits_in_sub_buf -= BITS_FOR_P
	}
	return res
}

func (c *CROSS[T, P]) CSPRNG_fp_mat_prime(state sha3.ShakeHash) []P {
	res := make([]P, c.ProtocolData.K*(c.ProtocolData.N-c.ProtocolData.K))
	// TODO: uint16 for RSDP-G, uint8 for RSDP
	FP_ELEM_mask := (uint(1) << BitsToRepresent(uint(c.ProtocolData.P-1))) - 1
	//CSPRNG_buffer := make([]uint8, RoundUp(uint(bitsVCTRng), 8)/8)
	BITS_FOR_P := BitsToRepresent(uint(c.ProtocolData.P - 1))
	//TODO: Switch case on the dsc + the real value
	CSPRNG_buffer := make([]byte, int(RoundUp(uint(c.ProtocolData.BITS_V_CT_RNG), 8)/8))
	state.Read(CSPRNG_buffer)
	placed := 0
	sub_buffer := uint64(0)
	for i := 0; i < 8; i++ {
		sub_buffer |= uint64(CSPRNG_buffer[i]) << uint64(8*i)
	}
	bits_in_sub_buf := 64
	pos_in_buf := 8
	pos_remaining := len(CSPRNG_buffer) - pos_in_buf
	for placed < c.ProtocolData.K*(c.ProtocolData.N-c.ProtocolData.K) {
		if bits_in_sub_buf <= 32 && pos_remaining > 0 {
			refresh_amount := int(math.Min(4, float64(pos_remaining)))
			refresh_buf := uint32(0)
			for i := 0; i < refresh_amount; i++ {
				refresh_buf |= uint32(CSPRNG_buffer[pos_in_buf+i]) << byte(8*i)
			}
			pos_in_buf += refresh_amount
			sub_buffer |= uint64(refresh_buf) << uint64(bits_in_sub_buf)
			bits_in_sub_buf += 8 * refresh_amount
			pos_remaining -= refresh_amount
		}
		res[placed] = P(sub_buffer & uint64(FP_ELEM_mask))
		if res[placed] < P(c.ProtocolData.P) {
			placed++
		}
		sub_buffer >>= BITS_FOR_P
		bits_in_sub_buf -= BITS_FOR_P
	}
	return res
}

func (c *CROSS[T, P]) CSPRNG_fp_vec(seed []byte) []byte {
	res := make([]byte, c.ProtocolData.N)
	FP_ELEM_mask := (uint8(1) << BitsToRepresent(uint(c.ProtocolData.P-1))) - 1
	dsc := uint16(2*c.ProtocolData.T - 1)
	BITS_FOR_P := BitsToRepresent(uint(c.ProtocolData.P - 1))
	CSPRNG_buffer := c.CSPRNG(seed, int(RoundUp(uint(c.ProtocolData.BITS_N_FP_CT_RNG), 8)/8), dsc)
	placed := 0
	sub_buffer := uint64(0)
	for i := 0; i < 8; i++ {
		sub_buffer |= uint64(CSPRNG_buffer[i]) << uint64(8*i)
	}
	bits_in_sub_buf := 64
	pos_in_buf := 8
	pos_remaining := len(CSPRNG_buffer) - pos_in_buf
	for placed < c.ProtocolData.N {
		if bits_in_sub_buf <= 32 && pos_remaining > 0 {
			refresh_amount := int(math.Min(4, float64(pos_remaining)))
			refresh_buf := uint32(0)
			for i := 0; i < refresh_amount; i++ {
				refresh_buf |= uint32(CSPRNG_buffer[pos_in_buf+i]) << byte(8*i)
			}
			pos_in_buf += refresh_amount
			sub_buffer |= uint64(refresh_buf) << uint64(bits_in_sub_buf)
			bits_in_sub_buf += 8 * refresh_amount
			pos_remaining -= refresh_amount
		}
		res[placed] = uint8(uint8(sub_buffer) & FP_ELEM_mask)
		if res[placed] < uint8(c.ProtocolData.P) {
			placed++
		}
		sub_buffer >>= BITS_FOR_P
		bits_in_sub_buf -= BITS_FOR_P
	}
	return res
}
func (c *CROSS[T, P]) CSPRNG_fp_vec_prime(state sha3.ShakeHash) []T {
	res := make([]T, c.ProtocolData.N)
	// TODO: uint16 for RSDP-G, uint8 for RSDP
	FP_ELEM_mask := (uint16(1) << BitsToRepresent(uint(c.ProtocolData.P-1))) - 1
	BITS_FOR_P := BitsToRepresent(uint(c.ProtocolData.P - 1))
	CSPRNG_buffer, _ := c.CSPRNG_state(state, int(RoundUp(uint(c.ProtocolData.BITS_N_FP_CT_RNG), 8)/8))
	placed := 0
	sub_buffer := uint64(0)
	for i := 0; i < 8; i++ {
		sub_buffer |= uint64(CSPRNG_buffer[i]) << uint64(8*i)
	}
	bits_in_sub_buf := 64
	pos_in_buf := 8
	pos_remaining := len(CSPRNG_buffer) - pos_in_buf
	for placed < c.ProtocolData.N {
		if bits_in_sub_buf <= 32 && pos_remaining > 0 {
			refresh_amount := int(math.Min(4, float64(pos_remaining)))
			refresh_buf := uint32(0)
			for i := 0; i < refresh_amount; i++ {
				refresh_buf |= uint32(CSPRNG_buffer[pos_in_buf+i]) << byte(8*i)
			}
			pos_in_buf += refresh_amount
			sub_buffer |= uint64(refresh_buf) << uint64(bits_in_sub_buf)
			bits_in_sub_buf += 8 * refresh_amount
			pos_remaining -= refresh_amount
		}
		res[placed] = T(uint16(sub_buffer) & FP_ELEM_mask)
		if res[placed] < T(c.ProtocolData.P) {
			placed++
		}
		sub_buffer >>= BITS_FOR_P
		bits_in_sub_buf -= BITS_FOR_P
	}
	return res
}

func (c *CROSS[T, P]) CSPRNG_fz_vec(seed []byte) []byte {
	res := make([]byte, c.ProtocolData.N)
	// TODO: uint16 for RSDP-G, uint8 for RSDP
	FZ_ELEM_mask := (uint8(1) << BitsToRepresent(uint(c.ProtocolData.Z-1))) - 1
	dsc := uint16(3*c.ProtocolData.T + 3)
	BITS_FOR_Z := BitsToRepresent(uint(c.ProtocolData.Z - 1))
	CSPRNG_buffer := c.CSPRNG(seed, int(RoundUp(uint(c.ProtocolData.BITS_N_FZ_CT_RNG), 8)/8), dsc)
	placed := 0
	sub_buffer := uint64(0)
	for i := 0; i < 8; i++ {
		sub_buffer |= uint64(CSPRNG_buffer[i]) << uint64(8*i)
	}
	bits_in_sub_buf := 64
	pos_in_buf := 8
	pos_remaining := len(CSPRNG_buffer) - pos_in_buf
	for placed < c.ProtocolData.N {
		if bits_in_sub_buf <= 32 && pos_remaining > 0 {
			refresh_amount := int(math.Min(4, float64(pos_remaining)))
			refresh_buf := uint32(0)
			for i := 0; i < refresh_amount; i++ {
				refresh_buf |= uint32(CSPRNG_buffer[pos_in_buf+i]) << byte(8*i)
			}
			pos_in_buf += refresh_amount
			sub_buffer |= uint64(refresh_buf) << uint64(bits_in_sub_buf)
			bits_in_sub_buf += 8 * refresh_amount
			pos_remaining -= refresh_amount
		}
		res[placed] = uint8(uint8(sub_buffer) & FZ_ELEM_mask)
		if res[placed] < uint8(c.ProtocolData.Z) {
			placed++
		}
		sub_buffer >>= BITS_FOR_Z
		bits_in_sub_buf -= BITS_FOR_Z
	}
	return res
}

func (c *CROSS[T, P]) CSPRNG_fz_vec_prime(state sha3.ShakeHash) ([]byte, sha3.ShakeHash) {
	res := make([]byte, c.ProtocolData.N)
	// TODO: uint16 for RSDP-G, uint8 for RSDP
	FZ_ELEM_mask := (uint8(1) << BitsToRepresent(uint(c.ProtocolData.Z-1))) - 1
	BITS_FOR_Z := BitsToRepresent(uint(c.ProtocolData.Z - 1))
	CSPRNG_buffer, state := c.CSPRNG_state(state, int(RoundUp(uint(c.ProtocolData.BITS_N_FZ_CT_RNG), 8)/8))
	placed := 0
	sub_buffer := uint64(0)
	for i := 0; i < 8; i++ {
		sub_buffer |= uint64(CSPRNG_buffer[i]) << uint64(8*i)
	}
	bits_in_sub_buf := 64
	pos_in_buf := 8
	pos_remaining := len(CSPRNG_buffer) - pos_in_buf
	for placed < c.ProtocolData.N {
		if bits_in_sub_buf <= 32 && pos_remaining > 0 {
			refresh_amount := int(math.Min(4, float64(pos_remaining)))
			refresh_buf := uint32(0)
			for i := 0; i < refresh_amount; i++ {
				refresh_buf |= uint32(CSPRNG_buffer[pos_in_buf+i]) << byte(8*i)
			}
			pos_in_buf += refresh_amount
			sub_buffer |= uint64(refresh_buf) << uint64(bits_in_sub_buf)
			bits_in_sub_buf += 8 * refresh_amount
			pos_remaining -= refresh_amount
		}
		res[placed] = uint8(uint8(sub_buffer) & FZ_ELEM_mask)
		if res[placed] < uint8(c.ProtocolData.Z) {
			placed++
		}
		sub_buffer >>= BITS_FOR_Z
		bits_in_sub_buf -= BITS_FOR_Z
	}
	return res, state
}

func (c *CROSS[T, P]) CSPRNG_fp_vec_chall_1(seed []byte) []T {
	res := make([]T, c.ProtocolData.T)
	// TODO: uint16 for RSDP-G, uint8 for RSDP
	FP_ELEM_mask := (T(1) << BitsToRepresent(uint(c.ProtocolData.P-2))) - 1
	dsc := uint16(3*c.ProtocolData.T - 1)
	BITS_FOR_P := BitsToRepresent(uint(c.ProtocolData.P - 2))
	CSPRNG_buffer := c.CSPRNG(seed, int(RoundUp(uint(c.ProtocolData.BITS_CHALL_1_FPSTAR_CT_RNG), 8)/8), dsc)
	placed := 0
	sub_buffer := uint64(0)
	for i := 0; i < 8; i++ {
		sub_buffer |= uint64(CSPRNG_buffer[i]) << uint64(8*i)
	}
	bits_in_sub_buf := 64
	pos_in_buf := 8
	pos_remaining := len(CSPRNG_buffer) - pos_in_buf
	for placed < c.ProtocolData.T {
		if bits_in_sub_buf <= 32 && pos_remaining > 0 {
			refresh_amount := int(math.Min(4, float64(pos_remaining)))
			refresh_buf := uint32(0)
			for i := 0; i < refresh_amount; i++ {
				refresh_buf |= uint32(CSPRNG_buffer[pos_in_buf+i]) << byte(8*i)
			}
			pos_in_buf += refresh_amount
			sub_buffer |= uint64(refresh_buf) << uint64(bits_in_sub_buf)
			bits_in_sub_buf += 8 * refresh_amount
			pos_remaining -= refresh_amount
		}
		res[placed] = T(T(sub_buffer)&FP_ELEM_mask) + 1
		if res[placed] < T(c.ProtocolData.P) {
			placed++
		}
		sub_buffer >>= BITS_FOR_P
		bits_in_sub_buf -= BITS_FOR_P
	}
	return res
}

func (c *CROSS[T, P]) CSPRNG_fz_inf_w(seed []byte) []byte {
	res := make([]byte, c.ProtocolData.M)
	// TODO: uint16 for RSDP-G, uint8 for RSDP
	FZ_ELEM_mask := (uint8(1) << BitsToRepresent(uint(c.ProtocolData.Z-1))) - 1
	dsc := uint16(3*c.ProtocolData.T + 3)
	BITS_FOR_Z := BitsToRepresent(uint(c.ProtocolData.Z - 1))
	CSPRNG_buffer := c.CSPRNG(seed, int(RoundUp(uint(c.ProtocolData.BITS_M_FZ_CT_RNG), 8)/8), dsc)
	placed := 0
	sub_buffer := uint64(0)
	for i := 0; i < 8; i++ {
		sub_buffer |= uint64(CSPRNG_buffer[i]) << uint64(8*i)
	}
	bits_in_sub_buf := 64
	pos_in_buf := 8
	pos_remaining := len(CSPRNG_buffer) - pos_in_buf
	for placed < c.ProtocolData.M {
		if bits_in_sub_buf <= 32 && pos_remaining > 0 {
			refresh_amount := int(math.Min(4, float64(pos_remaining)))
			refresh_buf := uint32(0)
			for i := 0; i < refresh_amount; i++ {
				refresh_buf |= uint32(CSPRNG_buffer[pos_in_buf+i]) << byte(8*i)
			}
			pos_in_buf += refresh_amount
			sub_buffer |= uint64(refresh_buf) << uint64(bits_in_sub_buf)
			bits_in_sub_buf += 8 * refresh_amount
			pos_remaining -= refresh_amount
		}
		res[placed] = uint8(uint8(sub_buffer) & FZ_ELEM_mask)
		if res[placed] < uint8(c.ProtocolData.Z) {
			placed++
		}
		sub_buffer >>= BITS_FOR_Z
		bits_in_sub_buf -= BITS_FOR_Z
	}
	return res
}

func (c *CROSS[T, P]) CSPRNG_fz_inf_w_prime(state sha3.ShakeHash) ([]byte, sha3.ShakeHash) {
	res := make([]byte, c.ProtocolData.M)
	// TODO: uint16 for RSDP-G, uint8 for RSDP
	FZ_ELEM_mask := (uint8(1) << BitsToRepresent(uint(c.ProtocolData.Z-1))) - 1
	BITS_FOR_Z := BitsToRepresent(uint(c.ProtocolData.Z - 1))
	CSPRNG_buffer, state := c.CSPRNG_state(state, int(RoundUp(uint(c.ProtocolData.BITS_M_FZ_CT_RNG), 8)/8))
	placed := 0
	sub_buffer := uint64(0)
	for i := 0; i < 8; i++ {
		sub_buffer |= uint64(CSPRNG_buffer[i]) << uint64(8*i)
	}
	bits_in_sub_buf := 64
	pos_in_buf := 8
	pos_remaining := len(CSPRNG_buffer) - pos_in_buf
	for placed < c.ProtocolData.M {
		if bits_in_sub_buf <= 32 && pos_remaining > 0 {
			refresh_amount := int(math.Min(4, float64(pos_remaining)))
			refresh_buf := uint32(0)
			for i := 0; i < refresh_amount; i++ {
				refresh_buf |= uint32(CSPRNG_buffer[pos_in_buf+i]) << byte(8*i)
			}
			pos_in_buf += refresh_amount
			sub_buffer |= uint64(refresh_buf) << uint64(bits_in_sub_buf)
			bits_in_sub_buf += 8 * refresh_amount
			pos_remaining -= refresh_amount
		}
		res[placed] = uint8(uint8(sub_buffer) & FZ_ELEM_mask)
		if res[placed] < uint8(c.ProtocolData.Z) {
			placed++
		}
		sub_buffer >>= BITS_FOR_Z
		bits_in_sub_buf -= BITS_FOR_Z
	}
	return res, state
}

func (c *CROSS[T, P]) CSPRNG_fz_mat(seed []byte) ([]byte, sha3.ShakeHash) {
	res := make([]byte, c.ProtocolData.M*(c.ProtocolData.N-c.ProtocolData.M))
	// TODO: uint16 for RSDP-G, uint8 for RSDP
	FZ_ELEM_mask := (uint8(1) << BitsToRepresent(uint(c.ProtocolData.Z-1))) - 1
	dsc := uint16(3*c.ProtocolData.T + 2)
	BITS_FOR_Z := BitsToRepresent(uint(c.ProtocolData.Z - 1))
	CSPRNG_buffer, state := c.CSPRNG_prime(seed, int(RoundUp(uint(c.ProtocolData.BITS_W_CT_RNG), 8)/8), dsc)
	placed := 0
	sub_buffer := uint64(0)
	for i := 0; i < 8; i++ {
		sub_buffer |= uint64(CSPRNG_buffer[i]) << uint64(8*i)
	}
	bits_in_sub_buf := 64
	pos_in_buf := 8
	pos_remaining := len(CSPRNG_buffer) - pos_in_buf
	for placed < c.ProtocolData.M*(c.ProtocolData.N-c.ProtocolData.M) {
		if bits_in_sub_buf <= 32 && pos_remaining > 0 {
			refresh_amount := int(math.Min(4, float64(pos_remaining)))
			refresh_buf := uint32(0)
			for i := 0; i < refresh_amount; i++ {
				refresh_buf |= uint32(CSPRNG_buffer[pos_in_buf+i]) << byte(8*i)
			}
			pos_in_buf += refresh_amount
			sub_buffer |= uint64(refresh_buf) << uint64(bits_in_sub_buf)
			bits_in_sub_buf += 8 * refresh_amount
			pos_remaining -= refresh_amount
		}
		res[placed] = uint8(uint8(sub_buffer) & FZ_ELEM_mask)
		if res[placed] < uint8(c.ProtocolData.Z) {
			placed++
		}
		sub_buffer >>= BITS_FOR_Z
		bits_in_sub_buf -= BITS_FOR_Z
	}
	return res, state
}

func (c *CROSS[T, P]) Expand_digest_to_fixed_weight(digest []byte) []bool {
	fixed_weight_string := make([]bool, c.ProtocolData.T)
	dsc_csprng_b := uint16(3 * c.ProtocolData.T)
	CSPRNG_buffer := c.CSPRNG(digest, int(RoundUp(uint(c.ProtocolData.BITS_CWSTR_RNG), 8)/8), dsc_csprng_b)
	for i := 0; i < c.ProtocolData.W; i++ {
		fixed_weight_string[i] = true
	}
	sub_buffer := uint64(0)
	for i := 0; i < 8; i++ {
		sub_buffer |= uint64(CSPRNG_buffer[i]) << uint64(8*i)
	}
	bits_in_sub_buf := 64
	pos_in_buf := 8
	pos_remaining := len(CSPRNG_buffer) - pos_in_buf
	curr := 0
	for curr < c.ProtocolData.T {
		if bits_in_sub_buf <= 32 && pos_remaining > 0 {
			refresh_amount := int(math.Min(4, float64(pos_remaining)))
			refresh_buf := uint32(0)
			for i := 0; i < refresh_amount; i++ {
				refresh_buf |= uint32(CSPRNG_buffer[pos_in_buf+i]) << byte(8*i)
			}
			pos_in_buf += refresh_amount
			sub_buffer |= uint64(refresh_buf) << uint64(bits_in_sub_buf)
			bits_in_sub_buf += 8 * refresh_amount
			pos_remaining -= refresh_amount
		}
		bits_for_pos := BitsToRepresent(uint(c.ProtocolData.T - 1 - curr))
		pos_mask := (uint64(1) << uint64(bits_for_pos)) - 1
		candidate_pos := uint16(sub_buffer & pos_mask)
		if candidate_pos < uint16(c.ProtocolData.T-curr) {
			dest := curr + int(candidate_pos)
			tmp := fixed_weight_string[curr]
			fixed_weight_string[curr] = fixed_weight_string[dest]
			fixed_weight_string[dest] = tmp
			curr++
		}
		sub_buffer >>= uint64(bits_for_pos)
		bits_in_sub_buf -= bits_for_pos
	}
	return fixed_weight_string
}
