package shake

import (
	"math"

	"golang.org/x/crypto/sha3"
)

func CSPRNG(security_level int, seed []byte, output_len int, dsc uint16) ([]byte, error) {
	var shake sha3.ShakeHash
	if security_level == 1 {
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
	output := make([]byte, output_len) // Adjust length as needed
	shake.Read(output)
	return output, nil
}

func isRepresentableInDBits(d, n uint) int {
	if n >= (1<<(d-1)) && n < (1<<d) {
		return int(d)
	}
	return -1
}

func bitsToRepresent(n uint) int {
	if n == 0 {
		return 1
	}

	result := 15
	for d := uint(1); d <= 16; d++ {
		result += isRepresentableInDBits(d, n)
	}
	return result
}
func roundUp(amount, roundAmt uint) uint {
	return ((amount + roundAmt - 1) / roundAmt) * roundAmt
}

func CSPRNG_fp_mat(res []uint8, N int, seed []byte, bitsVCTRng int, p int) {
	// TODO: uint16 for RSDP-G, uint8 for RSDP
	FP_ELEM_mask := (uint(1) << bitsToRepresent(uint(p-1))) - 1
	CSPRNG_buffer := make([]uint8, roundUp(uint(bitsVCTRng), 8)/8)
	BITS_FOR_P := bitsToRepresent(uint(p - 1))
	//TODO: Switch case on the dsc + the real value
	CSPRNG(1, seed, len(CSPRNG_buffer), 0)
	placed := 0
	sub_buffer := uint64(0)
	for i := 0; i < 8; i++ {
		sub_buffer |= uint64(CSPRNG_buffer[i] << uint8(8*i))
	}
	bits_in_sub_buf := 64
	pos_in_buf := 8
	pos_remaining := len(CSPRNG_buffer) - pos_in_buf
	for placed < N {
		if bits_in_sub_buf <= 32 && pos_remaining > 0 {
			refresh_amount := int(math.Min(4, float64(pos_remaining)))
			refresh_buf := uint32(0)
			for i := 0; i < refresh_amount; i++ {
				refresh_buf |= uint32(CSPRNG_buffer[pos_in_buf+i] << uint8(8*i))
			}
			pos_in_buf += refresh_amount
			sub_buffer |= uint64(refresh_buf) << uint64(bits_in_sub_buf)
			bits_in_sub_buf += 8 * refresh_amount
			pos_remaining -= refresh_amount
		}
		res[placed] = uint8(uint(sub_buffer) & FP_ELEM_mask)
		if res[placed] < uint8(p) {
			placed++
		}
		sub_buffer >>= BITS_FOR_P
		bits_in_sub_buf -= BITS_FOR_P
	}
}

func CSPRNG_fz_vec() {

}
