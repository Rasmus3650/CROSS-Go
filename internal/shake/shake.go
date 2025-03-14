package shake

import (
	"fmt"
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

func CSPRNG_init(security_level int, seed []byte, output_len int, dsc uint16) (sha3.ShakeHash, error) {
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
	return shake, nil
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

func CSPRNG_fp_mat(K, N, t int, seed []byte, bitsVCTRng int, p int) []byte {
	res := make([]byte, K*(N-K))
	// TODO: uint16 for RSDP-G, uint8 for RSDP
	FP_ELEM_mask := (uint8(1) << bitsToRepresent(uint(p-1))) - 1
	//CSPRNG_buffer := make([]uint8, roundUp(uint(bitsVCTRng), 8)/8)
	BITS_FOR_P := bitsToRepresent(uint(p - 1))
	//TODO: Switch case on the dsc + the real value
	dsc := uint16(0 + 3*t + 2)
	CSPRNG_buffer, err := CSPRNG(1, seed, int(roundUp(uint(bitsVCTRng), 8)/8), dsc)
	//fmt.Println("CSPRNG_buffer:", CSPRNG_buffer)
	if err != nil {
		fmt.Errorf("Error in CSPRNG: %v", err)
	}
	placed := 0
	sub_buffer := uint64(0)
	for i := 0; i < 8; i++ {
		sub_buffer |= uint64(CSPRNG_buffer[i]) << uint64(8*i)
	}
	bits_in_sub_buf := 64
	pos_in_buf := 8
	pos_remaining := len(CSPRNG_buffer) - pos_in_buf
	for placed < K*(N-K) {
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
		if res[placed] < uint8(p) {
			placed++
		}
		sub_buffer >>= BITS_FOR_P
		bits_in_sub_buf -= BITS_FOR_P
	}
	return res
}

func CSPRNG_fz_vec() {

}
