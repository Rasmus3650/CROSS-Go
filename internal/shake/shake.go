package shake

import "golang.org/x/crypto/sha3"

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

func CSPRNG_fp_mat() {
	// TODO: uint16 for RSDP-G, uint8 for RSDP
	FP_ELEM_mask := (uint(1) << bitsToRepresent(p-1)) - 1
	buffer := make([]uint8, bufferSize, roundUp(bitsVCTRng, 8)/8)

}

func CSPRNG_fz_vec() {

}
