package shake

import "golang.org/x/crypto/sha3"

// TODO: Move this into a seperate file
func csprngInitialize(seed []byte, output_len int, dsc uint16) ([]byte, error) {
	shake := sha3.NewShake128()
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
