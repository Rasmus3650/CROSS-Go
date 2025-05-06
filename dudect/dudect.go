package dudect

import (
	"PQC-Master-Thesis/pkg/vanilla"
	"crypto/rand"
)

cross, _ := vanilla.NewCROSS(common.RSDP_1_BALANCED)
keys, _ := cross.KeyGen()
signature_size := 13152
// TODO: flatten signature to byte array when we generate valid ones
func prepare_inputs_sign() (input_data [][]byte, classes []int) {
	input_data = make([][]byte, number_measurements)
	classes = make([]int, number_measurements)
	for i := 0; i < number_measurements; i++ {
		//all messages should be valid to sign, doesn't make sense to test with no data
		classes[i] = rand.Int(2)
		if classes[i] == 0 {
			// Class 0: fixed message
			message[i] = make([]byte, "Hello World!")
			input_data[i] = message[i]
		} else {
			// Class 1: random message
			msg_length := rand.Int(5000) + 1
			input_data[i] = make([]byte, 5000)
			_, _ = rand.Read(input_data[i])
		}
		return
	}
}

// TODO: unflatten signature
func do_one_computation_sign(data []byte) {
	_, _ = cross.Sign(keys.Sk, data)
}

// TODO: flatten signature to byte array when we generate valid ones
func prepare_inputs_verify() (input_data [][]byte, classes []int) {
	input_data = make([][]byte, number_measurements)
	classes = make([]int, number_measurements)
	innerLength := 32 + signature_size
	for i := range input_data {
		input_data[i] = make([]byte, innerLength)
	}
	for i := 0; i < number_measurements; i++ {
		classes[i] = rand.Int(5)
		message[i] = make([]byte, 32)
		_, _ = rand.Read(message[i])
		input_data[i][:32] = message[i]
		if classes[i] == 0 {
			// Class 0: valid signature
			signature, _ := cross.Sign(keys.Sk, message[i])
			input_data[i][32:] = signature
		} else if classes[i] == 1 {
			// Class 1: valid signature, but invalid message
			signature, _ := cross.Sign(keys.Sk, message[i])
			input_data[i][32:] = signature
		} else if classes[i] == 2 {
			// Class 2: valid message, but invalid signature
			signature, _ := cross.Sign(keys.Sk, message[i])
			// flip a random bit in the signature
			bit := rand.Int(signature_size)

			//TODO: fix this to flip properly in signature, need language server
			signature[bit] ^= 1
			input_data[i][32:] = signature
		} else if classes[i] == 3 {
			// Class 3: Completely invalid signature, assume bytes of random data is invalid
			input_data[i][32:] = make([]byte, signature_size)
			_, _ = rand.Read(input_data[i])
		} else if classes[i] == 4 {
			// Class 4: fixed message, valid signature
			message[i] = make([]byte, 32)
			copy(message[i], "Hello World!")
			signature, _ := cross.Sign(keys.Sk, message[i])
		}
	}
	return
}

// TODO: convert the signature to correct type
func do_one_computation_verify(data []byte) {
	// Extract the message from the data
	message := data[:32]
	// Extract the signature from the data
	signature_raw := data[32:]
	signature := &vanilla.Signature{}
	_, _ = cross.Verify(keys.Pk, message, signature)
}
