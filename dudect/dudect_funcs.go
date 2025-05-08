package main

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/pkg/vanilla"
	"crypto/rand"
	"math/big"
)

var cross vanilla.CROSSInstance[uint8, uint16]
var keys vanilla.KeyPair

const signature_size = 13152

func init() {
	//Careful when testing RSDP-G, the type assertion below will fail
	tmp, _ := vanilla.NewCROSS(common.RSDP_1_BALANCED)
	cross = *tmp.(*vanilla.CROSSInstance[uint8, uint16])
	keys = cross.KeyGen()
}

func prepare_inputs() (input_data [][]byte, classes []int) {
	input_data = make([][]byte, number_measurements)
	classes = make([]int, number_measurements)
	for i := 0; i < number_measurements; i++ {
		//all messages should be valid to sign, doesn't make sense to test with no data
		temp, _ := rand.Int(rand.Reader, big.NewInt(2))
		classes[i] = int(temp.Int64())
		if classes[i] == 0 {
			// Class 0: fixed message
			message := []byte("Hello World!")
			input_data[i] = message
		} else {
			// Class 1: random message
			temp_msg_length, _ := rand.Int(rand.Reader, big.NewInt(5000))
			msg_length := int(temp_msg_length.Int64()) + 1
			input_data[i] = make([]byte, msg_length)
			_, _ = rand.Read(input_data[i])
		}
		return
	}
	return
}

func do_one_computation(data []byte) {
	_, _ = cross.Sign(keys.Sk, data)
}

func prepare_inputs_verify() (input_data [][]byte, classes []int) {
	input_data = make([][]byte, number_measurements)
	classes = make([]int, number_measurements)
	innerLength := 32 + signature_size
	for i := range input_data {
		input_data[i] = make([]byte, innerLength)
	}
	for i := 0; i < number_measurements; i++ {
		temp, _ := rand.Int(rand.Reader, big.NewInt(5))
		classes[i] = int(temp.Int64())
		message := make([]byte, 32)
		_, _ = rand.Read(message)
		copy(input_data[i][:32], message)
		if classes[i] == 0 {
			// Class 0: valid signature
			signature, _ := cross.Sign(keys.Sk, message)
			signature_bytes := signature.ToBytes()
			copy(input_data[i][32:], signature_bytes)
		} else if classes[i] == 1 {
			// Class 1: valid signature, but invalid message
			signature, _ := cross.Sign(keys.Sk, message)
			signature_bytes := signature.ToBytes()
			copy(input_data[i][32:], signature_bytes)
		} else if classes[i] == 2 {
			// Class 2: valid message, but invalid signature
			signature, _ := cross.Sign(keys.Sk, message)
			signature_bytes := signature.ToBytes()
			copy(input_data[i][32:], signature_bytes)
			// Select a random byte to flip
			bite, _ := rand.Int(rand.Reader, big.NewInt(int64(len(signature_bytes))))
			bit, _ := rand.Int(rand.Reader, big.NewInt(9))
			//TODO: fix this to flip properly in signature, need language server
			signature_bytes[bite.Int64()] ^= 1 << bit.Int64()
			copy(input_data[i][32:], signature_bytes)
		} else if classes[i] == 3 {
			// Class 3: Completely invalid signature, assume bytes of random data is invalid
			signature := make([]byte, signature_size)
			_, _ = rand.Read(input_data[i])
			copy(input_data[i][32:], signature)
		} else if classes[i] == 4 {
			// Class 4: fixed message, valid signature
			message = make([]byte, 32)
			copy(message, "Hello World!")
			signature, _ := cross.Sign(keys.Sk, message)
			signature_bytes := signature.ToBytes()
			copy(input_data[i][32:], signature_bytes)
		}
	}
	return
}

func do_one_computation_verify(data []byte) {
	// Extract the message from the data
	message := data[:32]
	// Extract the signature from the data
	signature_raw := data[32:]
	signature := cross.ToSig(signature_raw)
	_, _ = cross.Verify(keys.Pk, message, signature)
}
