package main

import (
	"crypto/rand"
	"math/big"

	"github.com/Rasmus3650/CROSS-Go/internal/common"
	"github.com/Rasmus3650/CROSS-Go/pkg/vanilla"
)

var cross_inst vanilla.CROSSInstance[uint8, uint16]
var keypair vanilla.KeyPair

const signature_size_dudect = 13152
const secret_key_size_dudect = (2 * 128) / 8

func init() {
	//Careful when testing RSDP-G, the type assertion below will fail
	tmp, _ := vanilla.NewCROSS(common.RSDP_1_BALANCED)
	cross_inst = *tmp.(*vanilla.CROSSInstance[uint8, uint16])
	keypair = cross_inst.KeyGen()
}

func prepare_inputs_2() (input_data [][]byte, classes []int) {
	input_data = make([][]byte, number_measurements)
	classes = make([]int, number_measurements)
	for i := 0; i < number_measurements; i++ {
		//all messages should be valid to sign, doesn't make sense to test with no data
		temp, _ := rand.Int(rand.Reader, big.NewInt(2))
		classes[i] = int(temp.Int64())
		if classes[i] == 0 {
			// Class 0: fixed message
			message := make([]byte, secret_key_size_dudect+12)
			copy(message[:12], "Hello World!")
			copy(message[12:], keypair.Sk)
			input_data[i] = message
		} else {
			// Class 1: random message
			msg_length := 12
			message := make([]byte, msg_length)
			_, _ = rand.Read(message)
			input_data[i] = make([]byte, secret_key_size_dudect+12)
			copy(input_data[i][:12], message)
			new_key := cross_inst.KeyGen()
			copy(input_data[i][12:], new_key.Sk)
		}
	}
	return
}

func do_one_computation_2(data []byte) {
	message := data[:12]
	secret_key := data[12:]
	_, _ = cross_inst.Sign(secret_key, message)
}

func prepare_inputs_verify_2() (input_data [][]byte, classes []int) {
	input_data = make([][]byte, number_measurements)
	classes = make([]int, number_measurements)
	innerLength := 32 + signature_size_dudect
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
			signature, _ := cross_inst.Sign(keypair.Sk, message)
			signature_bytes := signature.ToBytes()
			copy(input_data[i][32:], signature_bytes)
		} else if classes[i] == 1 {
			// Class 1: valid signature, but invalid message
			signature, _ := cross_inst.Sign(keypair.Sk, message[:16])
			signature_bytes := signature.ToBytes()
			copy(input_data[i][32:], signature_bytes)
		} else if classes[i] == 2 {
			// Class 2: valid message, but invalid signature
			signature, _ := cross_inst.Sign(keypair.Sk, message)
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
			signature := make([]byte, signature_size_dudect)
			_, _ = rand.Read(input_data[i])
			copy(input_data[i][32:], signature)
		} else if classes[i] == 4 {
			// Class 4: fixed message, valid signature
			message = make([]byte, 32)
			copy(message, "Hello World!")
			signature, _ := cross_inst.Sign(keypair.Sk, message)
			signature_bytes := signature.ToBytes()
			copy(input_data[i][32:], signature_bytes)
		}
	}
	return
}

func do_one_computation_verify_2(data []byte) {
	// Extract the message from the data
	message := data[:32]
	// Extract the signature from the data
	signature_raw := data[32:]
	signature := cross_inst.ToSig(signature_raw)
	_, _ = cross_inst.Verify(keypair.Pk, message, signature)
}
