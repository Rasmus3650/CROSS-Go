package main

import (
	"github.com/Rasmus3650/CROSS-Go/common"
	"github.com/Rasmus3650/CROSS-Go/pkg/vanilla"
)

func main() {
	// Initialize the CROSS instance
	cross, err := vanilla.NewCROSS(common.RSDP_1_BALANCED)
	if err != nil {
		panic(err)
	}
	// Generate keys
	keys := cross.KeyGen()

	// Sign a message
	msg := []byte("Hello, world!")
	sig, err := cross.Sign(keys.Sk, msg)
	if err != nil {
		panic(err)
	}
	// Verify the signature
	ok, err := cross.Verify(keys.Pk, msg, sig)
	if err != nil {
		panic(err)
	}
	if !ok {
		panic("Signature verification failed")
	}
}
