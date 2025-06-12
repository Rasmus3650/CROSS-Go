package main

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/pkg/vanilla"
	"fmt"
)

func test() {
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

func main() {
	x := []byte{1, 2, 3, 4, 5}
	slice := x[:3]
	fmt.Println("slice: ", slice)
	slice = append(slice, 6)
	fmt.Println("x: ", x)
	fmt.Println("slice: ", slice)
}
