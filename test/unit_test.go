package test_suite

import (
	"bytes"
	"fmt"
	"testing"
)

func TestShakeCSPRNG(t *testing.T) {
	seed := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	T := 256
	domain_sep := 0
	output_len := 64
	dsc := uint16(domain_sep + 3*T + 2)
	randomBytes, err := shake.csprngInitialize(seed, output_len, dsc)
	if err != nil {
		fmt.Println("Error initializing CSPRNG:", err)
		return
	}
	// Golang generated hashes
	go_seed_e := randomBytes[:32]
	go_seed_pk := randomBytes[32:]
	// C generated hashes
	c_seed_e := []byte{15, 121, 106, 185, 65, 60, 38, 57, 192, 11, 100, 5, 36, 234, 50, 253, 115, 61, 99, 71, 54, 20, 106, 223, 64, 83, 75, 131, 107, 171, 179, 163}
	c_seed_pk := []byte{197, 184, 200, 221, 6, 37, 92, 70, 124, 127, 54, 125, 11, 163, 142, 207, 26, 21, 208, 178, 226, 28, 152, 49, 104, 87, 51, 136, 32, 87, 109, 243}
	// Assertions
	if !bytes.Equal(go_seed_e, c_seed_e) {
		t.Errorf("go_seed_e and c_seed_e do not match:\nGo: %v\nC:  %v", go_seed_e, c_seed_e)
	}

	if !bytes.Equal(go_seed_pk, c_seed_pk) {
		t.Errorf("go_seed_pk and c_seed_pk do not match:\nGo: %v\nC:  %v", go_seed_pk, c_seed_pk)
	}
}
func TestShakeHash(t *testing.T) {
	seed := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	output_len := 32
	dsc := uint16(32768)
	randomBytes, err := csprngInitialize(seed, output_len, dsc)
	if err != nil {
		fmt.Println("Error initializing CSPRNG:", err)
		return
	}
	fmt.Println(randomBytes)
}
