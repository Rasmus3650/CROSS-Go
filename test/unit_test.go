package test_suite

import (
	"PQC-Master-Thesis/internal/shake"
	"bytes"
	"fmt"
	"testing"
)

func TestShake128CSPRNG(t *testing.T) {
	seed := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	T := 256
	domain_sep := 0
	output_len := 64
	dsc := uint16(domain_sep + 3*T + 2)
	randomBytes, err := shake.CsprngInitialize(1, seed, output_len, dsc)
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

func TestShake256CSPRNG(t *testing.T) {
	seed := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	T := 384
	domain_sep := 0
	output_len := 96
	dsc := uint16(domain_sep + 3*T + 2)
	randomBytes, err := shake.CsprngInitialize(3, seed, output_len, dsc)
	if err != nil {
		fmt.Println("Error initializing CSPRNG:", err)
		return
	}
	// Golang generated hashes
	go_seed_e := randomBytes[:48]
	go_seed_pk := randomBytes[48:]
	// C generated hashes
	c_seed_e := []byte{147, 238, 19, 229, 132, 25, 3, 81, 217, 50, 197, 252, 15, 121, 71, 77, 59, 160, 55, 163, 146, 103, 3, 167, 152, 130, 247, 60, 29, 204, 157, 69, 70, 35, 64, 96, 134, 142, 22, 254, 205, 197, 227, 165, 188, 249, 140, 130}
	c_seed_pk := []byte{252, 18, 4, 247, 69, 37, 146, 26, 108, 50, 74, 40, 51, 109, 52, 238, 94, 56, 18, 49, 143, 146, 119, 36, 49, 34, 218, 174, 138, 181, 109, 8, 128, 156, 164, 183, 60, 22, 239, 224, 21, 140, 175, 33, 17, 75, 55, 66}
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
	randomBytes, err := shake.CsprngInitialize(1, seed, output_len, dsc)
	if err != nil {
		fmt.Println("Error initializing CSPRNG:", err)
		return
	}
	fmt.Println(randomBytes)
}
