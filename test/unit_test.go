package test_suite

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestShakeBasic(t *testing.T) {
	data := make([]byte, (2*128)/8) // 2*lambda in bytes
	sha3.ShakeSum128(data, []byte{42})
	fmt.Println(data)
}
