package test_suite

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/Rasmus3650/CROSS-Go/common"
	"github.com/Rasmus3650/CROSS-Go/pkg/vanilla"
)

func TestBitFlip(t *testing.T) {
	cross, err := vanilla.NewCROSS(common.RSDP_1_BALANCED)
	if err != nil {
		t.Fatalf("Failed to create CROSS: %v", err)
	}
	msg := make([]byte, 32)
	rand.Read(msg)
	key := cross.KeyGen()
	signature, err := cross.Sign(key.Sk, msg)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Helper functions
	flipBit := func(b byte, i uint) byte {
		return b ^ (1 << i)
	}

	verify := func(sig *vanilla.Signature) bool {
		ok, err := cross.Verify(key.Pk, msg, *sig)
		return err == nil && ok
	}

	if !verify(&signature) {
		t.Fatal("Original signature does not verify")
	}

	flipBytes := func(bytes []byte, name string) {
		for byteIdx := 0; byteIdx < len(bytes); byteIdx++ {
			for bitIdx := 0; bitIdx < 8; bitIdx++ {
				bytes[byteIdx] = flipBit(bytes[byteIdx], uint(bitIdx))

				if verify(&signature) {
					t.Errorf("Signature still verified after flipping bit %d in %s[%d]", bitIdx, name, byteIdx)
				}

				bytes[byteIdx] = flipBit(bytes[byteIdx], uint(bitIdx)) // flip back
			}
		}
	}
	flipBytes(signature.Salt, "Salt")
	flipBytes(signature.Digest_cmt, "Digest_cmt")
	flipBytes(signature.Digest_chall_2, "Digest_chall_2")

	for pathIdx, pathBytes := range signature.Path {
		flipBytes(pathBytes, fmt.Sprintf("Path[%d]", pathIdx))
	}

	for proofIdx, proofBytes := range signature.Proof {
		flipBytes(proofBytes, fmt.Sprintf("Proof[%d]", proofIdx))
	}

	flipBytes(signature.Resp_1, "Resp_1")

	for resp0Idx, resp0 := range signature.Resp_0 {
		flipBytes(resp0.V_bar, fmt.Sprintf("Resp_0[%d].V_bar", resp0Idx))
	}

}
