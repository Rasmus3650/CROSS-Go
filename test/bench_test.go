package test_suite

import (
	"testing"

	"github.com/Rasmus3650/CROSS-Go/internal"
	"github.com/Rasmus3650/CROSS-Go/pkg/vanilla"
)

/*func BenchmarkSign(b *testing.B) {
	msg := []byte("Hello, world!")

	for i := 0; i < 10; i++ {
		// Initialize the CROSS instance
		cross, err := vanilla.NewCROSS(internal.RSDP_1_BALANCED)
		if err != nil {
			b.Fatalf("failed to initialize CROSS: %v", err)
		}
		// Generate keys
		keys, err := cross.KeyGen()
		if err != nil {
			b.Fatalf("key generation failed: %v", err)
		}
		// Sign a message
		sig, err := cross.Sign(keys.Sk, msg)
		if err != nil {
			b.Fatalf("signing failed: %v", err)
		}
		// Verify the signature
		ok, err := cross.Verify(keys.Pk, msg, sig)
		if err != nil {
			b.Fatalf("verification failed: %v", err)
		}
		if !ok {
			b.Fatal("signature verification failed")
		}
	}
}
*/

func BenchmarkKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cross, _ := vanilla.NewCROSS(internal.RSDP_1_BALANCED)
		_ = cross.KeyGen()
	}
}

func BenchmarkSign(b *testing.B) {
	msg := []byte("Hello, world!")
	cross, _ := vanilla.NewCROSS(internal.RSDP_1_BALANCED)
	keys := cross.KeyGen()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cross.Sign(keys.Sk, msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	msg := []byte("Hello, world!")
	cross, _ := vanilla.NewCROSS(internal.RSDP_1_BALANCED)
	keys := cross.KeyGen()
	sig, _ := cross.Sign(keys.Sk, msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cross.Verify(keys.Pk, msg, sig)
	}
}
