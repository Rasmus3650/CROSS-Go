package main

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/pkg/vanilla"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"testing"
	"time"
)

func main() {
	// Create the CPU profile file
	f, err := os.Create("cpu.prof")
	if err != nil {
		log.Fatal("could not create CPU profile: ", err)
	}
	defer f.Close()

	// Start CPU profiling
	if err := pprof.StartCPUProfile(f); err != nil {
		log.Fatal("could not start CPU profile: ", err)
	}
	defer pprof.StopCPUProfile() // Run the benchmark manually
	result := testing.Benchmark(func(b *testing.B) {
		msg := []byte("Hello, world!")
		cross, _ := vanilla.NewCROSS(common.RSDP_1_BALANCED)
		keys := cross.KeyGen()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = cross.Sign(keys.Sk, msg)
		}
	})

	log.Println(result)
}

func test1() {
	const iterations = 1000
	var totalKeyGen, totalSign, totalVerify time.Duration

	msg := []byte("Hello, world!")

	for i := 0; i < iterations; i++ {
		// KeyGen timing
		cross, _ := vanilla.NewCROSS(common.RSDP_1_BALANCED)
		startKeyGen := time.Now()
		keys := cross.KeyGen()
		totalKeyGen += time.Since(startKeyGen)

		// Sign timing
		startSign := time.Now()
		sig, err := cross.Sign(keys.Sk, msg)
		totalSign += time.Since(startSign)
		if err != nil {
			fmt.Printf("Error signing at iteration %d: %v\n", i, err)
			continue
		}
		// Verify timing
		startVerify := time.Now()
		ok, err := cross.Verify(keys.Pk, msg, sig)
		totalVerify += time.Since(startVerify)
		if err != nil {
			fmt.Printf("Error verifying at iteration %d: %v\n", i, err)
			continue
		}
		if !ok {
			fmt.Printf("Signature verification failed at iteration %d\n", i)
			continue
		}
	}

	// Print average times
	fmt.Printf("Average KeyGen time: %v\n", totalKeyGen/time.Duration(iterations))
	fmt.Printf("Average Sign time:   %v\n", totalSign/time.Duration(iterations))
	fmt.Printf("Average Verify time: %v\n", totalVerify/time.Duration(iterations))
}
