package main

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/pkg/vanilla"
	"log"
	"os"
	"runtime/pprof"
	"testing"
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
		keys, _ := cross.KeyGen()
		b.ResetTimer()
		for i := 0; i < 100; i++ {
			_, _ = cross.Sign(keys.Sk, msg)
		}
	})

	log.Println(result)
}
