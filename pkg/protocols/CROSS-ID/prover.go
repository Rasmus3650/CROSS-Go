package CROSSID

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/internal/matrix"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
)

func ProverHandleConnection(params common.SchemeData, msg_type string) {
	switch msg_type {
	case "init":
		msg := InitMsg(params)
		fmt.Print(msg)
	case "resp1":
		msg := Resp1Msg()
		fmt.Print(msg)
	case "resp2":
		msg := Resp2Msg()
		fmt.Print(msg)
	default:
		fmt.Errorf("Invalid message type: %s", msg_type)
	}
}

func modExp(base, exponent, modulus int) int {
	result := new(big.Int).Exp(big.NewInt(int64(base)), big.NewInt(int64(exponent)), big.NewInt(int64(modulus)))
	return int(result.Int64())
}

func isPrime(n int) bool {
	if n <= 1 {
		return false
	}
	for i := 2; i <= int(math.Sqrt(float64(n))); i++ {
		if n%i == 0 {
			return false
		}
	}
	return true
}
func findGenerator(p, z int) (int, error) {
	// Check if p is prime
	if !isPrime(p) {
		return 0, fmt.Errorf("p must be prime")
	}

	// Try each candidate g from 2 to p-1
	for g := 2; g < p; g++ {
		order := 1
		// Compute the order of g modulo p
		for modExp(g, order, p) != 1 {
			order++
		}

		// Check if the order is exactly Z
		if order == z {
			return g, nil
		}
	}

	return 0, fmt.Errorf("no generator found with order %d", z)
}

func KeyGen(params common.SchemeData) {
	// Private Key: e \in G
	// Public Key: G subset equal E^n, H \in F_p^{(n-k)X n}
	H := make([]byte, params.N-params.K*params.N)
	_, err := rand.Read(H)
	if err != nil {
		panic(err)
	}
	matrix.ListToMatrix(H, params.N-params.K, params.N, params.P) // Might need to change for uniform random sampling in F_p

	// Get generator for F_P^* of order Z
	g, _ := findGenerator(params.P, params.Z)
	if err != nil {
		panic(err)
	}
	E := make([]int, params.Z)
	for i := 1; i <= params.Z; i++ {
		E[i-1] = modExp(g, i, params.P)
	}
}

func InitMsg(params common.SchemeData) int {
	seed := make([]byte, params.Lambda/8)
	rand.Read(seed)
	return 0

}
func Resp1Msg() int {
	return 0
}

func Resp2Msg() int {
	return 0
}
