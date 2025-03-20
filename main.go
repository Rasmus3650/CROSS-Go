package main

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/pkg/vanilla"
)

func main() {
	cross, err := vanilla.NewCROSS(common.RSDP_1_BALANCED)
	if err != nil {
		panic(err)
	}
	cross.KeyGen()

}
