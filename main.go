package main

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/pkg/vanilla"
)

func main() {
	data, err := common.GetSecurityConfig(1)
	if err != nil {
		panic(err)
	}
	vanilla.KeyGen(data)
}
