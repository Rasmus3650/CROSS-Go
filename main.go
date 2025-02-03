package main

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/pkg/vanilla"
)

func main() {
	data, err := common.GetSchemeConfig(1)
	if err != nil {
		panic(err)
	}
	//Change to generator
	g := 1
	vanilla.KeyGen(g, data)
}
