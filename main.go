package main

import (
	common "github.com/rasmus3650/PQC-Master-Thesis/internal/common"
	pkg "github.com/rasmus3650/PQC-Master-Thesis/pkg/vanilla"
)

func main() {
	data, err := common.GetSecurityConfig(1)
	if err != nil {
		panic(err)
	}
	pkg.KeyGen(data)

}
