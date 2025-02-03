package vanilla

import (
	"PQC-Master-Thesis/internal/common"
	"crypto/rand"
	"fmt"
)

func Sign(pri []byte, msg []byte, params common.SchemeData) {
	eta, H, seed_pk := ExpandPrivateSeed(params, pri)
	m_seed := make([]byte, params.Lambda/8)
	salt := make([]byte, (2*params.Lambda)/8)
	rand.Read(m_seed)
	rand.Read(salt)
	fmt.Println(eta, H, seed_pk)
}
