package vanilla

import (
	"PQC-Master-Thesis/internal/common"
	"fmt"

	"golang.org/x/crypto/sha3"
)

func unpackSignature(sig []byte, proto_params common.ProtocolData) ([]byte, []byte, []byte, error) {
	//TODO: Check if sig is of correct length
	salt := make([]byte, (2*proto_params.Lambda)/8)
	digest_cmt := make([]byte, (2*proto_params.Lambda)/8)
	digest_chall_2 := make([]byte, (2*proto_params.Lambda)/8)
	//TODO: unpack path, proof resp
	salt = sig[:(2*proto_params.Lambda)/8]
	digest_cmt = sig[(2*proto_params.Lambda)/8 : (4*proto_params.Lambda)/8]
	digest_chall_2 = sig[(4*proto_params.Lambda)/8 : (6*proto_params.Lambda)/8]

	return salt, digest_cmt, digest_chall_2, nil
}

func Verify(pk Pub, msg []byte, sig []byte, proto_params common.ProtocolData) (bool, error) {
	//TODO: Unpack signature
	salt, digest_cmt, digest_chall_2, err := unpackSignature(sig, proto_params)
	if err != nil {
		return false, fmt.Errorf("Error unpacking signature: %v", err)
	}
	c := 2*proto_params.T - 1
	n_minus_k := proto_params.N - proto_params.K
	V := make([][]byte, n_minus_k)
	for i := range V {
		V[i] = make([]byte, proto_params.K)
	}
	buffer := make([]byte, n_minus_k*proto_params.K)

	// Security probably dies here since p=509 in RSDP-G, might be fine for RSDP
	sha3.ShakeSum128(buffer, append(pk.SeedPK, byte(3*proto_params.T+2)))
	idx := 0
	for i := 0; i < n_minus_k; i++ {
		for j := 0; j < proto_params.K; j++ {
			// Ensure values are in Fp
			V[i][j] = buffer[idx]%byte(proto_params.P-1) + 1
			if V[i][j] > byte(proto_params.P) {
				return false, fmt.Errorf("V[i][j] > P")
			}
			idx++
		}
	}

	H := make([][]byte, n_minus_k)
	for i := range H {
		H[i] = make([]byte, proto_params.N)
		// Copy V part
		copy(H[i][:proto_params.K], V[i])
		// Add identity matrix part
		H[i][proto_params.K+i] = 1
	}
	digest_msg := make([]byte, (2*proto_params.Lambda)/8)
	sha3.ShakeSum128(digest_msg, msg)
	digest_chall_1 := make([]byte, (2*proto_params.Lambda)/8)
	sha3.ShakeSum128(digest_chall_1, append(append(digest_msg, digest_cmt...), salt...))
	chall_1 := make([]byte, proto_params.T)
	sha3.ShakeSum128(chall_1, append(digest_chall_1, byte(proto_params.T+c)))
	chall_2 := expand_digest_to_fixed_weight(digest_chall_2, proto_params)

}
