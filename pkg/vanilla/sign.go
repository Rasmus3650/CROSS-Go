package vanilla

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/internal/trees/merkle"
	seedtree "PQC-Master-Thesis/internal/trees/seed"
	"crypto/rand"
	"fmt"
	"math/big"

	"golang.org/x/crypto/sha3"
)

func expandSK(seed_sk []byte, proto_params common.ProtocolData) ([]byte, [][]byte) {
	seed_e_pk := make([]byte, (4*proto_params.Lambda)/8)
	sha3.ShakeSum128(seed_e_pk, append(seed_sk, byte(3*proto_params.T+1)))
	seed_e := seed_e_pk[:2*proto_params.Lambda/8]
	seed_pk := seed_e_pk[2*proto_params.Lambda/8:]

	n_minus_k := proto_params.N - proto_params.K
	V := make([][]byte, n_minus_k)
	for i := range V {
		V[i] = make([]byte, proto_params.K)
	}
	buffer := make([]byte, n_minus_k*proto_params.K)

	// Security probably dies here since p=509 in RSDP-G, might be fine for RSDP
	sha3.ShakeSum128(buffer, append(seed_pk, byte(3*proto_params.T+2)))
	idx := 0
	for i := 0; i < n_minus_k; i++ {
		for j := 0; j < proto_params.K; j++ {
			// Ensure values are in Fp
			V[i][j] = buffer[idx]%byte(proto_params.P-1) + 1
			if V[i][j] > byte(proto_params.P) {
				panic("V[i][j] > P")
			}
			idx++
		}
	}
	// This will generate trailing zeros in each row, might be wrong?
	H := make([][]byte, n_minus_k)
	for i := range H {
		H[i] = make([]byte, proto_params.N)
		// Copy V part
		copy(H[i][:proto_params.K], V[i])
		// Add identity matrix part
		H[i][proto_params.K+i] = 1
	}
	// This needs to be rejection sampling
	e_bar := make([]byte, proto_params.N)
	sha3.ShakeSum128(e_bar, append(seed_e, byte(3*proto_params.T+3)))
	for i, v := range e_bar {
		e_bar[i] = v%byte(proto_params.Z-1) + 1
	}
	return e_bar, H
}

// Probably needs re-writing
func fz_vec_sub(e_bar, e_bar_prime []byte) []byte {
	result := make([]byte, len(e_bar))
	for i := range e_bar {
		result[i] = e_bar[i] - e_bar_prime[i]
	}
	return result
}

func element_wise_mul(v, u_prime []byte, Z int) []byte {
	result := make([]byte, len(v))
	for i := range v {
		result[i] = byte(v[i]*u_prime[i]) % byte(Z)
	}
	return result
}

func Sign(g int, sk []byte, msg []byte, proto_params common.ProtocolData) ([]byte, error) {
	e_bar, H := expandSK(sk, proto_params)
	c := 2*proto_params.T - 1
	seed := make([]byte, proto_params.Lambda/8)
	salt := make([]byte, (2*proto_params.Lambda)/8)
	rand.Read(seed)
	rand.Read(salt)
	tree_params, err := common.GetTreeParams(proto_params.SchemeType, proto_params.ProblemVariant, proto_params.SecurityLevel)
	if err != nil {
		return nil, fmt.Errorf("Error getting tree params: %v", err)
	}
	commitments, err := seedtree.SeedLeaves(seed, salt, proto_params, tree_params)
	if err != nil {
		return nil, fmt.Errorf("Error building seed leaves: %v", err)
	}
	e_bar_prime := make([][]byte, proto_params.T)
	u_prime := make([][]byte, proto_params.T)
	v_bar := make([][]byte, proto_params.T)
	v := make([][]byte, proto_params.T)
	u := make([][]byte, proto_params.T)
	s_prime := make([][]byte, proto_params.T)
	cmt_0 := make([][]byte, proto_params.T)
	cmt_1 := make([][]byte, proto_params.T)
	for i := 0; i < proto_params.T; i++ {
		// TODO: PROPER SAMPLING!
		e_bar_buffer := make([]byte, proto_params.N)
		sha3.ShakeSum128(e_bar_buffer, append(append(commitments[i], salt...), byte(i+c)))
		for i, v := range e_bar_buffer {
			e_bar_buffer[i] = v%byte(proto_params.Z-1) + 1
		}
		e_bar_prime[i] = e_bar_buffer

		u_prime_buffer := make([]byte, proto_params.N)
		sha3.ShakeSum128(u_prime_buffer, append(append(commitments[i], salt...), byte(i+c)))
		for i, v := range u_prime_buffer {
			e_bar_buffer[i] = v%byte(proto_params.P-1) + 1
		}
		u_prime[i] = u_prime_buffer
		v_bar[i] = fz_vec_sub(e_bar, e_bar_prime[i])
		v_buffer := make([]byte, proto_params.N)
		for j := 0; j < proto_params.N; j++ {
			v_buffer[j] = byte(new(big.Int).Exp(big.NewInt(int64(g)), big.NewInt(int64(v_bar[i][j])), nil).Int64())
		}
		v[i] = v_buffer
		u[i] = element_wise_mul(v[i], u_prime[i], proto_params.Z)
		s_prime[i] = common.MultiplyVectorMatrix(u[i], common.TransposeByteMatrix(H))
		cmt_0_buffer := make([]byte, (2*proto_params.Lambda)/8)
		sha3.ShakeSum128(cmt_0_buffer, append(append(append(s_prime[i], v_bar[i]...), salt...), byte(i+c)))
		cmt_0[i] = cmt_0_buffer

		cmt_1_buffer := make([]byte, (2*proto_params.Lambda)/8)
		sha3.ShakeSum128(cmt_1_buffer, append(append(commitments[i], salt...), byte(i+c)))
		cmt_1[i] = cmt_1_buffer
	}
	digest_cmt_0, err := merkle.TreeRoot(cmt_0, proto_params, tree_params)
	digest_cmt_1 := make([]byte, (2*proto_params.Lambda)/8)
	flat_cmt_1 := make([]byte, 0)
	for _, b := range cmt_1 {
		flat_cmt_1 = append(flat_cmt_1, b...)
	}
	sha3.ShakeSum128(digest_cmt_1, flat_cmt_1)
	digest_cmt := make([]byte, (2*proto_params.Lambda)/8)
	sha3.ShakeSum128(digest_cmt, append(digest_cmt_0, digest_cmt_1...))

	digest_msg := make([]byte, (2*proto_params.Lambda)/8)
	sha3.ShakeSum128(digest_msg, msg)
	digest_chall_1 := make([]byte, (2*proto_params.Lambda)/8)
	sha3.ShakeSum128(digest_chall_1, append(append(digest_msg, digest_cmt...), salt...))
	//TODO: CSPRNG output needs to be in (F_p^*)^t, and fix value, gives us a problem with y[i] =
	chall_1 := make([]byte, proto_params.T)
	sha3.ShakeSum128(chall_1, append(digest_chall_1, byte(proto_params.T+c)))
	for i := range chall_1 {
		// -1, +1 to avoid 0
		chall_1[i] = chall_1[i]%byte(proto_params.P-1) + 1
	}
	var y []byte
	e_prime := make([][]byte, proto_params.T)
	for i := 0; i < proto_params.T; i++ {
		e_prime_i := make([]byte, proto_params.N)
		for j := 0; j < proto_params.N; j++ {
			//TODO: FIX THIS BULLSHIT MOST LIKELY QUITE WRONG!
			result := new(big.Int).Exp(big.NewInt(int64(g)), big.NewInt(int64(e_bar_prime[i][j])), big.NewInt(int64(proto_params.P)))
			e_prime_i[j] = result.Bytes()[0]
			ctr := 0
			for _ = range e_prime_i[j] {
				ctr++
			}
			fmt.Println("Length of e_prime_i[j] = ", ctr, " Should be 1")
		}
		e_prime[i] = e_prime_i
		//TODO: Implement scalar vector multiplication for byte and []byte
		//TODO: Make sure this is correct
		y = common.ScalarVecMulByte(e_prime[i], chall_1[i])
		for j := 0; j < len(y); j++ {
			y[j] = (y[j] + u_prime[i][j]) % byte(255)
		}
	}
	digest_chall_2 := make([]byte, (2*proto_params.Lambda)/8)
	sha3.ShakeSum128(digest_chall_2, append(y[:proto_params.T], digest_chall_1...))
	chall_2 := expand_digest_to_fixed_weight(digest_chall_2, proto_params)
	proof, err := merkle.TreeProof(cmt_0, chall_2, proto_params, tree_params)
	if err != nil {
		return nil, fmt.Errorf("Error generating proof: %v", err)
	}
	path, err := seedtree.SeedPath(seed, salt, chall_2, proto_params, tree_params)
	if err != nil {
		return nil, fmt.Errorf("Error generating seed path: %v", err)
	}
	//TODO: Ensure compatibility with refernce code for this
	resp_0 := make([][]byte, proto_params.T)
	resp_1 := make([][]byte, proto_params.T)
	for i := 0; i < proto_params.T; i++ {
		if chall_2[i] == false {
			resp_0[i] = append([]byte{y[i]}, v_bar[i]...)
			resp_1[i] = cmt_1[i]
		}
	}
	sgn := append(append(append(append(append(append(salt, digest_cmt...), digest_chall_2...), common.Flatten(path)...),
		common.Flatten(proof)...), common.Flatten(resp_0)...), common.Flatten(resp_1)...)
	return sgn, nil

}

// TODO: This needs to Fisher-Yates shuffle
func expand_digest_to_fixed_weight(digest_chall_2 []byte, proto_params common.ProtocolData) []bool {
	chall_2 := make([]byte, proto_params.T)
	sha3.ShakeSum128(chall_2, append(digest_chall_2, byte(3*proto_params.T))) // 3*T = T+c+1

	bool_chall_2 := make([]bool, proto_params.T)
	for i := range chall_2 {
		bool_chall_2[i] = chall_2[i]%2 == 1
	}

	return bool_chall_2
}
