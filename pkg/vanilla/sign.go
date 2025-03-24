package vanilla

import (
	"PQC-Master-Thesis/internal/common"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// TODO: This needs to Fisher-Yates shuffle
func (c *CROSSInstance) expand_digest_to_fixed_weight(digest_chall_2 []byte) []bool {
	chall_2 := make([]byte, c.ProtocolData.T)
	sha3.ShakeSum128(chall_2, append(digest_chall_2, byte(3*c.ProtocolData.T))) // 3*T = T+c+1

	bool_chall_2 := make([]bool, c.ProtocolData.T)
	for i := range chall_2 {
		bool_chall_2[i] = chall_2[i]%2 == 1
	}

	return bool_chall_2
}

func (c *CROSSInstance) Expand_sk(seed_sk []byte) ([]int, []byte, []byte, []byte, error) {
	dsc := uint16(0 + 3*c.ProtocolData.T + 1)
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {

		seed_e_seed_pk, err := c.CSPRNG(seed_sk, (4*c.ProtocolData.Lambda)/8, dsc)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		V_tr, _, err := c.Expand_pk(seed_e_seed_pk[2*c.ProtocolData.Lambda/8:])
		if err != nil {
			return nil, nil, nil, nil, err
		}
		e_bar, err := c.CSPRNG_fz_vec(seed_e_seed_pk[:2*c.ProtocolData.Lambda/8])
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return V_tr, e_bar, nil, nil, nil
	} else if c.ProtocolData.Variant() == common.VARIANT_RSDP_G {
		seed_e_seed_pk, err := c.CSPRNG(seed_sk, (4*c.ProtocolData.Lambda)/8, dsc)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		V_tr, W_mat, err := c.Expand_pk(seed_e_seed_pk[2*c.ProtocolData.Lambda/8:])
		if err != nil {
			return nil, nil, nil, nil, err
		}
		e_G_bar, err := c.CSPRNG_fz_inf_w(seed_e_seed_pk[:2*c.ProtocolData.Lambda/8])
		if err != nil {
			return nil, nil, nil, nil, err
		}
		e_bar := c.Fz_inf_w_by_fz_matrix(e_G_bar, W_mat)
		norm_e_bar := c.Fz_dz_norm_n(e_bar)
		return V_tr, W_mat, e_G_bar, norm_e_bar, nil
	}
	return nil, nil, nil, nil, fmt.Errorf("Invalid variant")
}

func element_wise_mul(v, u_prime []byte, Z int) []byte {
	result := make([]byte, len(v))
	for i := range v {
		result[i] = byte(v[i]*u_prime[i]) % byte(Z)
	}
	return result
}

func (c *CROSSInstance) Sign(sk, msg []byte) ([][]byte, error) {
	e_bar, e_G_bar, V_tr, W_mat, err := c.Expand_sk(sk)
	root_seed := make([]byte, c.ProtocolData.Lambda/8)
	salt := make([]byte, c.ProtocolData.Lambda/8)
	rand.Read(root_seed)
	rand.Read(salt)
	round_seeds, err := c.SeedLeaves(root_seed, salt)
	if err != nil {
		return nil, fmt.Errorf("Error building seed leaves: %v", err)
	}
	e_bar_prime := make([]byte, c.ProtocolData.T*c.ProtocolData.N)
	v_bar := make([]byte, c.ProtocolData.T*c.ProtocolData.N)
	u_prime := make([]byte, c.ProtocolData.T*c.ProtocolData.N)
	s_prime := make([]byte, c.ProtocolData.N-c.ProtocolData.K)
	cmt_0 := make([]byte, c.ProtocolData.T*((2*c.ProtocolData.Lambda)/8))
	cmt_1 := make([]byte, c.ProtocolData.T*((2*c.ProtocolData.Lambda)/8))
	v_G_bar := make([]byte, c.ProtocolData.T*c.ProtocolData.M)
	for i := 0; i < c.ProtocolData.T; i++ {
		csprng_input := append(round_seeds[i], salt...)
		dsc := uint16(0 + i + (2*c.ProtocolData.T - 1))
		round_state, err := c.CSPRNG_init(csprng_input, dsc)
		if err != nil {
			return nil, fmt.Errorf("Error initializing CSPRNG: %v", err)
		}
		if c.ProtocolData.Variant() == common.VARIANT_RSDP {
			e_bar_prime_i, state, err := c.CSPRNG_fz_vec_prime(round_state)
			round_state = state
			if err != nil {
				return nil, fmt.Errorf("Error generating e_bar_prime: %v", err)
			}
			copy(e_bar_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], e_bar_prime_i)
		} else {
			e_G_bar_prime, state, err := c.CSPRNG_fz_inf_w_prime(round_state)
			round_state = state
			if err != nil {
				return nil, fmt.Errorf("Error generating e_G_bar_prime: %v", err)
			}
			v_G_val := c.Fz_vec_sub_m(e_G_bar, e_G_bar_prime)
			v_G_val = c.Fz_dz_norm_m(v_G_val)
			copy(v_G_bar[i*c.ProtocolData.M:(i+1)*c.ProtocolData.M], v_G_val)
			e_bar_prime_i := c.Fz_inf_w_by_fz_matrix(e_G_bar_prime, W_mat)
			e_bar_prime_i = c.Fz_dz_norm_n(e_bar_prime_i)
		}
		v_bar_i := c.Fz_vec_sub_n(e_bar, e_bar_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N])
		v := c.Convert_restr_vec_to_fp(v_bar_i)
		v_bar = c.Fz_dz_norm_n(v_bar_i)
		copy(v_bar[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], v_bar_i)
		u_prime_i, err := c.CSPRNG_fp_vec_prime(round_state)
		if err != nil {
			return nil, fmt.Errorf("Error generating u_prime: %v", err)
		}
		copy(u_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], u_prime_i)
		u := c.Fp_vec_by_fp_vec_pointwise(v, u_prime_i)
		s_prime := c.Fp_vec_by_fp_matrix(u, V_tr)
		s_prime = c.Fp_dz_norm_synd(s_prime)
		var cmt_0_i_input []byte
		if c.ProtocolData.Variant() == common.VARIANT_RSDP {
			s_prime = c.Pack_fp_syn(s_prime)
			copy(cmt_0_i_input, append(append(s_prime, make([]byte, c.ProtocolData.N)...), salt...))
		} else {
			//TODO: FIX TYPE!
			res := make([]uint16, len(s_prime))
			for i := range s_prime {
				res[i] = uint16(s_prime[i])
			}
			s_prime = c.Pack_fp_syn_RSDPG(res)
			copy(cmt_0_i_input, append(append(s_prime, make([]byte, c.ProtocolData.T*c.ProtocolData.M)...), salt...))
		}

	}
}

/*
func (c *CROSSInstance) Sign(sk, msg []byte) ([][]byte, error) {
	e_bar, H := c.Expand_sk(sk)
	C := 2*c.ProtocolData.T - 1
	seed := make([]byte, c.ProtocolData.Lambda/8)
	salt := make([]byte, (2*c.ProtocolData.Lambda)/8)
	rand.Read(seed)
	rand.Read(salt)
	commitments, err := c.SeedLeaves(seed, salt)
	if err != nil {
		return nil, fmt.Errorf("Error building seed leaves: %v", err)
	}
	e_bar_prime := make([][]byte, c.ProtocolData.T)
	u_prime := make([][]byte, c.ProtocolData.T)
	v_bar := make([][]byte, c.ProtocolData.T)
	v := make([][]byte, c.ProtocolData.T)
	u := make([][]byte, c.ProtocolData.T)
	s_prime := make([][]byte, c.ProtocolData.T)
	cmt_0 := make([][]byte, c.ProtocolData.T)
	cmt_1 := make([][]byte, c.ProtocolData.T)
	for i := 0; i < c.ProtocolData.T; i++ {
		// TODO: PROPER SAMPLING!
		e_bar_buffer := make([]byte, c.ProtocolData.N)
		sha3.ShakeSum128(e_bar_buffer, append(append(commitments[i], salt...), byte(i+C)))
		for i, v := range e_bar_buffer {
			e_bar_buffer[i] = v%byte(c.ProtocolData.Z-1) + 1
		}
		e_bar_prime[i] = e_bar_buffer

		u_prime_buffer := make([]byte, c.ProtocolData.N)
		sha3.ShakeSum128(u_prime_buffer, append(append(commitments[i], salt...), byte(i+C)))
		for i, v := range u_prime_buffer {
			e_bar_buffer[i] = v%byte(c.ProtocolData.P-1) + 1
		}
		u_prime[i] = u_prime_buffer
		v_bar[i] = fz_vec_sub(e_bar, e_bar_prime[i])
		v_buffer := make([]byte, c.ProtocolData.N)
		for j := 0; j < c.ProtocolData.N; j++ {
			v_buffer[j] = byte(new(big.Int).Exp(big.NewInt(int64(c.ProtocolData.G)), big.NewInt(int64(v_bar[i][j])), nil).Int64())
		}
		v[i] = v_buffer
		u[i] = element_wise_mul(v[i], u_prime[i], c.ProtocolData.Z)
		s_prime[i] = common.MultiplyVectorMatrix(u[i], common.TransposeByteMatrix(H))
		cmt_0_buffer := make([]byte, (2*c.ProtocolData.Lambda)/8)
		sha3.ShakeSum128(cmt_0_buffer, append(append(append(s_prime[i], v_bar[i]...), salt...), byte(i+C)))
		cmt_0[i] = cmt_0_buffer

		cmt_1_buffer := make([]byte, (2*c.ProtocolData.Lambda)/8)
		sha3.ShakeSum128(cmt_1_buffer, append(append(commitments[i], salt...), byte(i+C)))
		cmt_1[i] = cmt_1_buffer
	}
	digest_cmt_0, err := c.TreeRoot(cmt_0)
	digest_cmt_1 := make([]byte, (2*c.ProtocolData.Lambda)/8)
	flat_cmt_1 := make([]byte, 0)
	for _, b := range cmt_1 {
		flat_cmt_1 = append(flat_cmt_1, b...)
	}
	sha3.ShakeSum128(digest_cmt_1, flat_cmt_1)
	digest_cmt := make([]byte, (2*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(digest_cmt, append(digest_cmt_0, digest_cmt_1...))

	digest_msg := make([]byte, (2*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(digest_msg, msg)
	digest_chall_1 := make([]byte, (2*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(digest_chall_1, append(append(digest_msg, digest_cmt...), salt...))
	//TODO: CSPRNG output needs to be in (F_p^*)^t, and fix value, gives us a problem with y[i] =
	chall_1 := make([]byte, c.ProtocolData.T)
	sha3.ShakeSum128(chall_1, append(digest_chall_1, byte(c.ProtocolData.T+C)))
	for i := range chall_1 {
		// -1, +1 to avoid 0
		chall_1[i] = chall_1[i]%byte(c.ProtocolData.P-1) + 1
	}
	var y []byte
	e_prime := make([][]byte, c.ProtocolData.T)
	for i := 0; i < c.ProtocolData.T; i++ {
		e_prime_i := make([]byte, c.ProtocolData.N)
		for j := 0; j < c.ProtocolData.N; j++ {
			//TODO: FIX THIS BULLSHIT MOST LIKELY QUITE WRONG!
			result := new(big.Int).Exp(big.NewInt(int64(c.ProtocolData.G)), big.NewInt(int64(e_bar_prime[i][j])), big.NewInt(int64(c.ProtocolData.P)))
			e_prime_i[j] = result.Bytes()[0]
			ctr := 0
			for _ = range e_prime_i[j] {
				ctr++
			}
			fmt.Println("Length of e_prime_i[j] = ", ctr, " Should be 1")
		}
		e_prime[i] = e_prime_i
		//TODO: Make sure this is correct
		y = common.ScalarVecMulByte(e_prime[i], chall_1[i])
		for j := 0; j < len(y); j++ {
			y[j] = (y[j] + u_prime[i][j]) % byte(255)
		}
	}
	digest_chall_2 := make([]byte, (2*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(digest_chall_2, append(y[:c.ProtocolData.T], digest_chall_1...))
	chall_2 := c.expand_digest_to_fixed_weight(digest_chall_2)
	proof, err := c.TreeProof(cmt_0, chall_2)
	if err != nil {
		return nil, fmt.Errorf("Error generating proof: %v", err)
	}
	path, err := c.SeedPath(seed, salt, chall_2)
	if err != nil {
		return nil, fmt.Errorf("Error generating seed path: %v", err)
	}
	//TODO: Ensure compatibility with refernce code for this
	resp_0 := make([][]byte, c.ProtocolData.T)
	resp_1 := make([][]byte, c.ProtocolData.T)
	for i := 0; i < c.ProtocolData.T; i++ {
		if chall_2[i] == false {
			resp_0[i] = append([]byte{y[i]}, v_bar[i]...)
			resp_1[i] = cmt_1[i]
		}
	}
	//TODO: Temporary way of creating the signature, needs to pack properly
	sgn := make([][]byte, 7)
	sgn[0] = salt
	sgn[1] = digest_cmt
	sgn[2] = digest_chall_2
	sgn[3] = common.Flatten(path)
	sgn[4] = common.Flatten(proof)
	sgn[5] = common.Flatten(resp_0)
	sgn[6] = common.Flatten(resp_1)
	//sgn := append(append(append(append(append(append(salt, digest_cmt...), digest_chall_2...), common.Flatten(path)...),
	//		common.Flatten(proof)...), common.Flatten(resp_0)...), common.Flatten(resp_1)...)
	return sgn, nil
}

// DummySign is a dummy implementation of the Sign function, used for testing purposes ONLY
func (c *CROSSInstance) DummySign(sk, msg, seed, salt []byte) ([][]byte, error) {
	e_bar, H := vanilla.Expand_sk(sk)
	C := 2*c.ProtocolData.T - 1
	commitments, err := c.SeedLeaves(seed, salt)
	if err != nil {
		return nil, fmt.Errorf("Error building seed leaves: %v", err)
	}
	e_bar_prime := make([][]byte, c.ProtocolData.T)
	u_prime := make([][]byte, c.ProtocolData.T)
	v_bar := make([][]byte, c.ProtocolData.T)
	v := make([][]byte, c.ProtocolData.T)
	u := make([][]byte, c.ProtocolData.T)
	s_prime := make([][]byte, c.ProtocolData.T)
	cmt_0 := make([][]byte, c.ProtocolData.T)
	cmt_1 := make([][]byte, c.ProtocolData.T)
	for i := 0; i < c.ProtocolData.T; i++ {
		// TODO: PROPER SAMPLING!
		e_bar_buffer := make([]byte, c.ProtocolData.N)
		sha3.ShakeSum128(e_bar_buffer, append(append(commitments[i], salt...), byte(i+C)))
		for i, v := range e_bar_buffer {
			e_bar_buffer[i] = v%byte(c.ProtocolData.Z-1) + 1
		}
		e_bar_prime[i] = e_bar_buffer

		u_prime_buffer := make([]byte, c.ProtocolData.N)
		sha3.ShakeSum128(u_prime_buffer, append(append(commitments[i], salt...), byte(i+C)))
		for i, v := range u_prime_buffer {
			e_bar_buffer[i] = v%byte(c.ProtocolData.P-1) + 1
		}
		u_prime[i] = u_prime_buffer
		v_bar[i] = fz_vec_sub(e_bar, e_bar_prime[i])
		v_buffer := make([]byte, c.ProtocolData.N)
		for j := 0; j < c.ProtocolData.N; j++ {
			v_buffer[j] = byte(new(big.Int).Exp(big.NewInt(int64(c.ProtocolData.G)), big.NewInt(int64(v_bar[i][j])), nil).Int64())
		}
		v[i] = v_buffer
		u[i] = element_wise_mul(v[i], u_prime[i], c.ProtocolData.Z)
		s_prime[i] = common.MultiplyVectorMatrix(u[i], common.TransposeByteMatrix(H))
		cmt_0_buffer := make([]byte, (2*c.ProtocolData.Lambda)/8)
		sha3.ShakeSum128(cmt_0_buffer, append(append(append(s_prime[i], v_bar[i]...), salt...), byte(i+C)))
		cmt_0[i] = cmt_0_buffer

		cmt_1_buffer := make([]byte, (2*c.ProtocolData.Lambda)/8)
		sha3.ShakeSum128(cmt_1_buffer, append(append(commitments[i], salt...), byte(i+C)))
		cmt_1[i] = cmt_1_buffer
	}
	digest_cmt_0, err := c.TreeRoot(cmt_0)
	digest_cmt_1 := make([]byte, (2*c.ProtocolData.Lambda)/8)
	flat_cmt_1 := make([]byte, 0)
	for _, b := range cmt_1 {
		flat_cmt_1 = append(flat_cmt_1, b...)
	}
	sha3.ShakeSum128(digest_cmt_1, flat_cmt_1)
	digest_cmt := make([]byte, (2*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(digest_cmt, append(digest_cmt_0, digest_cmt_1...))

	digest_msg := make([]byte, (2*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(digest_msg, msg)
	digest_chall_1 := make([]byte, (2*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(digest_chall_1, append(append(digest_msg, digest_cmt...), salt...))
	//TODO: CSPRNG output needs to be in (F_p^*)^t, and fix value, gives us a problem with y[i] =
	chall_1 := make([]byte, c.ProtocolData.T)
	sha3.ShakeSum128(chall_1, append(digest_chall_1, byte(c.ProtocolData.T+C)))
	for i := range chall_1 {
		// -1, +1 to avoid 0
		chall_1[i] = chall_1[i]%byte(c.ProtocolData.P-1) + 1
	}
	var y []byte
	e_prime := make([][]byte, c.ProtocolData.T)
	for i := 0; i < c.ProtocolData.T; i++ {
		e_prime_i := make([]byte, c.ProtocolData.N)
		for j := 0; j < c.ProtocolData.N; j++ {
			//TODO: FIX THIS BULLSHIT MOST LIKELY QUITE WRONG!
			result := new(big.Int).Exp(big.NewInt(int64(c.ProtocolData.G)), big.NewInt(int64(e_bar_prime[i][j])), big.NewInt(int64(c.ProtocolData.P)))
			e_prime_i[j] = result.Bytes()[0]
			ctr := 0
			for _ = range e_prime_i[j] {
				ctr++
			}
			fmt.Println("Length of e_prime_i[j] = ", ctr, " Should be 1")
		}
		e_prime[i] = e_prime_i
		//TODO: Make sure this is correct
		y = common.ScalarVecMulByte(e_prime[i], chall_1[i])
		for j := 0; j < len(y); j++ {
			y[j] = (y[j] + u_prime[i][j]) % byte(255)
		}
	}
	digest_chall_2 := make([]byte, (2*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(digest_chall_2, append(y[:c.ProtocolData.T], digest_chall_1...))
	chall_2 := c.expand_digest_to_fixed_weight(digest_chall_2)
	proof, err := c.TreeProof(cmt_0, chall_2)
	if err != nil {
		return nil, fmt.Errorf("Error generating proof: %v", err)
	}
	path, err := c.SeedPath(seed, salt, chall_2)
	if err != nil {
		return nil, fmt.Errorf("Error generating seed path: %v", err)
	}
	//TODO: Ensure compatibility with refernce code for this
	resp_0 := make([][]byte, c.ProtocolData.T)
	resp_1 := make([][]byte, c.ProtocolData.T)
	for i := 0; i < c.ProtocolData.T; i++ {
		if chall_2[i] == false {
			resp_0[i] = append([]byte{y[i]}, v_bar[i]...)
			resp_1[i] = cmt_1[i]
		}
	}
	//TODO: Temporary way of creating the signature, needs to pack properly
	sgn := make([][]byte, 7)
	sgn[0] = salt
	sgn[1] = digest_cmt
	sgn[2] = digest_chall_2
	sgn[3] = common.Flatten(path)
	sgn[4] = common.Flatten(proof)
	sgn[5] = common.Flatten(resp_0)
	sgn[6] = common.Flatten(resp_1)
	//sgn := append(append(append(append(append(append(salt, digest_cmt...), digest_chall_2...), common.Flatten(path)...),
	//		common.Flatten(proof)...), common.Flatten(resp_0)...), common.Flatten(resp_1)...)
	return sgn, nil

}
*/
