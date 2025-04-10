package vanilla

import (
	"PQC-Master-Thesis/internal/common"
	"bytes"
	"fmt"
)

func (c *CROSSInstance[T, P]) int16ToT(arr []int) []T {
	res := make([]T, len(arr))
	for i := range arr {
		res[i] = T(arr[i])
	}
	return res
}

// TODO: Check if we are allowed to bail out early, maybe should wait till final check
func (c *CROSSInstance[T, P]) Verify(pk Pub, m []byte, sig Signature) (bool, error) {
	// Length checks for all attributes of the signature
	valid_signature := true
	if len(sig.Salt) != 2*c.ProtocolData.Lambda/8 {
		valid_signature = false
	}
	if len(sig.Digest_cmt) != 2*c.ProtocolData.Lambda/8 {
		valid_signature = false
	}
	if len(sig.Digest_chall_2) != 2*c.ProtocolData.Lambda/8 {
		valid_signature = false
	}

	if c.ProtocolData.IsType(common.TYPE_BALANCED, common.TYPE_SMALL) {
		if len(sig.Path) != c.ProtocolData.TREE_NODES_TO_STORE {
			valid_signature = false
		}
		if len(sig.Proof) != c.ProtocolData.TREE_NODES_TO_STORE {
			valid_signature = false
		}
	} else {
		if len(sig.Path) != c.ProtocolData.W {
			valid_signature = false
		}
		if len(sig.Proof) != c.ProtocolData.W {
			valid_signature = false
		}
	}
	if len(sig.Resp_0) != c.ProtocolData.T-c.ProtocolData.W {
		for i := 0; i < c.ProtocolData.T-c.ProtocolData.W; i++ {
			if len(sig.Resp_0[i].Y) != c.DenselyPackedFpVecSize() {
				valid_signature = false
			}
			if c.ProtocolData.Variant() == common.VARIANT_RSDP {
				if len(sig.Resp_0[i].V_bar) != c.DenselyPackedFzVecSize() {
					valid_signature = false
				}
			} else {
				if len(sig.Resp_0[i].V_G_bar) != c.DenselyPackedFzRSDPGVecSize() {
					valid_signature = false
				}
			}
		}
	}
	if len(sig.Resp_1) != (c.ProtocolData.T-c.ProtocolData.W)*((2*c.ProtocolData.Lambda)/8) {
		valid_signature = false
	}
	if !valid_signature {
		return false, fmt.Errorf("invalid signature")
	}
	V_tr, W_mat, err := c.Expand_pk(pk.SeedPK)
	if err != nil {
		return false, err
	}
	s, is_padd_key_ok := c.Unpack_fp_syn(pk.S)
	digest_msg_cmt_salt := make([]byte, 3*(2*c.ProtocolData.Lambda/8))
	hash_val, err := c.CSPRNG(m, 2*c.ProtocolData.Lambda/8, uint16(32768))
	if err != nil {
		return false, err
	}
	copy(digest_msg_cmt_salt, hash_val)
	copy(digest_msg_cmt_salt[(2*c.ProtocolData.Lambda/8):], sig.Digest_cmt)
	copy(digest_msg_cmt_salt[2*(2*c.ProtocolData.Lambda/8):], sig.Salt)
	digest_chall_1, err := c.CSPRNG(digest_msg_cmt_salt, 2*c.ProtocolData.Lambda/8, uint16(32768))
	if err != nil {
		return false, err
	}
	chall_1, err := c.CSPRNG_fp_vec_chall_1(digest_chall_1)
	if err != nil {
		return false, err
	}
	chall_2, err := c.Expand_digest_to_fixed_weight(sig.Digest_chall_2)
	if err != nil {
		return false, err
	}
	round_seeds, is_stree_padding_ok, err := c.RebuildLeaves(sig.Path, sig.Salt, chall_2)
	if err != nil {
		return false, err
	}
	var cmt_0_i_input []byte
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		cmt_0_i_input = make([]byte, int(c.DenselyPackedFpSynSize())+c.DenselyPackedFzVecSize()+(2*c.ProtocolData.Lambda/8))
		copy(cmt_0_i_input[int(c.DenselyPackedFpSynSize())+c.DenselyPackedFzVecSize():], sig.Salt)
	} else {
		cmt_0_i_input = make([]byte, int(c.DenselyPackedFpSynSize())+c.DenselyPackedFzRSDPGVecSize()+(2*c.ProtocolData.Lambda/8))
		copy(cmt_0_i_input[int(c.DenselyPackedFpSynSize())+c.DenselyPackedFzRSDPGVecSize():], sig.Salt)

	}
	//remember to add salt, makes every dish more tasty
	cmt_1_i_input := make([]byte, 3*c.ProtocolData.Lambda/8)
	copy(cmt_1_i_input[c.ProtocolData.Lambda/8:], sig.Salt)
	cmt_0 := make([][]byte, c.ProtocolData.T)
	for i := 0; i < c.ProtocolData.T; i++ {
		cmt_0[i] = make([]byte, 2*c.ProtocolData.Lambda/8)
	}
	cmt_1 := make([]byte, c.ProtocolData.T*(2*c.ProtocolData.Lambda/8))
	e_bar_prime := make([]byte, c.ProtocolData.N)
	u_prime := make([]T, c.ProtocolData.N)
	y_prime := make([]T, c.ProtocolData.N)
	y_prime_H := make([]T, c.ProtocolData.N-c.ProtocolData.K)
	s_prime := make([]T, c.ProtocolData.N-c.ProtocolData.K)
	y := make([]T, c.ProtocolData.T*c.ProtocolData.N)
	v_bar := make([]byte, c.ProtocolData.N)
	used_rsps := 0
	is_signature_ok := true
	is_packed_padd_ok := true
	for i := 0; i < c.ProtocolData.T; i++ {
		domain_sep_csprng := uint16(0 + i + (2*c.ProtocolData.T - 1))
		domain_sep_hash := uint16(32768 + i + (2*c.ProtocolData.T - 1))
		if chall_2[i] {
			copy(cmt_1_i_input, round_seeds[i])
			cmt_1_val, err := c.CSPRNG(cmt_1_i_input, 2*c.ProtocolData.Lambda/8, domain_sep_hash)
			if err != nil {
				return false, err
			}
			copy(cmt_1[i*(2*c.ProtocolData.Lambda/8):], cmt_1_val)
			csprng_input := make([]byte, 3*c.ProtocolData.Lambda/8)
			copy(csprng_input, round_seeds[i])
			copy(csprng_input[c.ProtocolData.Lambda/8:], sig.Salt)
			state, err := c.CSPRNG_init(csprng_input, domain_sep_csprng)
			if err != nil {
				return false, err
			}
			if c.ProtocolData.Variant() == common.VARIANT_RSDP {
				e_bar_prime, _, err = c.CSPRNG_fz_vec_prime(state)
				if err != nil {
					return false, err
				}
			} else {
				e_G_bar_prime, _, err := c.CSPRNG_fz_inf_w_prime(state)
				if err != nil {
					return false, err
				}
				e_bar_prime = c.Fz_inf_w_by_fz_matrix(e_G_bar_prime, W_mat)
				e_bar_prime = c.Fz_dz_norm_n(e_bar_prime)
			}
			u_prime, err = c.CSPRNG_fp_vec_prime(state)
			if err != nil {
				return false, err
			}
			copy(y[i*c.ProtocolData.N:], c.Fp_vec_by_restr_vec_scaled(c.byteToT(e_bar_prime), u_prime, chall_1[i]))
			copy(y[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], c.Fp_dz_norm(y[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N]))
		} else {
			temp_val, bool_res := c.Unpack_fp_vec(sig.Resp_0[used_rsps].Y)
			copy(y[i*c.ProtocolData.N:], temp_val)
			is_packed_padd_ok = is_packed_padd_ok && bool_res
			if c.ProtocolData.Variant() == common.VARIANT_RSDP {
				v_bar, bool_res = c.Unpack_fz_vec(sig.Resp_0[used_rsps].V_bar)
				is_packed_padd_ok = is_packed_padd_ok && bool_res
				copy(cmt_0_i_input[c.DenselyPackedFpSynSize():], sig.Resp_0[used_rsps].V_bar)
				is_signature_ok = is_signature_ok && c.Is_fz_vec_in_restr_group_n(v_bar)
			} else {
				copy(cmt_0_i_input[c.DenselyPackedFpSynSize():], sig.Resp_0[used_rsps].V_G_bar)
				v_G_bar, padd_bool := c.Unpack_fz_rsdp_g_vec(sig.Resp_0[used_rsps].V_G_bar)
				is_packed_padd_ok = is_packed_padd_ok && padd_bool
				is_signature_ok = is_signature_ok && c.Is_fz_vec_in_restr_group_m(v_G_bar)
				v_bar = c.Fz_inf_w_by_fz_matrix(v_G_bar, W_mat)
			}
			copy(cmt_1[i*(2*c.ProtocolData.Lambda/8):], sig.Resp_1[used_rsps*(2*c.ProtocolData.Lambda/8):(used_rsps+1)*(2*c.ProtocolData.Lambda/8)])
			used_rsps++
			v := c.Convert_restr_vec_to_fp(v_bar)
			y_prime = c.Fp_vec_by_fp_vec_pointwise(v, y[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N])
			y_prime_H = c.Fp_vec_by_fp_matrix(y_prime, c.int16ToT(V_tr))
			y_prime_H = c.Fp_dz_norm_synd(y_prime_H)
			s_prime = c.Fp_synd_minus_fp_vec_scaled(y_prime_H, chall_1[i], s)
			s_prime = c.Fp_dz_norm_synd(s_prime)
			copy(cmt_0_i_input, c.Pack_fp_syn(s_prime))
			hash_val, err = c.CSPRNG(cmt_0_i_input, 2*c.ProtocolData.Lambda/8, domain_sep_hash)
			if err != nil {
				return false, err
			}
			cmt_0[i] = hash_val
		}
	}
	digest_cmt_0_cmt_1 := make([]byte, 2*(2*c.ProtocolData.Lambda/8))
	digest_val, is_mtree_padding_ok, err := c.RecomputeRoot(cmt_0, sig.Proof, chall_2)
	// TODO: set this to recomputeroot's result
	if err != nil {
		return false, err
	}
	copy(digest_cmt_0_cmt_1, digest_val)
	digest_hash_val, err := c.CSPRNG(cmt_1, 2*c.ProtocolData.Lambda/8, uint16(32768))
	if err != nil {
		return false, err
	}
	copy(digest_cmt_0_cmt_1[2*c.ProtocolData.Lambda/8:], digest_hash_val)
	digest_cmt_prime, err := c.CSPRNG(digest_cmt_0_cmt_1, 2*c.ProtocolData.Lambda/8, uint16(32768))
	if err != nil {
		return false, err
	}
	y_digest_chall_1 := make([]byte, c.ProtocolData.T*c.DenselyPackedFpVecSize()+(2*c.ProtocolData.Lambda/8))
	for x := 0; x < c.ProtocolData.T; x++ {
		copy(y_digest_chall_1[x*c.DenselyPackedFpVecSize():(x+1)*c.DenselyPackedFpVecSize()], c.Pack_fp_vec(y[x*c.ProtocolData.N:(x+1)*c.ProtocolData.N]))
	}
	copy(y_digest_chall_1[c.ProtocolData.T*c.DenselyPackedFpVecSize():], digest_chall_1)
	digest_chall_2_prime, err := c.CSPRNG(y_digest_chall_1, 2*c.ProtocolData.Lambda/8, uint16(32768))
	if err != nil {
		return false, err
	}
	does_digest_cmt_match := bytes.Equal(digest_cmt_prime, sig.Digest_cmt)
	does_digest_chall_2_match := bytes.Equal(digest_chall_2_prime, sig.Digest_chall_2)
	fmt.Println("is_signature_ok: ", is_signature_ok)
	fmt.Println("does_digest_cmt_match: ", does_digest_cmt_match)
	fmt.Println("does_digest_chall_2_match: ", does_digest_chall_2_match)
	fmt.Println("is_mtree_padding_ok: ", is_mtree_padding_ok)
	fmt.Println("is_stree_padding_ok: ", is_stree_padding_ok)
	fmt.Println("is_padd_key_ok: ", is_padd_key_ok)
	fmt.Println("is_packed_padd_ok: ", is_packed_padd_ok)

	is_signature_ok = is_signature_ok &&
		does_digest_cmt_match &&
		does_digest_chall_2_match &&
		is_mtree_padding_ok &&
		is_stree_padding_ok &&
		is_padd_key_ok &&
		is_packed_padd_ok
	return is_signature_ok, nil
}

/*
func (c *CROSSInstance[T, P]) Verify(pk Pub, msg, sig []byte) (bool, error) {
	//TODO: Unpack signature
	salt, digest_cmt, digest_chall_2, err := unpackSignature(sig, c.ProtocolData)
	if err != nil {
		return false, fmt.Errorf("Error unpacking signature: %v", err)
	}

	//TODO: Don't bail out early, just return false in the end
	//TODO: When doing g^something ensure that it is a valid byte (check reference code)
	sgn := make([][]byte, 7)
	salt := sgn[0]
	digest_cmt := sgn[1]
	digest_chall_2 := sgn[2]
	path := c.unpackPath(sgn[3])
	proof := common.Unflatten(sgn[4], c.TreeParams.Total_nodes)
	resp_0 := common.Unflatten(sgn[5], c.ProtocolData.T)
	resp_1 := common.Unflatten(sgn[6], c.ProtocolData.T)

	C := 2*c.ProtocolData.T - 1
	n_minus_k := c.ProtocolData.N - c.ProtocolData.K
	V := make([][]byte, n_minus_k)
	for i := range V {
		V[i] = make([]byte, c.ProtocolData.K)
	}
	buffer := make([]byte, n_minus_k*c.ProtocolData.K)

	// Security probably dies here since p=509 in RSDP-G, might be fine for RSDP
	sha3.ShakeSum128(buffer, append(pk.SeedPK, byte(3*c.ProtocolData.T+2)))
	idx := 0
	for i := 0; i < n_minus_k; i++ {
		for j := 0; j < c.ProtocolData.K; j++ {
			// Ensure values are in Fp
			V[i][j] = buffer[idx]%byte(c.ProtocolData.P-1) + 1
			if V[i][j] > byte(c.ProtocolData.P) {
				return false, fmt.Errorf("V[i][j] > P")
			}
			idx++
		}
	}

	H := make([][]byte, n_minus_k)
	for i := range H {
		H[i] = make([]byte, c.ProtocolData.N)
		// Copy V part
		copy(H[i][:c.ProtocolData.K], V[i])
		// Add identity matrix part
		H[i][c.ProtocolData.K+i] = 1
	}
	digest_msg := make([]byte, (2*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(digest_msg, msg)
	digest_chall_1 := make([]byte, (2*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(digest_chall_1, append(append(digest_msg, digest_cmt...), salt...))
	chall_1 := make([]byte, c.ProtocolData.T)
	sha3.ShakeSum128(chall_1, append(digest_chall_1, byte(c.ProtocolData.T+C)))
	chall_2, err := c.Expand_digest_to_fixed_weight(digest_chall_2)
	seed, err := c.RebuildLeaves(path, salt, chall_2)
	if err != nil {
		return false, fmt.Errorf("Error rebuilding leaves: %v", err)
	}
	cmt_1 := make([][]byte, c.ProtocolData.T)
	cmt_0 := make([][]byte, c.ProtocolData.T)
	e_bar_prime := make([][]byte, c.ProtocolData.T)
	u_prime := make([][]byte, c.ProtocolData.T)
	var y [][]byte
	for i := 0; i < c.ProtocolData.T; i++ {
		if chall_2[i] {
			buffer := make([]byte, (2*c.ProtocolData.Lambda)/8)
			sha3.ShakeSum128(buffer, append(append(seed[i], salt...), byte(i+C)))
			cmt_1[i] = buffer

			e_bar_buffer := make([]byte, c.ProtocolData.N)
			sha3.ShakeSum128(e_bar_buffer, append(append(seed[i], salt...), byte(i+C)))
			for i, v := range e_bar_buffer {
				e_bar_buffer[i] = v%byte(c.ProtocolData.Z-1) + 1
			}
			e_bar_prime[i] = e_bar_buffer

			u_prime_buffer := make([]byte, c.ProtocolData.N)
			sha3.ShakeSum128(u_prime_buffer, append(append(seed[i], salt...), byte(i+C)))
			for i, v := range u_prime_buffer {
				e_bar_buffer[i] = v%byte(c.ProtocolData.P-1) + 1
			}
			u_prime[i] = u_prime_buffer
			// TODO: Investigate this part more
			e_prime := make([][]byte, c.ProtocolData.N)
			for j := 0; j < c.ProtocolData.N; j++ {
				e_prime[i][j] = byte(new(big.Int).Exp(big.NewInt(int64(c.ProtocolData.G)), big.NewInt(int64(e_bar_prime[i][j])), nil).Int64())
			}
			y[i] = common.ScalarVecMulByte(e_prime[i], chall_1[i])
			for idx, _ := range y[i] {
				y[i][idx] += u_prime[i][idx]
			}
		} else {
			cmt_1[i] = resp_1[i]
			y[i] = []byte{resp_0[i][0]}
			v_bar := resp_0[i][1:]
			if len(v_bar) != c.ProtocolData.N {
				return false, fmt.Errorf("v_bar has incorrect length")
			}
			//TODO: Check if valid constant time?
			valid := true
			for _, v := range v_bar {
				if v > byte(c.ProtocolData.Z) {
					valid = false
				}
			}
			if !valid {
				return false, fmt.Errorf("v_bar has invalid values")
			}
			v := make([]byte, c.ProtocolData.N)
			for j := 0; j < c.ProtocolData.N; j++ {
				v[j] = byte(new(big.Int).Exp(big.NewInt(int64(c.ProtocolData.G)), big.NewInt(int64(v_bar[j])), nil).Int64())
			}
			y_prime := make([]byte, c.ProtocolData.N)
			for idx, _ := range v {
				y_prime[idx] = v[idx] * y[i][idx]
			}
			//TODO: Implement @
			H_matrix, err := common.MatrixMultiplicationByte(common.TransposeByteMatrix(H), y_prime)
			if err != nil {
				return false, fmt.Errorf("Error multiplying matrix: %v", err)
			}
			s_chall_1 := common.ScalarVecMulByte(pk.S, chall_1[i])
			s_prime := make([]byte, n_minus_k)
			for idx, _ := range H_matrix {
				s_prime[idx] = H_matrix[idx] - s_chall_1[idx]
			}
			cmt_0_buffer := make([]byte, (2*c.ProtocolData.Lambda)/8)
			sha3.ShakeSum128(cmt_0_buffer, append(append(append([]byte{s_prime[i]}, v_bar[i]), salt...), byte(i+C)))
			cmt_0[i] = cmt_0_buffer
		}

	}
	digest_cmt_0, err := c.RecomputeRoot(cmt_0, proof, chall_2)
	if err != nil {
		return false, fmt.Errorf("Error recomputing root: %v", err)
	}
	//TODO: Check if any of these need additional domain seperator inputs
	digest_cmt_1 := make([]byte, (2*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(digest_cmt_1, common.Flatten(cmt_1))
	digest_prime_cmt := make([]byte, (2*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(digest_prime_cmt, append(digest_cmt_0, digest_cmt_1...))
	digest_prime_chall_2 := make([]byte, (2*c.ProtocolData.Lambda)/8)
	sha3.ShakeSum128(digest_prime_chall_2, append(common.Flatten(y), digest_chall_1...))
	// TODO: Probably replace true with the error variable throughout it all
	if bytes.Equal(digest_prime_cmt, digest_cmt) && bytes.Equal(digest_prime_chall_2, digest_chall_2) {
		return true, nil
	}
	return false, nil
}
*/
