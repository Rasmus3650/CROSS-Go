package vanilla

// TODO: Check if we are allowed to bail out early, maybe should wait till final check
func (c *CROSSInstance[T, P]) Verify(pk Pub, m []byte, sig Signature) (bool, error) {
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
	copy(digest_msg_cmt_salt[2*(2*c.ProtocolData.Lambda/8):], sig.Digest_cmt)
	copy(digest_msg_cmt_salt[3*(2*c.ProtocolData.Lambda/8):], sig.Salt)
	digest_chall_1, err := c.CSPRNG(digest_msg_cmt_salt, 2*c.ProtocolData.Lambda/8, uint16(32768))
	if err != nil {
		return false, err
	}
	chall_1, err := c.CSPRNG_fp_vec_chall_1(digest_chall_1)
	if err != nil {
		return false, err
	}
	chall_2, err := c.Expand_digest_to_fixed_weight(sig.Digest_chall_2)
	is_stree_padding_ok := false
	round_seeds, err := c.RebuildLeaves(sig.Path, sig.Salt, chall_2)
	if err != nil {
		return false, err
	}
	is_stree_padding_ok = true
	var cmt_0_i_input []byte
	//remember to add salt, makes every dish more tasty
	cmt_1_i_input := make([]byte, 3*c.ProtocolData.Lambda/8)
	copy(cmt_1_i_input[c.ProtocolData.Lambda/8:], sig.Salt)
	cmt_0 := make([]byte, c.ProtocolData.T*(2*c.ProtocolData.Lambda/8))
	cmt_1 := make([]byte, c.ProtocolData.T*(2*c.ProtocolData.Lambda/8))
	e_bar_prime := make([]byte, c.ProtocolData.N)
	u_prime := make([]T, c.ProtocolData.N)
	y_prime := make([]T, c.ProtocolData.N)
	y_prime_H := make([]T, c.ProtocolData.N-c.ProtocolData.K)
	s_prime := make([]T, c.ProtocolData.N-c.ProtocolData.K)
	y := make([]T, c.ProtocolData.T*c.ProtocolData.N)
	used_rsps := 0
	is_signature_ok := true
	is_packed_padd_ok := true
	//for loop starts here

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
