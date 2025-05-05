package vanilla

import (
	"PQC-Master-Thesis/internal/common"
	"crypto/rand"
	"fmt"
)

type resp_0_struct struct {
	Y       []byte
	V_bar   []byte
	V_G_bar []byte
}

type Signature struct {
	Salt           []byte
	Digest_cmt     []byte
	Digest_chall_2 []byte
	Path           [][]byte
	Proof          [][]byte
	Resp_1         []byte
	Resp_0         []resp_0_struct
}

func (c *CROSSInstance[T, P]) Expand_sk(seed_sk []byte) ([]T, []byte, []byte, []byte) {
	dsc := uint16(0 + 3*c.ProtocolData.T + 1)
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {

		seed_e_seed_pk := c.CSPRNG(seed_sk, (4*c.ProtocolData.Lambda)/8, dsc)
		V_tr, _ := c.Expand_pk(seed_e_seed_pk[2*c.ProtocolData.Lambda/8:])
		e_bar := c.CSPRNG_fz_vec(seed_e_seed_pk[:2*c.ProtocolData.Lambda/8])
		return V_tr, nil, nil, e_bar
	} else if c.ProtocolData.Variant() == common.VARIANT_RSDP_G {
		seed_e_seed_pk := c.CSPRNG(seed_sk, (4*c.ProtocolData.Lambda)/8, dsc)
		V_tr, W_mat := c.Expand_pk(seed_e_seed_pk[2*c.ProtocolData.Lambda/8:])
		e_G_bar := c.CSPRNG_fz_inf_w(seed_e_seed_pk[:2*c.ProtocolData.Lambda/8])
		e_bar := c.Fz_inf_w_by_fz_matrix(e_G_bar, W_mat)
		norm_e_bar := c.Fz_dz_norm_n(e_bar)
		return V_tr, W_mat, e_G_bar, norm_e_bar
	}
	return nil, nil, nil, nil
}
func (c *CROSSInstance[T, P]) Sign(sk, msg []byte) (Signature, error) {
	signature := Signature{}
	V_tr, W_mat, e_G_bar, e_bar := c.Expand_sk(sk)
	salt := make([]byte, 2*c.ProtocolData.Lambda/8)
	root_seed := make([]byte, c.ProtocolData.Lambda/8)
	rand.Read(salt)
	rand.Read(root_seed)
	signature.Salt = salt
	round_seeds := c.SeedLeaves(root_seed, salt)
	e_bar_prime := make([]byte, c.ProtocolData.T*c.ProtocolData.N)
	v_bar := make([]byte, c.ProtocolData.T*c.ProtocolData.N)
	u_prime := make([]T, c.ProtocolData.T*c.ProtocolData.N)
	s_prime := make([]T, c.ProtocolData.N-c.ProtocolData.K)
	cmt_0 := make([][]byte, c.ProtocolData.T)
	cmt_1 := make([]byte, c.ProtocolData.T*((2*c.ProtocolData.Lambda)/8))
	v_G_bar := make([]byte, c.ProtocolData.T*c.ProtocolData.M)
	for i := 0; i < c.ProtocolData.T; i++ {
		var csprng_input []byte
		csprng_input = append(append(csprng_input, round_seeds[i]...), salt...)
		dsc := uint16(0 + i + (2*c.ProtocolData.T - 1))
		round_state := c.CSPRNG_init(csprng_input, dsc)
		if c.ProtocolData.Variant() == common.VARIANT_RSDP {
			e_bar_prime_i, state := c.CSPRNG_fz_vec_prime(round_state)
			round_state = state
			copy(e_bar_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], e_bar_prime_i)
		} else {
			e_G_bar_prime, state := c.CSPRNG_fz_inf_w_prime(round_state)
			round_state = state
			v_G_val := c.Fz_vec_sub_m(e_G_bar, e_G_bar_prime)
			v_G_val = c.Fz_dz_norm_m(v_G_val)
			copy(v_G_bar[i*c.ProtocolData.M:(i+1)*c.ProtocolData.M], v_G_val)
			e_bar_prime_i := c.Fz_inf_w_by_fz_matrix(e_G_bar_prime, W_mat)
			e_bar_prime_i = c.Fz_dz_norm_n(e_bar_prime_i)
			copy(e_bar_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], e_bar_prime_i)
		}
		v_bar_i := c.Fz_vec_sub_n(e_bar, e_bar_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N])
		v := c.Convert_restr_vec_to_fp(v_bar_i)
		v_bar_i = c.Fz_dz_norm_n(v_bar_i)
		copy(v_bar[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], v_bar_i)
		u_prime_i := c.CSPRNG_fp_vec_prime(round_state)
		copy(u_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], u_prime_i)
		u := c.Fp_vec_by_fp_vec_pointwise(v, u_prime_i)
		s_prime = c.Fp_vec_by_fp_matrix(u, V_tr)
		s_prime = c.Fp_dz_norm_synd(s_prime)
		var cmt_0_i_input []byte
		if c.ProtocolData.Variant() == common.VARIANT_RSDP {
			s_prime = c.byteToT(c.Pack_fp_syn(s_prime))
			v_bar_packed := c.Pack_fz_vec(c.byteToT(v_bar[i*c.ProtocolData.N : (i+1)*c.ProtocolData.N]))

			cmt_0_i_input = append(append(append(cmt_0_i_input, c.TtoByte(s_prime)...), v_bar_packed...), salt...)
		} else {
			s_prime = c.byteToT(c.Pack_fp_syn(s_prime))
			v_G_bar_packed := c.Pack_fz_rsdpg_vec(c.byteToT(v_G_bar[i*c.ProtocolData.M : (i+1)*c.ProtocolData.M]))
			cmt_0_i_input = append(append(append(cmt_0_i_input, c.TtoByte(s_prime)...), v_G_bar_packed...), salt...)
		}
		domain_sep_hash := uint16(32768 + i + (2*c.ProtocolData.T - 1))
		cmt_1_i_input := make([]byte, (3*c.ProtocolData.Lambda)/8)
		hash_val := c.CSPRNG(cmt_0_i_input, (2*c.ProtocolData.Lambda)/8, domain_sep_hash)
		cmt_0[i] = hash_val
		copy(cmt_1_i_input, round_seeds[i])
		copy(cmt_1_i_input[c.ProtocolData.Lambda/8:], salt)
		hash_cmt_1_val := c.CSPRNG(cmt_1_i_input, (2*c.ProtocolData.Lambda)/8, domain_sep_hash)
		copy(cmt_1[i*(2*c.ProtocolData.Lambda)/8:(i+1)*(2*c.ProtocolData.Lambda)/8], hash_cmt_1_val)
	}
	digest_cmt0_cmt1 := make([]byte, 2*(2*c.ProtocolData.Lambda)/8)
	root := c.TreeRoot(cmt_0)
	copy(digest_cmt0_cmt1, root)
	hash_val := c.CSPRNG(cmt_1, (2*c.ProtocolData.Lambda)/8, uint16(32768))
	copy(digest_cmt0_cmt1[(2*c.ProtocolData.Lambda)/8:], hash_val)
	digest_cmt := c.CSPRNG(digest_cmt0_cmt1, (2*c.ProtocolData.Lambda)/8, uint16(32768))
	signature.Digest_cmt = digest_cmt
	digest_msg_cmt_salt := make([]byte, 3*(2*c.ProtocolData.Lambda)/8)
	digest_msg_val := c.CSPRNG(msg, 2*c.ProtocolData.Lambda/8, uint16(32768))
	copy(digest_msg_cmt_salt, digest_msg_val)
	copy(digest_msg_cmt_salt[(2*c.ProtocolData.Lambda)/8:], digest_cmt)
	copy(digest_msg_cmt_salt[2*(2*c.ProtocolData.Lambda)/8:], salt)
	// Computing first challenge
	digest_chall_1 := make([]byte, (2*c.ProtocolData.Lambda)/8)
	chall_1_val := c.CSPRNG(digest_msg_cmt_salt, 3*(2*c.ProtocolData.Lambda)/8, uint16(32768))
	copy(digest_chall_1, chall_1_val)
	chall_1 := c.CSPRNG_fp_vec_chall_1(digest_chall_1)
	// Computing first response
	y := make([][]T, c.ProtocolData.T)

	for i := 0; i < c.ProtocolData.T; i++ {
		y[i] = c.Fp_vec_by_restr_vec_scaled(c.byteToT(e_bar_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N]), u_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], chall_1[i])
		y[i] = c.Fp_dz_norm(y[i])
	}
	y_digest_chall_1 := make([]byte, c.ProtocolData.T*c.DenselyPackedFpVecSize()+((2*c.ProtocolData.Lambda)/8))
	for i := 0; i < c.ProtocolData.T; i++ {
		val := c.Pack_fp_vec(y[i])
		copy(y_digest_chall_1[i*c.DenselyPackedFpVecSize():(i+1)*c.DenselyPackedFpVecSize()], val)
	}
	copy(y_digest_chall_1[c.ProtocolData.T*c.DenselyPackedFpVecSize():], digest_chall_1)
	digest_chall_2 := c.CSPRNG(y_digest_chall_1, (2*c.ProtocolData.Lambda)/8, uint16(32768))
	signature.Digest_chall_2 = digest_chall_2
	chall_2 := c.Expand_digest_to_fixed_weight(digest_chall_2)
	// Computing second round of responses
	proof := c.TreeProof(cmt_0, chall_2)
	path := c.SeedPath(root_seed, salt, chall_2)
	signature.Proof = proof
	signature.Path = path
	published_rsps := 0
	signature.Resp_0 = make([]resp_0_struct, c.ProtocolData.T-c.ProtocolData.W)
	signature.Resp_1 = make([]byte, (c.ProtocolData.T-c.ProtocolData.W)*((2*c.ProtocolData.Lambda)/8))
	for i := 0; i < c.ProtocolData.T; i++ {
		if !chall_2[i] {
			if !(published_rsps < c.ProtocolData.T-c.ProtocolData.W) {
				return Signature{}, fmt.Errorf("Too many responses published")
			}
			signature.Resp_0[published_rsps].Y = c.Pack_fp_vec(y[i])
			if c.ProtocolData.Variant() == common.VARIANT_RSDP {
				signature.Resp_0[published_rsps].V_bar = c.Pack_fz_vec(c.byteToT(v_bar[i*c.ProtocolData.N : (i+1)*c.ProtocolData.N]))
			} else {
				signature.Resp_0[published_rsps].V_G_bar = c.Pack_fz_rsdpg_vec(c.byteToT(v_G_bar[i*c.ProtocolData.M : (i+1)*c.ProtocolData.M]))
			}
			copy(signature.Resp_1[published_rsps*((2*c.ProtocolData.Lambda)/8):], cmt_1[i*((2*c.ProtocolData.Lambda)/8):(i+1)*((2*c.ProtocolData.Lambda)/8)])
			published_rsps++
		}
	}
	//TODO: Unpack into []byte
	return signature, nil
}

func (c *CROSSInstance[T, P]) DummySign(salt, root_seed, sk, msg []byte) (Signature, error) {
	signature := Signature{}
	V_tr, W_mat, e_G_bar, e_bar := c.Expand_sk(sk)
	signature.Salt = salt
	round_seeds := c.SeedLeaves(root_seed, salt)
	e_bar_prime := make([]byte, c.ProtocolData.T*c.ProtocolData.N)
	v_bar := make([]byte, c.ProtocolData.T*c.ProtocolData.N)
	u_prime := make([]T, c.ProtocolData.T*c.ProtocolData.N)
	s_prime := make([]T, c.ProtocolData.N-c.ProtocolData.K)
	cmt_0 := make([][]byte, c.ProtocolData.T)
	cmt_1 := make([]byte, c.ProtocolData.T*((2*c.ProtocolData.Lambda)/8))
	v_G_bar := make([]byte, c.ProtocolData.T*c.ProtocolData.M)
	for i := 0; i < c.ProtocolData.T; i++ {
		var csprng_input []byte
		csprng_input = append(append(csprng_input, round_seeds[i]...), salt...)
		dsc := uint16(0 + i + (2*c.ProtocolData.T - 1))
		round_state := c.CSPRNG_init(csprng_input, dsc)
		if c.ProtocolData.Variant() == common.VARIANT_RSDP {
			e_bar_prime_i, state := c.CSPRNG_fz_vec_prime(round_state)
			round_state = state
			copy(e_bar_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], e_bar_prime_i)
		} else {
			e_G_bar_prime, state := c.CSPRNG_fz_inf_w_prime(round_state)
			round_state = state
			v_G_val := c.Fz_vec_sub_m(e_G_bar, e_G_bar_prime)
			v_G_val = c.Fz_dz_norm_m(v_G_val)
			copy(v_G_bar[i*c.ProtocolData.M:(i+1)*c.ProtocolData.M], v_G_val)
			e_bar_prime_i := c.Fz_inf_w_by_fz_matrix(e_G_bar_prime, W_mat)
			e_bar_prime_i = c.Fz_dz_norm_n(e_bar_prime_i)
			copy(e_bar_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], e_bar_prime_i)
		}
		v_bar_i := c.Fz_vec_sub_n(e_bar, e_bar_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N])
		v := c.Convert_restr_vec_to_fp(v_bar_i)
		v_bar_i = c.Fz_dz_norm_n(v_bar_i)
		copy(v_bar[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], v_bar_i)
		u_prime_i := c.CSPRNG_fp_vec_prime(round_state)
		copy(u_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], u_prime_i)
		u := c.Fp_vec_by_fp_vec_pointwise(v, u_prime_i)
		s_prime = c.Fp_vec_by_fp_matrix(u, V_tr)
		s_prime = c.Fp_dz_norm_synd(s_prime)
		var cmt_0_i_input []byte
		if c.ProtocolData.Variant() == common.VARIANT_RSDP {
			s_prime = c.byteToT(c.Pack_fp_syn(s_prime))
			v_bar_packed := c.Pack_fz_vec(c.byteToT(v_bar[i*c.ProtocolData.N : (i+1)*c.ProtocolData.N]))

			cmt_0_i_input = append(append(append(cmt_0_i_input, c.TtoByte(s_prime)...), v_bar_packed...), salt...)
		} else {
			s_prime = c.byteToT(c.Pack_fp_syn(s_prime))
			v_G_bar_packed := c.Pack_fz_rsdpg_vec(c.byteToT(v_G_bar[i*c.ProtocolData.M : (i+1)*c.ProtocolData.M]))
			cmt_0_i_input = append(append(append(cmt_0_i_input, c.TtoByte(s_prime)...), v_G_bar_packed...), salt...)
		}
		domain_sep_hash := uint16(32768 + i + (2*c.ProtocolData.T - 1))
		cmt_1_i_input := make([]byte, (3*c.ProtocolData.Lambda)/8)
		hash_val := c.CSPRNG(cmt_0_i_input, (2*c.ProtocolData.Lambda)/8, domain_sep_hash)
		cmt_0[i] = hash_val
		copy(cmt_1_i_input, round_seeds[i])
		copy(cmt_1_i_input[c.ProtocolData.Lambda/8:], salt)
		hash_cmt_1_val := c.CSPRNG(cmt_1_i_input, (2*c.ProtocolData.Lambda)/8, domain_sep_hash)
		copy(cmt_1[i*(2*c.ProtocolData.Lambda)/8:(i+1)*(2*c.ProtocolData.Lambda)/8], hash_cmt_1_val)
	}
	digest_cmt0_cmt1 := make([]byte, 2*(2*c.ProtocolData.Lambda)/8)
	root := c.TreeRoot(cmt_0)
	copy(digest_cmt0_cmt1, root)
	hash_val := c.CSPRNG(cmt_1, (2*c.ProtocolData.Lambda)/8, uint16(32768))
	copy(digest_cmt0_cmt1[(2*c.ProtocolData.Lambda)/8:], hash_val)
	digest_cmt := c.CSPRNG(digest_cmt0_cmt1, (2*c.ProtocolData.Lambda)/8, uint16(32768))
	signature.Digest_cmt = digest_cmt
	digest_msg_cmt_salt := make([]byte, 3*(2*c.ProtocolData.Lambda)/8)
	digest_msg_val := c.CSPRNG(msg, 2*c.ProtocolData.Lambda/8, uint16(32768))
	copy(digest_msg_cmt_salt, digest_msg_val)
	copy(digest_msg_cmt_salt[(2*c.ProtocolData.Lambda)/8:], digest_cmt)
	copy(digest_msg_cmt_salt[2*(2*c.ProtocolData.Lambda)/8:], salt)
	// Computing first challenge
	digest_chall_1 := make([]byte, (2*c.ProtocolData.Lambda)/8)
	chall_1_val := c.CSPRNG(digest_msg_cmt_salt, 3*(2*c.ProtocolData.Lambda)/8, uint16(32768))
	copy(digest_chall_1, chall_1_val)
	chall_1 := c.CSPRNG_fp_vec_chall_1(digest_chall_1)
	// Computing first response
	y := make([][]T, c.ProtocolData.T)

	for i := 0; i < c.ProtocolData.T; i++ {
		y[i] = c.Fp_vec_by_restr_vec_scaled(c.byteToT(e_bar_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N]), u_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], chall_1[i])
		y[i] = c.Fp_dz_norm(y[i])
	}
	y_digest_chall_1 := make([]byte, c.ProtocolData.T*c.DenselyPackedFpVecSize()+((2*c.ProtocolData.Lambda)/8))
	for i := 0; i < c.ProtocolData.T; i++ {
		val := c.Pack_fp_vec(y[i])
		copy(y_digest_chall_1[i*c.DenselyPackedFpVecSize():(i+1)*c.DenselyPackedFpVecSize()], val)
	}
	copy(y_digest_chall_1[c.ProtocolData.T*c.DenselyPackedFpVecSize():], digest_chall_1)
	digest_chall_2 := c.CSPRNG(y_digest_chall_1, (2*c.ProtocolData.Lambda)/8, uint16(32768))
	signature.Digest_chall_2 = digest_chall_2
	chall_2 := c.Expand_digest_to_fixed_weight(digest_chall_2)
	// Computing second round of responses
	proof := c.TreeProof(cmt_0, chall_2)
	path := c.SeedPath(root_seed, salt, chall_2)
	signature.Proof = proof
	signature.Path = path
	published_rsps := 0
	signature.Resp_0 = make([]resp_0_struct, c.ProtocolData.T-c.ProtocolData.W)
	signature.Resp_1 = make([]byte, (c.ProtocolData.T-c.ProtocolData.W)*((2*c.ProtocolData.Lambda)/8))
	for i := 0; i < c.ProtocolData.T; i++ {
		if !chall_2[i] {
			if !(published_rsps < c.ProtocolData.T-c.ProtocolData.W) {
				return Signature{}, fmt.Errorf("Too many responses published")
			}
			signature.Resp_0[published_rsps].Y = c.Pack_fp_vec(y[i])
			if c.ProtocolData.Variant() == common.VARIANT_RSDP {
				signature.Resp_0[published_rsps].V_bar = c.Pack_fz_vec(c.byteToT(v_bar[i*c.ProtocolData.N : (i+1)*c.ProtocolData.N]))
			} else {
				signature.Resp_0[published_rsps].V_G_bar = c.Pack_fz_rsdpg_vec(c.byteToT(v_G_bar[i*c.ProtocolData.M : (i+1)*c.ProtocolData.M]))
			}
			copy(signature.Resp_1[published_rsps*((2*c.ProtocolData.Lambda)/8):], cmt_1[i*((2*c.ProtocolData.Lambda)/8):(i+1)*((2*c.ProtocolData.Lambda)/8)])
			published_rsps++
		}
	}
	//TODO: Unpack into []byte
	return signature, nil
}

func (c *CROSSInstance[T, P]) byteToT(arr []byte) []T {
	res := make([]T, len(arr))
	for i := range arr {
		res[i] = T(arr[i])
	}
	return res
}

func (c *CROSSInstance[T, P]) TtoByte(arr []T) []byte {
	res := make([]byte, len(arr))
	for i := range arr {
		res[i] = byte(arr[i])
	}
	return res
}

func flattenByteSlices(slices [][]byte) []byte {
	var total []byte
	for _, s := range slices {
		total = append(total, s...)
	}
	return total
}

func flattenResp0(resp []resp_0_struct) []byte {
	var total []byte
	for _, r := range resp {
		total = append(total, r.Y...)
		total = append(total, r.V_bar...)
		total = append(total, r.V_G_bar...)
	}
	return total
}

func (s *Signature) ToBytes() []byte {
	var total []byte

	total = append(total, s.Salt...)
	total = append(total, s.Digest_cmt...)
	total = append(total, s.Digest_chall_2...)
	total = append(total, flattenByteSlices(s.Path)...)
	total = append(total, flattenByteSlices(s.Proof)...)
	total = append(total, s.Resp_1...)
	total = append(total, flattenResp0(s.Resp_0)...)

	return total
}
