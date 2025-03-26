package vanilla

import (
	"PQC-Master-Thesis/internal/common"
	"crypto/rand"
	"fmt"
)

type resp_0_struct struct {
	y       []byte
	v_bar   []byte
	v_G_bar []byte
}

type Signature struct {
	salt           []byte
	digest_cmt     []byte
	digest_chall_2 []byte
	path           [][]byte
	proof          [][]byte
	resp_1         []byte
	resp_0         []resp_0_struct
}

func (c *CROSSInstance[T, P]) Expand_sk(seed_sk []byte) ([]int, []byte, []byte, []byte, error) {
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

func (c *CROSSInstance[T, P]) Sign(sk, msg []byte) (Signature, error) {
	signature := Signature{}
	e_bar, e_G_bar, V_tr, W_mat, err := c.Expand_sk(sk)
	root_seed := make([]byte, c.ProtocolData.Lambda/8)
	salt := make([]byte, c.ProtocolData.Lambda/8)
	rand.Read(root_seed)
	rand.Read(salt)
	signature.salt = salt
	round_seeds, err := c.SeedLeaves(root_seed, salt)
	if err != nil {
		return Signature{}, fmt.Errorf("Error building seed leaves: %v", err)
	}
	e_bar_prime := make([]byte, c.ProtocolData.T*c.ProtocolData.N)
	v_bar := make([]byte, c.ProtocolData.T*c.ProtocolData.N)
	u_prime := make([]byte, c.ProtocolData.T*c.ProtocolData.N)
	s_prime := make([]byte, c.ProtocolData.N-c.ProtocolData.K)
	cmt_0 := make([][]byte, c.ProtocolData.T)
	cmt_1 := make([]byte, c.ProtocolData.T*((2*c.ProtocolData.Lambda)/8))
	v_G_bar := make([]byte, c.ProtocolData.T*c.ProtocolData.M)
	for i := 0; i < c.ProtocolData.T; i++ {
		csprng_input := append(round_seeds[i], salt...)
		dsc := uint16(0 + i + (2*c.ProtocolData.T - 1))
		round_state, err := c.CSPRNG_init(csprng_input, dsc)
		if err != nil {
			return Signature{}, fmt.Errorf("Error initializing CSPRNG: %v", err)
		}
		if c.ProtocolData.Variant() == common.VARIANT_RSDP {
			e_bar_prime_i, state, err := c.CSPRNG_fz_vec_prime(round_state)
			round_state = state
			if err != nil {
				return Signature{}, fmt.Errorf("Error generating e_bar_prime: %v", err)
			}
			copy(e_bar_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], e_bar_prime_i)
		} else {
			e_G_bar_prime, state, err := c.CSPRNG_fz_inf_w_prime(round_state)
			round_state = state
			if err != nil {
				return Signature{}, fmt.Errorf("Error generating e_G_bar_prime: %v", err)
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
			return Signature{}, fmt.Errorf("Error generating u_prime: %v", err)
		}
		copy(u_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N], u_prime_i)
		u := c.Fp_vec_by_fp_vec_pointwise(v, c.byteToT(u_prime_i))
		s_prime = c.TtoByte(c.Fp_vec_by_fp_matrix(u, c.byteToT(V_tr)))
		s_prime = c.TtoByte(c.Fp_dz_norm_synd(c.byteToT(s_prime)))
		var cmt_0_i_input []byte
		if c.ProtocolData.Variant() == common.VARIANT_RSDP {
			s_prime = c.Pack_fp_syn(c.byteToT(s_prime))
			v_bar_packed := c.Pack_fz_vec(c.byteToT(v_bar[i*c.ProtocolData.N : (i+1)*c.ProtocolData.N]))
			copy(cmt_0_i_input, append(append(s_prime, v_bar_packed...), salt...))
		} else {
			//TODO: FIX TYPE!
			res := make([]uint16, len(s_prime))
			for i := range s_prime {
				res[i] = uint16(s_prime[i])
			}
			s_prime = c.Pack_fp_syn(c.uint16ToT(res))
			v_G_bar_packed := c.Pack_fz_rsdpg_vec(c.byteToT(v_G_bar[i*c.ProtocolData.M : (i+1)*c.ProtocolData.M]))
			copy(cmt_0_i_input, append(append(s_prime, v_G_bar_packed...), salt...))
		}
		domain_sep_hash := uint16(32768 + i + (2*c.ProtocolData.T - 1))
		cmt_1_i_input := make([]byte, (3*c.ProtocolData.Lambda)/8)
		hash_val, err := c.CSPRNG(cmt_0_i_input, (2*c.ProtocolData.Lambda)/8, domain_sep_hash)
		cmt_0[i] = hash_val
		copy(cmt_1_i_input, append(round_seeds[i], salt...))
		hash_cmt_1_val, err := c.CSPRNG(cmt_1_i_input, (2*c.ProtocolData.Lambda)/8, domain_sep_hash)
		if err != nil {
			return Signature{}, fmt.Errorf("Error generating cmt_1: %v", err)
		}
		copy(cmt_1[i*(2*c.ProtocolData.Lambda)/8:(i+1)*(2*c.ProtocolData.Lambda)/8], hash_cmt_1_val)
	}
	digest_cmt0_cmt1 := make([]byte, 2*(2*c.ProtocolData.Lambda)/8)
	root, err := c.TreeRoot(cmt_0)
	if err != nil {
		return Signature{}, fmt.Errorf("Error generating digest_cmt0_cmt1: %v", err)
	}
	copy(digest_cmt0_cmt1, root)
	hash_val, err := c.CSPRNG(cmt_1, (2*c.ProtocolData.Lambda)/8, uint16(32768))
	if err != nil {
		return Signature{}, fmt.Errorf("Error generating cmt_1: %v", err)
	}
	copy(digest_cmt0_cmt1[(2*c.ProtocolData.Lambda)/8:], hash_val)
	digest_cmt, err := c.CSPRNG(digest_cmt0_cmt1, 2*(2*c.ProtocolData.Lambda)/8, uint16(32768))
	if err != nil {
		return Signature{}, fmt.Errorf("Error generating digest_cmt: %v", err)
	}
	signature.digest_cmt = digest_cmt
	digest_msg_cmt_salt := make([]byte, 3*(2*c.ProtocolData.Lambda)/8)
	digest_msg_val, err := c.CSPRNG(msg, len(msg), uint16(32768))
	if err != nil {
		return Signature{}, fmt.Errorf("Error generating digest_msg: %v", err)
	}
	copy(digest_msg_cmt_salt, digest_msg_val)
	copy(digest_msg_cmt_salt[(2*c.ProtocolData.Lambda)/8:], digest_cmt)
	copy(digest_msg_cmt_salt[2*(2*c.ProtocolData.Lambda)/8:], salt)
	// Computing first challenge
	digest_chall_1 := make([]byte, (2*c.ProtocolData.Lambda)/8)
	chall_1_val, err := c.CSPRNG(digest_msg_cmt_salt, 3*(2*c.ProtocolData.Lambda)/8, uint16(32768))
	if err != nil {
		return Signature{}, fmt.Errorf("Error generating digest_chall_1: %v", err)
	}
	copy(digest_chall_1, chall_1_val)
	chall_1, err := c.CSPRNG_fp_vec_chall_1(digest_chall_1)
	if err != nil {
		return Signature{}, fmt.Errorf("Error generating chall_1: %v", err)
	}
	// Computing first response
	y := make([][]byte, c.ProtocolData.T)
	for i := 0; i < c.ProtocolData.T; i++ {
		y[i] = c.TtoByte(c.Fp_vec_by_restr_vec_scaled(c.byteToT(e_bar_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N]), c.byteToT(u_prime[i*c.ProtocolData.N:(i+1)*c.ProtocolData.N]), T(chall_1[i])))
		y[i] = c.Fp_dz_norm(y[i])
	}
	y_digest_chall_1 := make([]byte, c.ProtocolData.T*c.DenselyPackedFpVecSize()+((2*c.ProtocolData.Lambda)/8))
	for i := 0; i < c.ProtocolData.T; i++ {
		val := c.Pack_fp_vec(c.byteToT(y[i]))
		copy(y_digest_chall_1[i*c.DenselyPackedFpVecSize():(i+1)*c.DenselyPackedFpVecSize()], val)
	}
	copy(y_digest_chall_1[c.ProtocolData.T*c.DenselyPackedFpVecSize():], digest_chall_1)

	digest_chall_2, err := c.CSPRNG(y_digest_chall_1, c.ProtocolData.T*c.DenselyPackedFpVecSize()+((2*c.ProtocolData.Lambda)/8), uint16(32768))
	if err != nil {
		return Signature{}, fmt.Errorf("Error generating digest_chall_2: %v", err)
	}
	signature.digest_chall_2 = digest_chall_2
	chall_2, err := c.Expand_digest_to_fixed_weight(digest_chall_2)
	if err != nil {
		return Signature{}, fmt.Errorf("Error expanding digest to fixed weight: %v", err)
	}
	// Computing second round of responses
	proof, err := c.TreeProof(cmt_0, chall_2)
	if err != nil {
		return Signature{}, fmt.Errorf("Error generating proof: %v", err)
	}
	path, err := c.SeedPath(root_seed, salt, chall_2)
	if err != nil {
		return Signature{}, fmt.Errorf("Error generating seed path: %v", err)
	}
	//TODO: Unpack into []byte
	signature.proof = proof
	signature.path = path
	published_rsps := 0
	for i := 0; i < c.ProtocolData.T; i++ {
		if chall_2[i] {
			if !(published_rsps < c.ProtocolData.T-c.ProtocolData.W) {
				return Signature{}, fmt.Errorf("Too many responses published")
			}
			//TODO: Ensure this is valid go code, for setting resp_0[i] to values
			signature.resp_0[published_rsps].y = c.Pack_fp_vec(c.byteToT(y[i]))
			if c.ProtocolData.Variant() == common.VARIANT_RSDP {
				signature.resp_0[published_rsps].v_bar = c.Pack_fz_vec(c.byteToT(v_bar[i*c.ProtocolData.N : (i+1)*c.ProtocolData.N]))
			} else {
				signature.resp_0[published_rsps].v_G_bar = c.Pack_fz_rsdpg_vec(c.byteToT(v_G_bar[i*c.ProtocolData.M : (i+1)*c.ProtocolData.M]))
			}
			published_rsps++
		}
	}
	return signature, nil
}

func (c *CROSSInstance[T, P]) byteToT(arr []byte) []T {
	res := make([]T, len(arr))
	for i := range arr {
		res[i] = T(arr[i])
	}
	return res
}

func (c *CROSSInstance[T, P]) uint16ToT(arr []uint16) []T {
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
