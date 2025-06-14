package vanilla

import (
	"CROSS-Go/internal/common"
	"crypto/rand"
)

type Pk struct {
	SeedPK []byte
	S      []byte
}

type KeyPair struct {
	Sk []byte
	Pk
}

func (c *CROSSInstance[T, P]) Expand_pk(seed_pk []byte) ([]P, []byte) {
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		V_tr := c.CSPRNG_fp_mat(seed_pk)
		return V_tr, nil
	} else if c.ProtocolData.Variant() == common.VARIANT_RSDP_G {
		W_mat, state := c.CSPRNG_fz_mat(seed_pk)
		V_tr := c.CSPRNG_fp_mat_prime(state)
		return V_tr, W_mat
	} else {
		return nil, nil
	}
}

func (c *CROSSInstance[T, P]) KeyGen() KeyPair {
	seed_sk := make([]byte, (2*c.ProtocolData.Lambda)/8)
	//rand.Read can return an error, but according to documentation it never returns an error
	// according to the documentation, rand.Read can only error on very old linux systems, and this should crash the program completely
	rand.Read(seed_sk)
	seed_e_pk := c.CSPRNG(seed_sk, (4*c.ProtocolData.Lambda)/8, uint16(3*c.ProtocolData.T+1))
	seed_e := seed_e_pk[:2*c.ProtocolData.Lambda/8]
	seed_pk := seed_e_pk[2*c.ProtocolData.Lambda/8:]
	V_tr, W_mat := c.Expand_pk(seed_pk)
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		e_bar := c.CSPRNG_fz_vec(seed_e)
		temp_s := c.Restr_vec_by_fp_matrix(e_bar, V_tr)
		s := c.Fp_dz_norm_synd(temp_s)
		S := c.Pack_fp_syn(s)
		return KeyPair{Sk: seed_sk, Pk: Pk{SeedPK: seed_pk, S: S}}

	} else {
		e_G_bar := c.CSPRNG_fz_inf_w(seed_e)
		e_bar := c.Fz_inf_w_by_fz_matrix(e_G_bar, W_mat)
		e_bar = c.Fz_dz_norm_n(e_bar)
		temp_s := c.Restr_vec_by_fp_matrix(e_bar, V_tr)
		s := c.Fp_dz_norm_synd(temp_s)
		S := c.Pack_fp_syn(s)
		return KeyPair{Sk: seed_sk, Pk: Pk{SeedPK: seed_pk, S: S}}
	}
}

// Dummy KeyGen function for testing purposes ONLY
func (c *CROSSInstance[T, P]) DummyKeyGen(seed_sk []byte) KeyPair {
	seed_e_pk := c.CSPRNG(seed_sk, (4*c.ProtocolData.Lambda)/8, uint16(3*c.ProtocolData.T+1))
	seed_e := seed_e_pk[:2*c.ProtocolData.Lambda/8]
	seed_pk := seed_e_pk[2*c.ProtocolData.Lambda/8:]
	V_tr, W_mat := c.Expand_pk(seed_pk)
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		e_bar := c.CSPRNG_fz_vec(seed_e)
		temp_s := c.Restr_vec_by_fp_matrix(e_bar, V_tr)
		s := c.Fp_dz_norm_synd(temp_s)
		S := c.Pack_fp_syn(s)
		return KeyPair{Sk: seed_sk, Pk: Pk{SeedPK: seed_pk, S: S}}

	} else {
		e_G_bar := c.CSPRNG_fz_inf_w(seed_e)
		e_bar := c.Fz_inf_w_by_fz_matrix(e_G_bar, W_mat)
		e_bar = c.Fz_dz_norm_n(e_bar)
		temp_s := c.Restr_vec_by_fp_matrix(e_bar, V_tr)
		s := c.Fp_dz_norm_synd(temp_s)
		S := c.Pack_fp_syn(s)
		return KeyPair{Sk: seed_sk, Pk: Pk{SeedPK: seed_pk, S: S}}
	}
}
