package vanilla

import (
	"PQC-Master-Thesis/internal/common"
	"crypto/rand"
)

type Pub struct {
	SeedPK []byte
	S      []byte
}

type KeyPair struct {
	Pri []byte
	Pub
}

func (c *CROSSInstance[T, P]) Expand_pk(seed_pk []byte) ([]int, []byte) {
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

func (c *CROSSInstance[T, P]) KeyGen() (KeyPair, error) {
	seed_sk := make([]byte, (2*c.ProtocolData.Lambda)/8)
	_, err := rand.Read(seed_sk)
	if err != nil {
		return KeyPair{}, err
	}
	seed_e_pk := c.CSPRNG(seed_sk, (4*c.ProtocolData.Lambda)/8, uint16(0+3*c.ProtocolData.T+1))
	seed_e := seed_e_pk[:2*c.ProtocolData.Lambda/8]
	seed_pk := seed_e_pk[2*c.ProtocolData.Lambda/8:]
	V_tr, W_mat := c.Expand_pk(seed_pk)
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		e_bar := c.CSPRNG_fz_vec(seed_e)
		temp_s := c.Restr_vec_by_fp_matrix(e_bar, c.intToT(V_tr))
		s := c.Fp_dz_norm_synd(temp_s)
		S := c.Pack_fp_syn(s)
		return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: S}}, nil

	} else {
		e_G_bar := c.CSPRNG_fz_inf_w(seed_e)
		e_bar := c.Fz_inf_w_by_fz_matrix(e_G_bar, W_mat)
		e_bar = c.Fz_dz_norm_n(e_bar)
		temp_s := c.Restr_vec_by_fp_matrix(e_bar, c.intToT(V_tr))
		s := c.Fp_dz_norm_synd(temp_s)
		S := c.Pack_fp_syn(s)
		return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: S}}, nil
	}
}

// Dummy KeyGen function for testing purposes ONLY
func (c *CROSSInstance[T, P]) DummyKeyGen(seed_sk []byte) (KeyPair, error) {
	seed_e_pk := c.CSPRNG(seed_sk, (4*c.ProtocolData.Lambda)/8, uint16(0+3*c.ProtocolData.T+1))
	seed_e := seed_e_pk[:2*c.ProtocolData.Lambda/8]
	seed_pk := seed_e_pk[2*c.ProtocolData.Lambda/8:]
	V_tr, W_mat := c.Expand_pk(seed_pk)
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		e_bar := c.CSPRNG_fz_vec(seed_e)
		temp_s := c.Restr_vec_by_fp_matrix(e_bar, c.intToT(V_tr))
		s := c.Fp_dz_norm_synd(temp_s)
		S := c.Pack_fp_syn(s)
		return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: S}}, nil

	} else {
		e_G_bar := c.CSPRNG_fz_inf_w(seed_e)
		e_bar := c.Fz_inf_w_by_fz_matrix(e_G_bar, W_mat)
		e_bar = c.Fz_dz_norm_n(e_bar)
		temp_s := c.Restr_vec_by_fp_matrix(e_bar, c.intToT(V_tr))
		s := c.Fp_dz_norm_synd(temp_s)
		S := c.Pack_fp_syn(s)
		return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: S}}, nil
	}
}

func (c *CROSSInstance[T, P]) intToT(V []int) []T {
	result := make([]T, len(V))
	for i := range V {
		result[i] = T(V[i])
	}
	return result
}
