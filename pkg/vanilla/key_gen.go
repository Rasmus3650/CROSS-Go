package vanilla

import (
	"PQC-Master-Thesis/internal/common"
	"crypto/rand"
	"fmt"
)

type Pub struct {
	SeedPK []byte
	S      []byte
}

type KeyPair struct {
	Pri []byte
	Pub
}

func (c *CROSSInstance) Expand_pk(seed_pk []byte) ([]int, []byte, error) {
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		V_tr, err := c.CSPRNG_fp_mat(seed_pk)
		if err != nil {
			return nil, nil, err
		}
		return V_tr, nil, nil
	} else if c.ProtocolData.Variant() == common.VARIANT_RSDP_G {
		W_mat, state, err := c.CSPRNG_fz_mat(seed_pk)
		if err != nil {
			return nil, nil, err
		}
		V_tr, err := c.CSPRNG_fp_mat_prime(state)
		if err != nil {
			return nil, nil, err
		}
		return V_tr, W_mat, nil
	}
	return nil, nil, fmt.Errorf("Invalid variant")
}

func (c *CROSSInstance) KeyGen() (KeyPair, error) {
	seed_sk := make([]byte, (2*c.ProtocolData.Lambda)/8)
	_, err := rand.Read(seed_sk)
	if err != nil {
		return KeyPair{}, err
	}
	seed_e_pk, err := c.CSPRNG(seed_sk, (4*c.ProtocolData.Lambda)/8, uint16(0+3*c.ProtocolData.T+1))
	if err != nil {
		return KeyPair{}, err
	}
	seed_e := seed_e_pk[:2*c.ProtocolData.Lambda/8]
	seed_pk := seed_e_pk[2*c.ProtocolData.Lambda/8:]
	V_tr, W_mat, err := c.Expand_pk(seed_pk)
	if err != nil {
		return KeyPair{}, err
	}
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		e_bar, err := c.CSPRNG_fz_vec(seed_e)
		if err != nil {
			return KeyPair{}, err
		}
		temp_s := c.Restr_vec_by_fp_matrix(e_bar, V_tr)
		s := c.Fp_dz_norm_synd(temp_s)
		S := c.Pack_fp_syn(s)
		return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: S}}, nil

	} else {
		e_G_bar, err := c.CSPRNG_fz_inf_w(seed_e)
		if err != nil {
			return KeyPair{}, err
		}
		e_bar := c.Fz_inf_w_by_fz_matrix(e_G_bar, W_mat)
		e_bar = c.Fz_dz_norm_n(e_bar)
		temp_s := c.Restr_vec_by_fp_matrix_RSDPG(e_bar, V_tr)
		s := c.Fp_dz_norm_synd_RSDPG(temp_s)
		S := c.Pack_fp_syn_RSDPG(s)
		return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: S}}, nil
	}
}

// Dummy KeyGen function for testing purposes ONLY
func (c *CROSSInstance) DummyKeyGen(seed_sk []byte) (KeyPair, error) {

	seed_e_pk, err := c.CSPRNG(seed_sk, (4*c.ProtocolData.Lambda)/8, uint16(0+3*c.ProtocolData.T+1))
	seed_e := seed_e_pk[:2*c.ProtocolData.Lambda/8]
	seed_pk := seed_e_pk[2*c.ProtocolData.Lambda/8:]
	V_tr, W_mat, err := c.Expand_pk(seed_pk)
	if err != nil {
		return KeyPair{}, err
	}
	if c.ProtocolData.Variant() == common.VARIANT_RSDP {
		e_bar, err := c.CSPRNG_fz_vec(seed_e)
		if err != nil {
			return KeyPair{}, err
		}
		temp_s := c.Restr_vec_by_fp_matrix(e_bar, V_tr)
		s := c.Fp_dz_norm_synd(temp_s)
		S := c.Pack_fp_syn(s)
		return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: S}}, nil

	} else {
		e_G_bar, err := c.CSPRNG_fz_inf_w(seed_e)
		if err != nil {
			return KeyPair{}, err
		}
		e_bar := c.Fz_inf_w_by_fz_matrix(e_G_bar, W_mat)
		e_bar = c.Fz_dz_norm_n(e_bar)
		temp_s := c.Restr_vec_by_fp_matrix_RSDPG(e_bar, V_tr)
		s := c.Fp_dz_norm_synd_RSDPG(temp_s)
		S := c.Pack_fp_syn_RSDPG(s)
		return KeyPair{Pri: seed_sk, Pub: Pub{SeedPK: seed_pk, S: S}}, nil
	}
}
