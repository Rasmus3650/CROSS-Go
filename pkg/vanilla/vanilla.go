package vanilla

import (
	"PQC-Master-Thesis/internal"
	"PQC-Master-Thesis/internal/common"
	"fmt"

	"golang.org/x/crypto/sha3"
)

type CROSSAllMethods interface {
	GetProtocolData() common.ProtocolData
	GetTreeParams() common.TreeParams
	KeyGen() (KeyPair, error)
	DummyKeyGen(seed_sk []byte) (KeyPair, error)
	DummySign(salt, root_seed, sk, msg []byte) (Signature, error)
	Verify(pk Pub, m []byte, sig Signature) (bool, error)
	Expand_pk(seed_pk []byte) ([]int, []byte, error)
	Expand_sk(seed_sk []byte) ([]int, []byte, []byte, []byte, error)

	//arith
	Fz_dz_norm_n(v []byte) []byte
	Fz_inf_w_by_fz_matrix(fz_vec_e, W_mat []byte) []byte

	//seed
	SeedLeaves(seed, salt []byte) ([][]byte, error)
	RebuildLeaves(path [][]byte, salt []byte, chall_2 []bool) ([][]byte, bool, error)
	SeedPath(seed, salt []byte, chall_2 []bool) ([][]byte, error)

	//merkle
	TreeProof(commitments [][]byte, chall_2 []bool) ([][]byte, error)
	RecomputeRoot(cmt_0, proof [][]byte, chall_2 []bool) ([]byte, bool, error)
	TreeRoot(commitments [][]byte) ([]byte, error)

	//Shake
	CSPRNG(seed []byte, output_len int, dsc uint16) ([]byte, error)
	CSPRNG_fp_mat(seed []byte) ([]int, error)
	CSPRNG_fz_vec(seed []byte) ([]byte, error)
	CSPRNG_fp_vec(seed []byte) ([]byte, error)
	CSPRNG_fz_inf_w(seed []byte) ([]byte, error)
	CSPRNG_fz_mat(seed []byte) ([]byte, sha3.ShakeHash, error)
	Expand_digest_to_fixed_weight(digest []byte) ([]bool, error)
}

type CROSSMethods interface {
	KeyGen() (KeyPair, error)
}

func (c *CROSSInstance[T, P]) GetProtocolData() common.ProtocolData {
	return c.CROSS.ProtocolData
}
func (c *CROSSInstance[T, P]) GetTreeParams() common.TreeParams {
	return c.CROSS.TreeParams
}

type CROSSInstance[T internal.FP_ELEM, P internal.FP_PREC] struct {
	*internal.CROSS[T, P]
}

// NewCROSS creates a new CROSS instance
func NewCROSS(scheme_identifier common.CONFIG_IDENT) (CROSSAllMethods, error) {
	protocolData, err := common.GetProtocolConfig(scheme_identifier)
	if err != nil {
		return nil, err
	}
	treeParams, err := common.GetTreeParams(scheme_identifier)
	if err != nil {
		return nil, err
	}
	if protocolData.Variant() == common.VARIANT_RSDP {
		return &CROSSInstance[uint8, uint16]{
			CROSS: &internal.CROSS[uint8, uint16]{
				ProtocolData: protocolData,
				TreeParams:   treeParams,
			},
		}, nil
	} else if protocolData.Variant() == common.VARIANT_RSDP_G {
		return &CROSSInstance[uint16, uint32]{
			CROSS: &internal.CROSS[uint16, uint32]{
				ProtocolData: protocolData,
				TreeParams:   treeParams,
			},
		}, nil
	}
	panic(fmt.Sprintf("Invalid variant"))
}
