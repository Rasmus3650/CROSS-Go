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
	Sign(sk, msg []byte) (Signature, error)
	DummySign(salt, root_seed, sk, msg []byte) (Signature, error)
	Verify(pk Pk, m []byte, sig Signature) (bool, error)

	//arith
	Fz_dz_norm_n(v []byte) []byte
	Fz_inf_w_by_fz_matrix(fz_vec_e, W_mat []byte) []byte

	//seed
	SeedLeaves(seed, salt []byte) [][]byte
	RebuildLeaves(path [][]byte, salt []byte, chall_2 []bool) ([][]byte, bool)
	SeedPath(seed, salt []byte, chall_2 []bool) [][]byte

	//merkle
	TreeProof(commitments [][]byte, chall_2 []bool) [][]byte
	RecomputeRoot(cmt_0, proof [][]byte, chall_2 []bool) ([]byte, bool)
	TreeRoot(commitments [][]byte) []byte

	//Shake
	CSPRNG(seed []byte, output_len int, dsc uint16) []byte
	CSPRNG_fz_vec(seed []byte) []byte
	CSPRNG_fp_vec(seed []byte) []byte
	CSPRNG_fz_inf_w(seed []byte) []byte
	CSPRNG_fz_mat(seed []byte) ([]byte, sha3.ShakeHash)
	Expand_digest_to_fixed_weight(digest []byte) []bool
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
