package vanilla

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/internal/trees"
)

type CROSSInstance struct {
	*trees.CROSS
}

// NewCROSS creates a new CROSS instance
func NewCROSS(scheme_identifier common.CONFIG_IDENT) (*CROSSInstance, error) {
	protocolData, err := common.GetProtocolConfig(scheme_identifier)
	if err != nil {
		return nil, err
	}
	treeParams, err := common.GetTreeParams(scheme_identifier)
	if err != nil {
		return nil, err
	}

	return &CROSSInstance{
		CROSS: &trees.CROSS{
			ProtocolData: protocolData,
			TreeParams:   treeParams,
		},
	}, nil
}
