package vanilla

import "PQC-Master-Thesis/internal/common"

type CROSS struct {
	ProtocolData common.ProtocolData
	TreeParams   common.TreeParams
}

// NewCROSS creates a new CROSS instance
func NewCROSS(scheme_identifier common.CONFIG_IDENT) (*CROSS, error) {
	protocolData, err := common.GetProtocolConfig(scheme_identifier)
	if err != nil {
		return nil, err
	}

	treeParams, err := common.GetTreeParams(scheme_identifier)
	if err != nil {
		return nil, err
	}

	return &CROSS{
		ProtocolData: protocolData,
		TreeParams:   treeParams,
	}, nil
}
