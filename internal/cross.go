package internal

import (
	"fmt"
)

type FP_ELEM interface {
	uint8 | uint16
}

type FP_PREC interface {
	uint16 | uint32
}

func FP_DOUBLE_PREC[T FP_ELEM, P FP_PREC](input T) P {
	switch v := any(input).(type) {
	case uint8:
		// If the input is uint8, convert to uint16 (because uint16 is part of FP_DOUBLE_PREC)
		return P(uint16(v))
	case uint16:
		// If the input is uint16, convert to uint32 (because uint32 is part of FP_DOUBLE_PREC)
		return P(uint32(v))
	}
	panic(fmt.Sprintf("unexpected type %T", input))
}

type CROSS[T FP_ELEM, P FP_PREC] struct {
	ProtocolData ProtocolData
	TreeParams   TreeParams
}
