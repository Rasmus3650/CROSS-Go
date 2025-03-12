package common

import (
	"fmt"
	"iter"
)

// 3 NIST security levels
// Category 1: 128 AES gates, roughly 143 bits of security
// Category 3: 192 AES gates, roughly 207 bits of security
// Category 5: 256 AES gates, roughly 272 bits of security

type (
	ProtocolData struct {
		T int
		W int
		G int
		SchemeData
	}

	SchemeData struct {
		Config CONFIG_IDENT
		Csprng string
		Lambda int
		Params
	}

	Params struct {
		P int
		Z int
		N int
		K int
		M int
	}

	TreeParams struct {
		NPL         []int // Nodes per level
		LPL         []int // Leaves per level
		Off         []int // Offsets for parent/child computation
		LSI         []int // Leaves start indices
		NCL         []int // Number of consecutive leaves
		Total_nodes int   // Total number of nodes in tree
	}

	CONFIG_IDENT uint8
)

func (s SchemeData) Type() uint {
	return uint(s.Config & TYPE_MASK)
}

func (s SchemeData) Variant() uint {
	return uint(s.Config & VARIANT_MASK)
}

func (s SchemeData) Level() uint {
	return uint(s.Config & LEVEL_MASK)
}

func (s SchemeData) IsType(types ...uint8) bool {
	t := s.Config & TYPE_MASK
	for _, ti := range types {
		if ti == uint8(t) {
			return true
		}
	}
	return false
}

func (s SchemeData) IsGVariant() bool {
	return (s.Config & VARIANT_MASK) == VARIANT_RSDP_G
}

func (s SchemeData) IsLevel(types ...uint8) bool {
	t := s.Config & LEVEL_MASK
	for _, ti := range types {
		if ti == uint8(t) {
			return true
		}
	}
	return false
}

const (
	RSDP_NAME   = "RSDP"
	RSDP_G_NAME = "RSDP-G"
)

const (
	VARIANT_MASK   = 0b00100000
	VARIANT_RSDP   = 0
	VARIANT_RSDP_G = 32
)

const (
	LEVEL_MASK = 0b00000111
	LEVEL_1    = 1
	LEVEL_3    = 3
	LEVEL_5    = 5
)

const (
	NO_TYPE_MASK  CONFIG_IDENT = 0b00100111
	TYPE_MASK     CONFIG_IDENT = 0b00011000
	TYPE_SMALL                 = 8
	TYPE_BALANCED              = 16
	TYPE_FAST                  = 24
)

const (
	RSDP_1          CONFIG_IDENT = VARIANT_RSDP + LEVEL_1
	RSDP_1_SMALL    CONFIG_IDENT = VARIANT_RSDP + LEVEL_1 + TYPE_SMALL
	RSDP_1_BALANCED CONFIG_IDENT = VARIANT_RSDP + LEVEL_1 + TYPE_BALANCED
	RSDP_1_FAST     CONFIG_IDENT = VARIANT_RSDP + LEVEL_1 + TYPE_FAST
	RSDP_3          CONFIG_IDENT = VARIANT_RSDP + LEVEL_3
	RSDP_3_SMALL    CONFIG_IDENT = VARIANT_RSDP + LEVEL_3 + TYPE_SMALL
	RSDP_3_BALANCED CONFIG_IDENT = VARIANT_RSDP + LEVEL_3 + TYPE_BALANCED
	RSDP_3_FAST     CONFIG_IDENT = VARIANT_RSDP + LEVEL_3 + TYPE_FAST
	RSDP_5          CONFIG_IDENT = VARIANT_RSDP + LEVEL_5
	RSDP_5_SMALL    CONFIG_IDENT = VARIANT_RSDP + LEVEL_5 + TYPE_SMALL
	RSDP_5_BALANCED CONFIG_IDENT = VARIANT_RSDP + LEVEL_5 + TYPE_BALANCED
	RSDP_5_FAST     CONFIG_IDENT = VARIANT_RSDP + LEVEL_5 + TYPE_FAST

	RSDP_G_1          CONFIG_IDENT = VARIANT_RSDP_G + LEVEL_1
	RSDP_G_1_SMALL    CONFIG_IDENT = VARIANT_RSDP_G + LEVEL_1 + TYPE_SMALL
	RSDP_G_1_BALANCED CONFIG_IDENT = VARIANT_RSDP_G + LEVEL_1 + TYPE_BALANCED
	RSDP_G_1_FAST     CONFIG_IDENT = VARIANT_RSDP_G + LEVEL_1 + TYPE_FAST
	RSDP_G_3          CONFIG_IDENT = VARIANT_RSDP_G + LEVEL_3
	RSDP_G_3_SMALL    CONFIG_IDENT = VARIANT_RSDP_G + LEVEL_3 + TYPE_SMALL
	RSDP_G_3_BALANCED CONFIG_IDENT = VARIANT_RSDP_G + LEVEL_3 + TYPE_BALANCED
	RSDP_G_3_FAST     CONFIG_IDENT = VARIANT_RSDP_G + LEVEL_3 + TYPE_FAST
	RSDP_G_5          CONFIG_IDENT = VARIANT_RSDP_G + LEVEL_5
	RSDP_G_5_SMALL    CONFIG_IDENT = VARIANT_RSDP_G + LEVEL_5 + TYPE_SMALL
	RSDP_G_5_BALANCED CONFIG_IDENT = VARIANT_RSDP_G + LEVEL_5 + TYPE_BALANCED
	RSDP_G_5_FAST     CONFIG_IDENT = VARIANT_RSDP_G + LEVEL_5 + TYPE_FAST
)

func Configs() iter.Seq2[int, CONFIG_IDENT] {
	configs := []CONFIG_IDENT{
		RSDP_1_SMALL, RSDP_1_BALANCED, RSDP_1_FAST,
		RSDP_3_SMALL, RSDP_3_BALANCED, RSDP_3_FAST,
		RSDP_5_SMALL, RSDP_5_BALANCED, RSDP_5_FAST,
		RSDP_G_1_SMALL, RSDP_G_1_BALANCED, RSDP_G_1_FAST,
		RSDP_G_3_SMALL, RSDP_G_3_BALANCED, RSDP_G_3_FAST,
		RSDP_G_5_SMALL, RSDP_G_5_BALANCED, RSDP_G_5_FAST,
	}
	return func(yield func(int, CONFIG_IDENT) bool) {
		for i, c := range configs {
			if !yield(i, c) {
				return
			}
		}
	}
}

var SCHEME_1_BASIS = SchemeData{
	Csprng: "SHAKE128-256", // SHAKE-128 with 256 bit output
	Lambda: 128,
}

var SCHEME_3_BASIS = SchemeData{
	Csprng: "SHAKE256-384", // SHAKE-256 with 384 bit output
	Lambda: 192,
}
var SCHEME_5_BASIS = SchemeData{
	Csprng: "SHAKE256-512", // SHAKE-256 with 512 bit output
	Lambda: 256,
}

const (
	RSDP_PARAM_P = 127
	RSDP_PARAM_Z = 7

	RSDP_G_PARAM_P = 509
	RSDP_G_PARAM_Z = 127
)

var RSDP_1_BASIS = ProtocolData{
	SchemeData: SchemeData{
		Csprng: SCHEME_1_BASIS.Csprng,
		Lambda: SCHEME_1_BASIS.Lambda,
		Params: Params{
			P: RSDP_PARAM_P, Z: RSDP_PARAM_Z,
			N: 127, K: 76,
		},
	},
	G: 2,
}

var RSDP_3_BASIS = ProtocolData{
	SchemeData: SchemeData{
		Csprng: SCHEME_3_BASIS.Csprng,
		Lambda: SCHEME_3_BASIS.Lambda,
		Params: Params{
			P: RSDP_PARAM_P, Z: RSDP_PARAM_Z,
			N: 187, K: 111,
		},
	},
	G: 2,
}

var RSDP_5_BASIS = ProtocolData{
	SchemeData: SchemeData{
		Csprng: SCHEME_5_BASIS.Csprng,
		Lambda: SCHEME_5_BASIS.Lambda,
		Params: Params{
			P: RSDP_PARAM_P, Z: RSDP_PARAM_Z,
			N: 251, K: 150,
		},
	},
	G: 2,
}

var RSDP_G_1_BASIS = ProtocolData{
	SchemeData: SchemeData{
		Csprng: SCHEME_1_BASIS.Csprng,
		Lambda: SCHEME_1_BASIS.Lambda,
		Params: Params{
			P: RSDP_G_PARAM_P, Z: RSDP_G_PARAM_Z,
			N: 55, K: 36, M: 25,
		},
	},
	G: 16,
}

var RSDP_G_3_BASIS = ProtocolData{
	SchemeData: SchemeData{
		Csprng: SCHEME_3_BASIS.Csprng,
		Lambda: SCHEME_3_BASIS.Lambda,
		Params: Params{
			P: RSDP_G_PARAM_P, Z: RSDP_G_PARAM_Z,
			N: 79, K: 48, M: 40,
		},
	},
	G: 16,
}

var RSDP_G_5_BASIS = ProtocolData{
	SchemeData: SchemeData{
		Csprng: SCHEME_5_BASIS.Csprng,
		Lambda: SCHEME_5_BASIS.Lambda,
		Params: Params{
			P: RSDP_G_PARAM_P, Z: RSDP_G_PARAM_Z,
			N: 106, K: 69, M: 48,
		},
	},
	G: 16,
}

func GetProtocolConfig(config CONFIG_IDENT) (ProtocolData, error) {
	var data ProtocolData

	switch config & NO_TYPE_MASK {
	case RSDP_1:
		data = RSDP_1_BASIS
	case RSDP_3:
		data = RSDP_3_BASIS
	case RSDP_5:
		data = RSDP_5_BASIS
	case RSDP_G_1:
		data = RSDP_G_1_BASIS
	case RSDP_G_3:
		data = RSDP_G_3_BASIS
	case RSDP_G_5:
		data = RSDP_G_5_BASIS
	default:
		return ProtocolData{}, fmt.Errorf("invalid value in config")
	}

	data.Config = config

	switch config {
	case RSDP_1_SMALL:
		data.T = 520
		data.W = 488
	case RSDP_1_BALANCED:
		data.T = 256
		data.W = 215
	case RSDP_1_FAST:
		data.T = 157
		data.W = 82
	case RSDP_3_SMALL:
		data.T = 580
		data.W = 527
	case RSDP_3_BALANCED:
		data.T = 384
		data.W = 321
	case RSDP_3_FAST:
		data.T = 239
		data.W = 125
	case RSDP_5_SMALL:
		data.T = 832
		data.W = 762
	case RSDP_5_BALANCED:
		data.T = 512
		data.W = 427
	case RSDP_5_FAST:
		data.T = 321
		data.W = 167
	case RSDP_G_1_SMALL:
		data.T = 512
		data.W = 484
	case RSDP_G_1_BALANCED:
		data.T = 256
		data.W = 220
	case RSDP_G_1_FAST:
		data.T = 147
		data.W = 76
	case RSDP_G_3_SMALL:
		data.T = 512
		data.W = 463
	case RSDP_G_3_BALANCED:
		data.T = 268
		data.W = 196
	case RSDP_G_3_FAST:
		data.T = 224
		data.W = 119
	case RSDP_G_5_SMALL:
		data.T = 642
		data.W = 575
	case RSDP_G_5_BALANCED:
		data.T = 356
		data.W = 258
	case RSDP_G_5_FAST:
		data.T = 300
		data.W = 153
	default:
		return ProtocolData{}, fmt.Errorf("invalid config value")
	}

	return data, nil
}

func GetTreeParams(config CONFIG_IDENT) (TreeParams, error) {
	params := TreeParams{}

	switch config {
	case RSDP_1_FAST:
		params.Off = []int{0, 0, 0, 0, 0, 2, 2, 58, 58}
		params.NPL = []int{1, 2, 4, 8, 16, 30, 60, 64, 128}
		params.LPL = []int{0, 0, 0, 0, 1, 0, 28, 0, 128}
		params.LSI = []int{185, 93, 30}
		params.NCL = []int{128, 28, 1}
	case RSDP_1_BALANCED:
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 0}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 256}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 0, 256}
		params.LSI = []int{255}
		params.NCL = []int{256}
	case RSDP_1_SMALL:
		params.Off = []int{0, 0, 0, 0, 0, 16, 16, 16, 16, 16, 16}
		params.NPL = []int{1, 2, 4, 8, 16, 16, 32, 64, 128, 256, 512}
		params.LPL = []int{0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 512}
		params.LSI = []int{527, 23}
		params.NCL = []int{512, 8}
	case RSDP_3_FAST:
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 2, 30}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 126, 224}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 1, 14, 224}
		params.LSI = []int{253, 239, 126}
		params.NCL = []int{224, 14, 1}
	case RSDP_3_BALANCED:
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 256}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 256}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 0, 128, 256}
		params.LSI = []int{511, 383}
		params.NCL = []int{256, 128}
	case RSDP_3_SMALL:
		params.Off = []int{0, 0, 0, 0, 0, 8, 8, 8, 8, 136, 136}
		params.NPL = []int{1, 2, 4, 8, 16, 24, 48, 96, 192, 256, 512}
		params.LPL = []int{0, 0, 0, 0, 4, 0, 0, 0, 64, 0, 512}
		params.LSI = []int{647, 327, 27}
		params.NCL = []int{512, 64, 4}
	case RSDP_5_FAST:
		params.Off = []int{0, 0, 0, 2, 2, 2, 2, 2, 2, 130}
		params.NPL = []int{1, 2, 4, 6, 12, 24, 48, 96, 192, 256}
		params.LPL = []int{0, 0, 1, 0, 0, 0, 0, 0, 64, 256}
		params.LSI = []int{385, 321, 6}
		params.NCL = []int{256, 64, 1}
	case RSDP_5_BALANCED:
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 512}
		params.LSI = []int{511}
		params.NCL = []int{512}
	case RSDP_5_SMALL:
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 128}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 384, 768}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 768}
		params.LSI = []int{895, 447}
		params.NCL = []int{768, 64}
	case RSDP_G_1_FAST:
		params.Off = []int{0, 0, 0, 0, 2, 6, 6, 38, 38}
		params.NPL = []int{1, 2, 4, 8, 14, 24, 48, 64, 128}
		params.LPL = []int{0, 0, 0, 1, 2, 0, 16, 0, 128}
		params.LSI = []int{165, 85, 27, 14}
		params.NCL = []int{128, 16, 2, 1}
	case RSDP_G_1_BALANCED:
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 0}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 256}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 0, 256}
		params.LSI = []int{255}
		params.NCL = []int{256}
	case RSDP_G_1_SMALL:
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 512}
		params.LSI = []int{511}
		params.NCL = []int{512}
	case RSDP_G_3_FAST:
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 64}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 192}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 32, 192}
		params.LSI = []int{255, 223}
		params.NCL = []int{192, 32}
	case RSDP_G_3_BALANCED:
		params.Off = []int{0, 0, 0, 0, 0, 8, 24, 24, 24, 24}
		params.NPL = []int{1, 2, 4, 8, 16, 24, 32, 64, 128, 256}
		params.LPL = []int{0, 0, 0, 0, 4, 8, 0, 0, 0, 256}
		params.LSI = []int{279, 47, 27}
		params.NCL = []int{256, 8, 4}
	case RSDP_G_3_SMALL:
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 512}
		params.LSI = []int{511}
		params.NCL = []int{512}
	case RSDP_G_5_FAST:
		params.Off = []int{0, 0, 0, 0, 0, 0, 8, 24, 88, 88}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 56, 96, 128, 256}
		params.LPL = []int{0, 0, 0, 0, 0, 4, 8, 32, 0, 256}
		params.LSI = []int{343, 183, 111, 59}
		params.NCL = []int{256, 32, 8, 4}
	case RSDP_G_5_BALANCED:
		params.Off = []int{0, 0, 0, 0, 0, 0, 8, 8, 8, 200}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 56, 112, 224, 256}
		params.LPL = []int{0, 0, 0, 0, 0, 4, 0, 0, 96, 256}
		params.LSI = []int{455, 359, 59}
		params.NCL = []int{256, 96, 4}
	case RSDP_G_5_SMALL:
		params.Off = []int{0, 0, 0, 0, 4, 4, 4, 4, 4, 4, 260}
		params.NPL = []int{1, 2, 4, 8, 12, 24, 48, 96, 192, 384, 512}
		params.LPL = []int{0, 0, 0, 2, 0, 0, 0, 0, 0, 128, 512}
		params.LSI = []int{771, 643, 13}
		params.NCL = []int{512, 128, 2}
	default:
		return TreeParams{}, fmt.Errorf("invalid parameters for tree structures")
	}

	params.Total_nodes = Sum(params.NPL)
	return params, nil
}

/*
type ProtocolData struct {
	T int
	W int
	G int
	SchemeData
}

type SchemeData struct {
	SecurityLevel  int
	ProblemVariant string
	SchemeType     string
	Csprng         string
	Lambda         int
	Params
}
type Params struct {
	P int
	Z int
	N int
	K int
	M int
}
type TreeParams struct {
	NPL         []int // Nodes per level
	LPL         []int // Leaves per level
	Off         []int // Offsets for parent/child computation
	LSI         []int // Leaves start indices
	NCL         []int // Number of consecutive leaves
	Total_nodes int   // Total number of nodes in tree
}

func GetProtocolConfig(schemeType, variant string, level int) (ProtocolData, error) {
	data := ProtocolData{}
	switch variant {
	case "RSDP-G":
		data.G = 16
		switch level {
		case 1:
			switch schemeType {
			case "small":
				data.T = 512
				data.W = 484
			case "balanced":
				data.T = 256
				data.W = 220
			case "fast":
				data.T = 147
				data.W = 76
			default:
				return ProtocolData{}, fmt.Errorf("invalid scheme type: %s. Must be small, balanced, or fast", schemeType)
			}
		case 3:
			switch schemeType {
			case "small":
				data.T = 512
				data.W = 463
			case "balanced":
				data.T = 268
				data.W = 196
			case "fast":
				data.T = 224
				data.W = 119
			default:
				return ProtocolData{}, fmt.Errorf("invalid scheme type: %s. Must be small, balanced, or fast", schemeType)
			}
		case 5:
			switch schemeType {
			case "small":
				data.T = 642
				data.W = 575
			case "balanced":
				data.T = 356
				data.W = 258
			case "fast":
				data.T = 300
				data.W = 153
			default:
				return ProtocolData{}, fmt.Errorf("invalid scheme type: %s. Must be small, balanced, or fast", schemeType)
			}
		default:
			return ProtocolData{}, fmt.Errorf("invalid security level: %d. Must be 1, 3, or 5", level)
		}
	case "RSDP":
		data.G = 2
		switch level {
		case 1:
			switch schemeType {
			case "small":
				data.T = 520
				data.W = 488
			case "balanced":
				data.T = 256
				data.W = 215
			case "fast":
				data.T = 157
				data.W = 82
			default:
				return ProtocolData{}, fmt.Errorf("invalid scheme type: %s. Must be small, balanced, or fast", schemeType)
			}
		case 3:
			switch schemeType {
			case "small":
				data.T = 580
				data.W = 527
			case "balanced":
				data.T = 384
				data.W = 321
			case "fast":
				data.T = 239
				data.W = 125
			default:
				return ProtocolData{}, fmt.Errorf("invalid scheme type: %s. Must be small, balanced, or fast", schemeType)
			}
		case 5:
			switch schemeType {
			case "small":
				data.T = 832
				data.W = 762
			case "balanced":
				data.T = 512
				data.W = 427
			case "fast":
				data.T = 321
				data.W = 167
			default:
				return ProtocolData{}, fmt.Errorf("invalid scheme type: %s. Must be small, balanced, or fast", schemeType)
			}
		default:
			return ProtocolData{}, fmt.Errorf("invalid security level: %d. Must be 1, 3, or 5", level)
		}
	default:
		return ProtocolData{}, fmt.Errorf("invalid problem variant: %s. Must be RSDP-G or RSDP", variant)
	}
	data.SchemeData, _ = GetSchemeConfig(schemeType, variant, level)
	return data, nil
}

func GetSchemeConfig(schemeType, variant string, level int) (SchemeData, error) {
	data := SchemeData{}
	switch schemeType {
	case "small":
		data.SchemeType = "small"
	case "balanced":
		data.SchemeType = "balanced"
	case "fast":
		data.SchemeType = "fast"
	default:
		return SchemeData{}, fmt.Errorf("invalid scheme type: %s. Must be small, balanced, or fast", schemeType)
	}

	switch variant {
	case "RSDP-G":
		data.ProblemVariant = "RSDP-G"
		switch level {
		case 1:
			data.SecurityLevel = level
			data.Csprng = "SHAKE128-256" // SHAKE-128 with 256 bit output
			data.Lambda = 128
			data.Params = Params{
				P: 509,
				Z: 127,
				N: 55,
				K: 36,
				M: 25,
			}
		case 3:
			data.SecurityLevel = level
			data.Csprng = "SHAKE256-384" // SHAKE-256 with 384 bit output
			data.Lambda = 192
			data.Params = Params{
				P: 509,
				Z: 127,
				N: 79,
				K: 48,
				M: 40,
			}

		case 5:
			data.SecurityLevel = level
			data.Csprng = "SHAKE256-512" // SHAKE-256 with 512 bit output
			data.Lambda = 256
			data.Params = Params{
				P: 509,
				Z: 127,
				N: 106,
				K: 69,
				M: 48,
			}

		default:
			return SchemeData{}, fmt.Errorf("invalid security level: %d. Must be 1, 3, or 5", level)
		}
	case "RSDP":
		data.ProblemVariant = "RSDP"
		switch level {
		case 1:
			data.SecurityLevel = level
			data.Csprng = "SHAKE128-256" // SHAKE-128 with 256 bit output
			data.Lambda = 128
			data.Params = Params{
				P: 127,
				Z: 7,
				N: 127,
				K: 76,
			}
		case 3:
			data.SecurityLevel = level
			data.Csprng = "SHAKE256-384" // SHAKE-256 with 384 bit output
			data.Lambda = 192
			data.Params = Params{
				P: 127,
				Z: 7,
				N: 187,
				K: 111,
			}

		case 5:
			data.SecurityLevel = level
			data.Csprng = "SHAKE256-512" // SHAKE-256 with 512 bit output
			data.Lambda = 256
			data.Params = Params{
				P: 127,
				Z: 7,
				N: 251,
				K: 150,
			}

		default:
			return SchemeData{}, fmt.Errorf("invalid security level: %d. Must be 1, 3, or 5", level)
		}
	default:
		return SchemeData{}, fmt.Errorf("invalid problem variant: %s. Must be RSDP-G or RSDP", variant)
	}
	return data, nil
}

func GetTreeParams(schemeType, variant string, level int) (TreeParams, error) {
	// Magic Constants generated by the CROSS team using: Available at parameters.h on Github
	params := TreeParams{}
	if level == 1 && variant == "RSDP" && schemeType == "fast" {
		params.Off = []int{0, 0, 0, 0, 0, 2, 2, 58, 58}
		params.NPL = []int{1, 2, 4, 8, 16, 30, 60, 64, 128}
		params.LPL = []int{0, 0, 0, 0, 1, 0, 28, 0, 128}
		params.LSI = []int{185, 93, 30}
		params.NCL = []int{128, 28, 1}
	} else if level == 1 && variant == "RSDP" && schemeType == "balanced" {
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 0}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 256}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 0, 256}
		params.LSI = []int{255}
		params.NCL = []int{256}
	} else if level == 1 && variant == "RSDP" && schemeType == "small" {
		params.Off = []int{0, 0, 0, 0, 0, 16, 16, 16, 16, 16, 16}
		params.NPL = []int{1, 2, 4, 8, 16, 16, 32, 64, 128, 256, 512}
		params.LPL = []int{0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 512}
		params.LSI = []int{527, 23}
		params.NCL = []int{512, 8}
	} else if level == 3 && variant == "RSDP" && schemeType == "fast" {
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 2, 30}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 126, 224}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 1, 14, 224}
		params.LSI = []int{253, 239, 126}
		params.NCL = []int{224, 14, 1}
	} else if level == 3 && variant == "RSDP" && schemeType == "balanced" {
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 256}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 256}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 0, 128, 256}
		params.LSI = []int{511, 383}
		params.NCL = []int{256, 128}
	} else if level == 3 && variant == "RSDP" && schemeType == "small" {
		params.Off = []int{0, 0, 0, 0, 0, 8, 8, 8, 8, 136, 136}
		params.NPL = []int{1, 2, 4, 8, 16, 24, 48, 96, 192, 256, 512}
		params.LPL = []int{0, 0, 0, 0, 4, 0, 0, 0, 64, 0, 512}
		params.LSI = []int{647, 327, 27}
		params.NCL = []int{512, 64, 4}
	} else if level == 5 && variant == "RSDP" && schemeType == "fast" {
		params.Off = []int{0, 0, 0, 2, 2, 2, 2, 2, 2, 130}
		params.NPL = []int{1, 2, 4, 6, 12, 24, 48, 96, 192, 256}
		params.LPL = []int{0, 0, 1, 0, 0, 0, 0, 0, 64, 256}
		params.LSI = []int{385, 321, 6}
		params.NCL = []int{256, 64, 1}
	} else if level == 5 && variant == "RSDP" && schemeType == "balanced" {
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 512}
		params.LSI = []int{511}
		params.NCL = []int{512}
	} else if level == 5 && variant == "RSDP" && schemeType == "small" {
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 128}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 384, 768}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 768}
		params.LSI = []int{895, 447}
		params.NCL = []int{768, 64}
	} else if level == 1 && variant == "RSDP-G" && schemeType == "fast" {
		params.Off = []int{0, 0, 0, 0, 2, 6, 6, 38, 38}
		params.NPL = []int{1, 2, 4, 8, 14, 24, 48, 64, 128}
		params.LPL = []int{0, 0, 0, 1, 2, 0, 16, 0, 128}
		params.LSI = []int{165, 85, 27, 14}
		params.NCL = []int{128, 16, 2, 1}
	} else if level == 1 && variant == "RSDP-G" && schemeType == "balanced" {
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 0}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 256}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 0, 256}
		params.LSI = []int{255}
		params.NCL = []int{256}
	} else if level == 1 && variant == "RSDP-G" && schemeType == "small" {
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 512}
		params.LSI = []int{511}
		params.NCL = []int{512}
	} else if level == 3 && variant == "RSDP-G" && schemeType == "fast" {
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 64}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 192}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 32, 192}
		params.LSI = []int{255, 223}
		params.NCL = []int{192, 32}
	} else if level == 3 && variant == "RSDP-G" && schemeType == "balanced" {
		params.Off = []int{0, 0, 0, 0, 0, 8, 24, 24, 24, 24}
		params.NPL = []int{1, 2, 4, 8, 16, 24, 32, 64, 128, 256}
		params.LPL = []int{0, 0, 0, 0, 4, 8, 0, 0, 0, 256}
		params.LSI = []int{279, 47, 27}
		params.NCL = []int{256, 8, 4}
	} else if level == 3 && variant == "RSDP-G" && schemeType == "small" {
		params.Off = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512}
		params.LPL = []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 512}
		params.LSI = []int{511}
		params.NCL = []int{512}
	} else if level == 5 && variant == "RSDP-G" && schemeType == "fast" {
		params.Off = []int{0, 0, 0, 0, 0, 0, 8, 24, 88, 88}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 56, 96, 128, 256}
		params.LPL = []int{0, 0, 0, 0, 0, 4, 8, 32, 0, 256}
		params.LSI = []int{343, 183, 111, 59}
		params.NCL = []int{256, 32, 8, 4}
	} else if level == 5 && variant == "RSDP-G" && schemeType == "balanced" {
		params.Off = []int{0, 0, 0, 0, 0, 0, 8, 8, 8, 200}
		params.NPL = []int{1, 2, 4, 8, 16, 32, 56, 112, 224, 256}
		params.LPL = []int{0, 0, 0, 0, 0, 4, 0, 0, 96, 256}
		params.LSI = []int{455, 359, 59}
		params.NCL = []int{256, 96, 4}
	} else if level == 5 && variant == "RSDP-G" && schemeType == "small" {
		params.Off = []int{0, 0, 0, 0, 4, 4, 4, 4, 4, 4, 260}
		params.NPL = []int{1, 2, 4, 8, 12, 24, 48, 96, 192, 384, 512}
		params.LPL = []int{0, 0, 0, 2, 0, 0, 0, 0, 0, 128, 512}
		params.LSI = []int{771, 643, 13}
		params.NCL = []int{512, 128, 2}
	} else {
		return TreeParams{}, fmt.Errorf("invalid parameters for tree structures")
	}
	params.Total_nodes = Sum(params.NPL)
	return params, nil
}
*/
