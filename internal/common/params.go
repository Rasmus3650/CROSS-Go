package common

import (
	"fmt"
)

// 3 NIST security levels
// Category 1: 128 AES gates, roughly 143 bits of security
// Category 3: 192 AES gates, roughly 207 bits of security
// Category 5: 256 AES gates, roughly 272 bits of security

type ProtocolData struct {
	T int
	W int
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

func GetProtocolConfig(schemeType, variant string, level int) (ProtocolData, error) {
	data := ProtocolData{}
	switch variant {
	case "RSDP-G":
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
