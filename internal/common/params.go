package common

import "fmt"

// 3 NIST security levels
// Category 1: 128 AES gates, roughly 143 bits of security
// Category 3: 192 AES gates, roughly 207 bits of security
// Category 5: 256 AES gates, roughly 272 bits of security

type SchemeData struct {
	SecurityLevel int
	Csprng        string
	Lambda        int
	Params        Params
}
type Params struct {
	P int
	Z int
	N int
	K int
}

func GetSecurityConfig(level int) (SchemeData, error) {
	switch level {
	case 1:
		return SchemeData{
			SecurityLevel: 1,
			Csprng:        "SHAKE128-256", // SHAKE-128 with 256 bit output
			Lambda:        128,
			Params: Params{
				P: 127,
				Z: 7,
				N: 127,
				K: 76,
			},
		}, nil

	case 3:
		return SchemeData{
			SecurityLevel: 3,
			Csprng:        "SHAKE256-384", // SHAKE-256 with 384 bit output
			Lambda:        192,
			Params: Params{
				P: 127,
				Z: 7,
				N: 187,
				K: 111,
			},
		}, nil

	case 5:
		return SchemeData{
			SecurityLevel: 5,
			Csprng:        "SHAKE256-512", // SHAKE-256 with 512 bit output
			Lambda:        256,
			Params: Params{
				P: 127,
				Z: 7,
				N: 251,
				K: 150,
			},
		}, nil

	default:
		return SchemeData{}, fmt.Errorf("invalid security level: %d. Must be 1, 3, or 5", level)
	}
}
