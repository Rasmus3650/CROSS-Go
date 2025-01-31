package common

import "fmt"

// 3 NIST security levels
// Category 1: 128 AES gates, roughly 143 bits of security
// Category 3: 192 AES gates, roughly 207 bits of security
// Category 5: 256 AES gates, roughly 272 bits of security

type SecurityData struct {
	category int
	csprng   string
	params   Params
}
type Params struct {
	p int
	z int
	n int
	k int
}

func GetSecurityConfig(level int) (SecurityData, error) {
	switch level {
	case 1:
		return SecurityData{
			category: 1,
			csprng:   "SHAKE128", // SHAKE-128 with 256 bit output
			params: Params{
				p: 127,
				z: 7,
				n: 127,
				k: 76,
			},
		}, nil

	case 3:
		return SecurityData{
			category: 3,
			csprng:   "SHAKE256", // SHAKE-256 with 384 bit output
			params: Params{
				p: 127,
				z: 7,
				n: 187,
				k: 111,
			},
		}, nil

	case 5:
		return SecurityData{
			category: 5,
			csprng:   "SHAKE256", // SHAKE-256 with 512 bit output
			params: Params{
				p: 127,
				z: 7,
				n: 251,
				k: 150,
			},
		}, nil

	default:
		return SecurityData{}, fmt.Errorf("invalid security level: %d. Must be 1, 3, or 5", level)
	}
}
