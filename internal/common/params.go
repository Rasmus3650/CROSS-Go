package common

import "fmt"

// SecurityLevel represents the security level (1, 3, or 5)
type SecurityLevel int

const (
	low    SecurityLevel = 1
	medium SecurityLevel = 3
	high   SecurityLevel = 5
)

type SecurityData struct {
	category int
	csprng   string
	params   CROSSParam
}
type CROSSParam struct {
	p int
	z int
	n int
	k int
}

func GetSecurityConfig(level SecurityLevel) (SecurityData, error) {
	switch level {
	case low:
		return SecurityData{
			category: 1,
			csprng:   "SHAKE128", // SHAKE-128 with 256 bit output
			params: CROSSParam{
				p: 127,
				z: 7,
				n: 127,
				k: 76,
			},
		}, nil

	case medium:
		return SecurityData{
			category: 3,
			csprng:   "SHAKE256", // SHAKE-256 with 384 bit output
			params: CROSSParam{
				p: 127,
				z: 7,
				n: 187,
				k: 111,
			},
		}, nil

	case high:
		return SecurityData{
			category: 5,
			csprng:   "SHAKE256", // SHAKE-256 with 512 bit output
			params: CROSSParam{
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
