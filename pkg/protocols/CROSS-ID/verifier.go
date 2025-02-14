package CROSSID

import (
	"crypto/rand"
	"fmt"
)

func VerifierHandleConnection(msg_type string) {
	switch msg_type {
	case "chal1":
		Chal1Msg()
	case "chal2":
		msg := Chal2Msg()
		fmt.Println(msg)
	case "verify":
		VerifyMsg()
	default:
		fmt.Errorf("Invalid message type: %s", msg_type)
	}
}

func Chal1Msg() {
	//Sample uniformly at random from F^*_p
}

func Chal2Msg() []byte {
	bit := make([]byte, 1)
	rand.Read(bit)
	bit[0] = bit[0] % 2
	return bit
}

func VerifyMsg() {

}
