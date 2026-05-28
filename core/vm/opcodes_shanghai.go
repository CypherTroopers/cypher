package vm

const PUSH0 OpCode = 0x5f

func init() {
	opCodeToString[PUSH0] = "PUSH0"
}
