package vm

// CLZ returns the number of leading zero bits in a 256-bit word (EIP-7939).
const CLZ OpCode = 0x1e

func init() {
	opCodeToString[CLZ] = "CLZ"
}
