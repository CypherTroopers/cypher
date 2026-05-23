package vm

const (
	TLOAD  OpCode = 0x5c
	TSTORE OpCode = 0x5d
	MCOPY  OpCode = 0x5e
)

func init() {
	opCodeToString[TLOAD] = "TLOAD"
	opCodeToString[TSTORE] = "TSTORE"
	opCodeToString[MCOPY] = "MCOPY"
}
