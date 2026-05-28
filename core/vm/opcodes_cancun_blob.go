package vm

const (
	BLOBHASH    OpCode = 0x49
	BLOBBASEFEE OpCode = 0x4a
)

func init() {
	opCodeToString[BLOBHASH] = "BLOBHASH"
	opCodeToString[BLOBBASEFEE] = "BLOBBASEFEE"
}
