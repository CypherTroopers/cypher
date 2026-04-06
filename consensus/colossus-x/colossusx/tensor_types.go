package colossusx

type TensorTile struct {
	MatrixA [256]int8
	MatrixB [256]int8
	Bias    [16]int32
	Permute [32]byte
	Meta    [32]byte
}

type TensorDAGAccessor interface {
	TileCount() uint64
	ReadTensorTile(uint64, *TensorTile)
}
