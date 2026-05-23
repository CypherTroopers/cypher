package bls

const curveFp254BNb = 0

func init() {
	if err := Init(curveFp254BNb); err != nil {
		panic(err)
	}
}
