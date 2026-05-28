package types

import "errors"

var (
	ErrGasFeeCapTooLow = errors.New("max fee per gas less than block base fee")
)
