package network

import (
	"errors"
	"fmt"
)

// SendErrorKind identifies a deterministic local send failure. These failures
// depend only on the message and local protocol rules, so retrying the same
// message cannot make them succeed.
type SendErrorKind uint8

const (
	SendErrorInvalidMessage SendErrorKind = iota + 1
	SendErrorMarshal
	SendErrorInvalidClass
	SendErrorPacketTooLarge
)

func (kind SendErrorKind) String() string {
	switch kind {
	case SendErrorInvalidMessage:
		return "invalid-message"
	case SendErrorMarshal:
		return "marshal"
	case SendErrorInvalidClass:
		return "invalid-class"
	case SendErrorPacketTooLarge:
		return "packet-too-large"
	default:
		return fmt.Sprintf("send-error-kind-%d", kind)
	}
}

// PermanentSendError wraps a deterministic local failure. Callers should not
// retry the same message when this error is present in the error chain.
type PermanentSendError struct {
	Kind SendErrorKind
	err  error
}

func (err *PermanentSendError) Error() string {
	if err == nil || err.err == nil {
		return "permanent send error"
	}
	return err.err.Error()
}

func (err *PermanentSendError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.err
}

// NewPermanentSendError marks err as a deterministic local send failure. It
// preserves an existing PermanentSendError so nested transport layers do not
// overwrite the original reason.
func NewPermanentSendError(kind SendErrorKind, err error) error {
	if err == nil {
		return nil
	}
	if IsPermanentSendError(err) {
		return err
	}
	return &PermanentSendError{Kind: kind, err: err}
}

// IsPermanentSendError reports whether retrying the same message is guaranteed
// to fail without changing the message or local protocol configuration.
func IsPermanentSendError(err error) bool {
	var permanent *PermanentSendError
	return errors.As(err, &permanent)
}

func validNetworkClass(class uint8) bool {
	return class <= NetClassBulkGossip
}
