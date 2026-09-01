package network

import (
	"errors"
	"fmt"
	"testing"
)

type marshalFailureMessage struct {
	privateValue string
}

func requirePermanentSendErrorKind(t *testing.T, err error, want SendErrorKind) {
	t.Helper()
	if err == nil {
		t.Fatal("expected send error")
	}
	if !IsPermanentSendError(err) {
		t.Fatalf("send error was not classified as permanent: %v", err)
	}
	var permanent *PermanentSendError
	if !errors.As(err, &permanent) {
		t.Fatalf("permanent send error was not exported through errors.As: %T", err)
	}
	if permanent.Kind != want {
		t.Fatalf("permanent send error kind = %v, want %v", permanent.Kind, want)
	}
}

func TestMarshalFailureIsPermanentAcrossTransports(t *testing.T) {
	RegisterMessage(&marshalFailureMessage{})
	message := &marshalFailureMessage{privateValue: "not protobuf serializable"}

	_, marshalErr := Marshal(message)
	requirePermanentSendErrorKind(t, marshalErr, SendErrorMarshal)

	transports := map[string]Conn{
		"tcp":  &TCPConn{},
		"kcp":  &KCPConn{},
		"quic": &QUICConn{},
	}
	for name, conn := range transports {
		t.Run(name, func(t *testing.T) {
			_, err := conn.Send(message)
			requirePermanentSendErrorKind(t, err, SendErrorMarshal)
		})
	}
}

func TestQUICDeterministicValidationErrorsArePermanent(t *testing.T) {
	conn := new(QUICConn)
	_, err := conn.sendRaw(nil, NetClassBulkGossip+1)
	requirePermanentSendErrorKind(t, err, SendErrorInvalidClass)

	tooLarge := make([]byte, quicControlMaxPacketSize+1)
	_, err = conn.sendRaw(tooLarge, NetClassHotstuffControl)
	requirePermanentSendErrorKind(t, err, SendErrorPacketTooLarge)
}

func TestQUICStreamLocalFailureRemainsTransient(t *testing.T) {
	err := fmt.Errorf("send stream: %w", &quicStreamLocalSendError{err: ErrTimeout})
	if IsPermanentSendError(err) {
		t.Fatalf("transient stream failure was classified as permanent: %v", err)
	}
	if !isQUICStreamLocalSendError(err) {
		t.Fatalf("transient stream failure lost its stream-local classification: %v", err)
	}
}
