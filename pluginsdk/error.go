package pluginsdk

import (
	"context"
	"errors"
	"fmt"

	pluginpb "github.com/getsops/sops/v3/plugin"
)

const (
	CodeCanceled           Code = 1
	CodeUnknown            Code = 2
	CodeInvalidArgument    Code = 3
	CodeDeadlineExceeded   Code = 4
	CodeNotFound           Code = 5
	CodeAlreadyExists      Code = 6
	CodePermissionDenied   Code = 7
	CodeResourceExhausted  Code = 8
	CodeFailedPrecondition Code = 9
	CodeAborted            Code = 10
	CodeOutOfRange         Code = 11
	CodeUnimplemented      Code = 12
	CodeInternal           Code = 13
	CodeUnavailable        Code = 14
	CodeDataLoss           Code = 15
	CodeUnauthenticated    Code = 16
)

type Code uint32

func (c Code) String() string {
	switch c {
	case CodeCanceled:
		return "canceled"
	case CodeUnknown:
		return "unknown"
	case CodeInvalidArgument:
		return "invalid_argument"
	case CodeDeadlineExceeded:
		return "deadline_exceeded"
	case CodeNotFound:
		return "not_found"
	case CodeAlreadyExists:
		return "already_exists"
	case CodePermissionDenied:
		return "permission_denied"
	case CodeResourceExhausted:
		return "resource_exhausted"
	case CodeFailedPrecondition:
		return "failed_precondition"
	case CodeAborted:
		return "aborted"
	case CodeOutOfRange:
		return "out_of_range"
	case CodeUnimplemented:
		return "unimplemented"
	case CodeInternal:
		return "internal"
	case CodeUnavailable:
		return "unavailable"
	case CodeDataLoss:
		return "data_loss"
	case CodeUnauthenticated:
		return "unauthenticated"
	}
	return fmt.Sprintf("code_%d", c)
}

func (c Code) ToProto() pluginpb.Code {
	switch c {
	case CodeCanceled:
		return pluginpb.Code_CODE_CANCELED
	case CodeUnknown:
		return pluginpb.Code_CODE_UNKNOWN
	case CodeInvalidArgument:
		return pluginpb.Code_CODE_INVALID_ARGUMENT
	case CodeDeadlineExceeded:
		return pluginpb.Code_CODE_DEADLINE_EXCEEDED
	case CodeNotFound:
		return pluginpb.Code_CODE_NOT_FOUND
	case CodeAlreadyExists:
		return pluginpb.Code_CODE_ALREADY_EXISTS
	case CodePermissionDenied:
		return pluginpb.Code_CODE_PERMISSION_DENIED
	case CodeResourceExhausted:
		return pluginpb.Code_CODE_RESOURCE_EXHAUSTED
	case CodeFailedPrecondition:
		return pluginpb.Code_CODE_FAILED_PRECONDITION
	case CodeAborted:
		return pluginpb.Code_CODE_ABORTED
	case CodeOutOfRange:
		return pluginpb.Code_CODE_OUT_OF_RANGE
	case CodeUnimplemented:
		return pluginpb.Code_CODE_UNIMPLEMENTED
	case CodeInternal:
		return pluginpb.Code_CODE_INTERNAL
	case CodeUnavailable:
		return pluginpb.Code_CODE_UNAVAILABLE
	case CodeDataLoss:
		return pluginpb.Code_CODE_DATA_LOSS
	case CodeUnauthenticated:
		return pluginpb.Code_CODE_UNAUTHENTICATED
	}
	return pluginpb.Code_CODE_UNKNOWN
}

type Error struct {
	code  Code
	cause error
}

func NewError(code Code, cause error) *Error {
	return &Error{code: code, cause: cause}
}

func NewErrorf(code Code, format string, args ...any) *Error {
	return NewError(code, fmt.Errorf(format, args...))
}

func WrapError(err error) *Error {
	if err == nil {
		return nil
	}
	if pErr, ok := errors.AsType[*Error](err); ok {
		return pErr
	}
	if errors.Is(err, context.Canceled) {
		return NewError(CodeCanceled, err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return NewError(CodeDeadlineExceeded, err)
	}
	return NewError(CodeUnknown, err)
}

func (e *Error) Code() Code {
	if e == nil || e.code == 0 {
		return CodeUnknown
	}
	return e.code
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.cause == nil {
		return e.Code().String()
	}
	return e.Code().String() + ": " + e.cause.Error()
}

func (e *Error) ToProto() *pluginpb.Error {
	return &pluginpb.Error{
		Code:    e.code.ToProto(),
		Message: e.Error(),
	}
}
