package pluginsdk

import (
	"fmt"

	pluginpb "github.com/getsops/sops/v3/plugin"
)

const (
	CodeUnspecified     Code = 0
	CodeCanceled        Code = 1
	CodeUnknown         Code = 2
	CodeInvalidArgument Code = 3

	minCode = 0
	maxCode = 3
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
	}
	return fmt.Sprintf("code_%d", c)
}

func (c Code) ToProto() pluginpb.Code {
	if c >= minCode && c <= maxCode {
		return pluginpb.Code(c)
	}
	return pluginpb.Code(CodeUnspecified)
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
	code := e.Code()
	if e.cause == nil {
		return code.String()
	}
	return code.String() + ": " + e.cause.Error()
}

func (e *Error) ToProto() *pluginpb.Error {
	return &pluginpb.Error{
		Code:    e.code.ToProto(),
		Message: e.Error(),
	}
}
