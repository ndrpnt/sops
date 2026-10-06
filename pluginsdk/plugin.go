package pluginsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	pluginpb "github.com/getsops/sops/v3/plugin"
	"google.golang.org/protobuf/proto"
)

// TODO: provide Init func ?
type Plugin[T any] interface {
	Wrap(context.Context, EncryptRequest[T]) (*EncryptResponse, error)
	Unwrap(context.Context, DecryptRequest[T]) (*DecryptResponse, error)
}

type Runner[T any] struct {
	Plugin Plugin[T]
}

func (r *Runner[T]) Wrap(
	ctx context.Context,
	protoReq *pluginpb.EncryptRequest,
) *pluginpb.EncryptResponse {
	req := &EncryptRequest[T]{
		Plaintext:     protoReq.GetPlaintext(),
		Configuration: new(T),
	}
	jsonBytes, err := protoReq.GetConfiguration().MarshalJSON()
	if err != nil {
		return &pluginpb.EncryptResponse{
			Error: &pluginpb.Error{
				Code:    pluginpb.Code_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("marshaling config to JSON: %v", err),
			},
		}
	}
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(req.Configuration); err != nil {
		return &pluginpb.EncryptResponse{
			Error: &pluginpb.Error{
				Code:    pluginpb.Code_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("decoding config into %T: %v", req.Configuration, err),
			},
		}
	}
	resp, err := r.Plugin.Wrap(ctx, *req)
	if err != nil {
		return &pluginpb.EncryptResponse{
			Error: WrapError(err).ToProto(),
		}
	}
	return &pluginpb.EncryptResponse{Ciphertext: resp.Ciphertext}
}

func (r *Runner[T]) Unwrap(
	ctx context.Context,
	protoReq *pluginpb.DecryptRequest,
) *pluginpb.DecryptResponse {
	req := &DecryptRequest[T]{
		Ciphertext:    protoReq.GetCiphertext(),
		Configuration: new(T),
	}
	jsonBytes, err := protoReq.GetConfiguration().MarshalJSON()
	if err != nil {
		return &pluginpb.DecryptResponse{
			Error: &pluginpb.Error{
				Code:    pluginpb.Code_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("marshaling config to JSON: %v", err),
			},
		}
	}
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(req.Configuration); err != nil {
		return &pluginpb.DecryptResponse{
			Error: &pluginpb.Error{
				Code:    pluginpb.Code_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("decoding config into %T: %v", req.Configuration, err),
			},
		}
	}
	resp, err := r.Plugin.Unwrap(ctx, *req)
	if err != nil {
		return &pluginpb.DecryptResponse{
			Error: WrapError(err).ToProto(),
		}
	}
	return &pluginpb.DecryptResponse{Plaintext: resp.Plaintext}
}

func (r *Runner[T]) Run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Release a blocked request read when the host cancels the operation.
	stopRead := context.AfterFunc(ctx, func() { _ = os.Stdin.Close() })
	defer stopRead()
	command := flag.String("c", "", "encrypt or decrypt")
	flag.Parse()
	msgIn, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugin error: reading stdin: %v\n", err)
		return 1
	}
	var msgOut []byte
	switch *command {
	case "encrypt":
		var protoReq pluginpb.EncryptRequest
		if err := proto.Unmarshal(msgIn, &protoReq); err != nil {
			fmt.Fprintf(os.Stderr, "plugin error: unmarshaling proto msg: %v\n", err)
			return 1
		}
		protoResp := r.Wrap(ctx, &protoReq)
		if msgOut, err = proto.Marshal(protoResp); err != nil {
			fmt.Fprintf(os.Stderr, "plugin error: marshaling proto msg: %v\n", err)
			return 1
		}
	case "decrypt":
		var protoReq pluginpb.DecryptRequest
		if err := proto.Unmarshal(msgIn, &protoReq); err != nil {
			fmt.Fprintf(os.Stderr, "plugin error: unmarshaling proto msg: %v\n", err)
			return 1
		}
		protoResp := r.Unwrap(ctx, &protoReq)
		if msgOut, err = proto.Marshal(protoResp); err != nil {
			fmt.Fprintf(os.Stderr, "plugin error: marshaling proto msg: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "plugin error: unrecognized command: %s\n", *command)
		return 1
	}
	if _, err := os.Stdout.Write(msgOut); err != nil {
		fmt.Fprintf(os.Stderr, "plugin error: writing stdout: %v\n", err)
		return 1
	}
	return 0
}

type EncryptRequest[T any] struct {
	Plaintext     []byte
	Configuration *T
}

type DecryptRequest[T any] struct {
	Ciphertext    []byte
	Configuration *T
}

type DecryptResponse struct {
	Plaintext []byte
}

type EncryptResponse struct {
	Ciphertext []byte
}
