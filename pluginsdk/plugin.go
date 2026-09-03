package pluginsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	pluginpb "github.com/getsops/sops/v3/plugin"
	"google.golang.org/protobuf/proto"
)

// TODO: provide Init func
type Plugin[T any] interface {
	Wrap(context.Context, EncryptRequest[T]) (*EncryptResponse, error)
	Unwrap(context.Context, DecryptRequest[T]) (*DecryptResponse, error)
}

// TODO: handle signals
func Run[T any](plugin Plugin[T]) int {
	ctx := context.Background()
	command := flag.String("c", "", "encrypt or decrypt")
	flag.Parse()
	msgIn, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugin error: reading stdin: %v\n", err)
		return 1
	}
	var resp interface{ Marshal() ([]byte, error) }
	switch *command {
	case "encrypt":
		var req EncryptRequest[T]
		err = req.Unmarshal(msgIn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "plugin error: reading request: %v\n", err)
			return 1
		}
		resp, err = plugin.Wrap(ctx, req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "plugin error: wrapping key: %v\n", err)
			return 1
		}
	case "decrypt":
		var req DecryptRequest[T]
		err = req.Unmarshal(msgIn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "plugin error: reading request: %v\n", err)
			return 1
		}
		resp, err = plugin.Unwrap(ctx, req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "plugin error: unwrapping key: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "plugin error: unrecognized command: %s\n", *command)
		return 1
	}
	msgOut, err := resp.Marshal()
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugin error: writting response: %v\n", err)
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

func (r *EncryptRequest[T]) Unmarshal(msg []byte) error {
	var protoReq pluginpb.EncryptRequest
	if err := proto.Unmarshal(msg, &protoReq); err != nil {
		return fmt.Errorf("unmarshaling proto msg: %w", err)
	}
	r.Plaintext = protoReq.GetPlaintext()
	r.Configuration = new(T)
	jsonBytes, err := protoReq.GetConfiguration().MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshaling config to JSON: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(r.Configuration); err != nil {
		return fmt.Errorf("decoding config into %T: %w", r.Configuration, err)
	}
	return nil
}

type DecryptRequest[T any] struct {
	Ciphertext    []byte
	Configuration *T
}

func (r *DecryptRequest[T]) Unmarshal(msg []byte) error {
	var protoReq pluginpb.DecryptRequest
	if err := proto.Unmarshal(msg, &protoReq); err != nil {
		return fmt.Errorf("unmarshaling proto msg: %w", err)
	}
	r.Ciphertext = protoReq.GetCiphertext()
	r.Configuration = new(T)
	jsonBytes, err := protoReq.GetConfiguration().MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshaling config to JSON: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(r.Configuration); err != nil {
		return fmt.Errorf("decoding config into %T: %w", r.Configuration, err)
	}
	return nil
}

type DecryptResponse struct {
	Plaintext []byte
}

func (resp *DecryptResponse) Marshal() ([]byte, error) {
	protoResp := pluginpb.DecryptResponse{Plaintext: resp.Plaintext}
	msg, err := proto.Marshal(&protoResp)
	if err != nil {
		return nil, fmt.Errorf("marshaling proto msg: %w", err)
	}
	return msg, nil
}

type EncryptResponse struct {
	Ciphertext []byte
}

func (resp *EncryptResponse) Marshal() ([]byte, error) {
	protoResp := pluginpb.EncryptResponse{Ciphertext: resp.Ciphertext}
	msg, err := proto.Marshal(&protoResp)
	if err != nil {
		return nil, fmt.Errorf("marshaling proto msg: %w", err)
	}
	return msg, nil
}
