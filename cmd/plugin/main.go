package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"google.golang.org/protobuf/proto"
)

func main() {
	command := flag.String("c", "", "encrypt or decrypt")
	flag.Parse()
	switch *command {
	case "encrypt":
		if err := encrypt(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "decrypt":
		if err := decrypt(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	default:
		panic("unrecognized command")
	}
}

func decrypt() error {
	protoReq, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	req := &DecryptRequest{}
	err = proto.Unmarshal(protoReq, req)
	if err != nil {
		return fmt.Errorf("failed to unmarshal EncryptRequest: %v", err)
	}

	// decrypt logic
	suffixEncryption := len(req.Ciphertext) - 3
	respDecrypted := req.Ciphertext[0:suffixEncryption]

	resp := &EncryptResponse{
		Ciphertext: respDecrypted,
	}

	protoResp, err := proto.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal EncryptResponse: %v", err)
	}

	if _, err := os.Stdout.Write(protoResp); err != nil {
		return fmt.Errorf("writing stdout: %w", err)
	}

	return nil
}

func encrypt() error {
	protoReq, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	req := &EncryptRequest{}
	err = proto.Unmarshal(protoReq, req)
	if err != nil {
		return fmt.Errorf("failed to unmarshal EncryptRequest: %v", err)
	}

	// encrypt logic
	respEncryptStr := string(req.Plaintext) + "bla"

	resp := &EncryptResponse{
		Ciphertext: []byte(respEncryptStr),
	}

	protoResp, err := proto.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal EncryptResponse: %v", err)
	}

	if _, err := os.Stdout.Write(protoResp); err != nil {
		return fmt.Errorf("writing stdout: %w", err)
	}

	return nil
}
