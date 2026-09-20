package main

import (
	"bytes"
	"context"
	"os"

	sdk "github.com/getsops/sops/v3/pluginsdk"
)

func main() {
	os.Exit(sdk.Run(suffixPlugin{}))
}

type suffixConfig struct {
	Suffix string `json:"suffix"`
}

type suffixPlugin struct{}

func (suffixPlugin) Wrap(ctx context.Context, req sdk.EncryptRequest[suffixConfig]) (*sdk.EncryptResponse, error) {
	return &sdk.EncryptResponse{
		Ciphertext: []byte(string(req.Plaintext) + req.Configuration.Suffix),
	}, nil
}

func (suffixPlugin) Unwrap(ctx context.Context, req sdk.DecryptRequest[suffixConfig]) (*sdk.DecryptResponse, error) {
	return &sdk.DecryptResponse{
		Plaintext: bytes.TrimSuffix(req.Ciphertext, []byte(req.Configuration.Suffix)),
	}, nil
}
