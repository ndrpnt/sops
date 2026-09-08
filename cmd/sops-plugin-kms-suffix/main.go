package main

import (
	"bytes"
	"context"
	"fmt"
	"os"

	sdk "github.com/getsops/sops/v3/pluginsdk"
)

func main() {
	plugin, err := New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugin error: instantiating Scaleway Key Manager client: %v\n", err)
		os.Exit(1)
	}
	os.Exit(sdk.Run(plugin))
}

type suffixConfig struct {
	Suffix string `json:"suffix"`
}

type suffixPlugin struct{}

func New() (*suffixPlugin, error) {
	return &suffixPlugin{}, nil
}

func (p *suffixPlugin) Wrap(ctx context.Context, req sdk.EncryptRequest[suffixConfig]) (*sdk.EncryptResponse, error) {
	return &sdk.EncryptResponse{
		Ciphertext: []byte(string(req.Plaintext) + req.Configuration.Suffix),
	}, nil
}

func (p *suffixPlugin) Unwrap(ctx context.Context, req sdk.DecryptRequest[suffixConfig]) (*sdk.DecryptResponse, error) {
	return &sdk.DecryptResponse{
		Plaintext: bytes.TrimSuffix(req.Ciphertext, []byte(req.Configuration.Suffix)),
	}, nil
}
