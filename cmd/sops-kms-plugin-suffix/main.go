package main

import (
	"bytes"
	"os"

	sdk "github.com/getsops/sops/v3/pluginsdk"
)

func main() {
	plugin := &suffixPlugin{}
	os.Exit(sdk.Run(plugin))
}

type suffixConfig struct {
	Suffix string `json:"suffix"`
}

type suffixPlugin struct{}

func (p *suffixPlugin) Wrap(req sdk.EncryptRequest[suffixConfig]) (*sdk.EncryptResponse, error) {
	return &sdk.EncryptResponse{
		Ciphertext: []byte(string(req.Plaintext) + req.Configuration.Suffix),
	}, nil
}

func (p *suffixPlugin) Unwrap(req sdk.DecryptRequest[suffixConfig]) (*sdk.DecryptResponse, error) {
	return &sdk.DecryptResponse{
		Plaintext: bytes.TrimSuffix(req.Ciphertext, []byte(req.Configuration.Suffix)),
	}, nil
}
