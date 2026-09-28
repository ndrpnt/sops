package main

import (
	"context"
	"os"

	"github.com/getsops/sops/v3/cmd/sops-plugin-kms-hcvault/internal/hcvault"
	"github.com/getsops/sops/v3/pluginsdk"
)

func main() {
	os.Exit(pluginsdk.Run(hcvaultPlugin{}))
}

type hcvaultConfig struct {
	URI string `json:"uri"`
}

type hcvaultPlugin struct{}

func (hcvaultPlugin) Wrap(ctx context.Context, req pluginsdk.EncryptRequest[hcvaultConfig]) (*pluginsdk.EncryptResponse, error) {
	key, err := hcvault.NewMasterKeyFromURI(req.Configuration.URI)
	if err != nil {
		return nil, err
	}
	if err := key.Encrypt(req.Plaintext); err != nil {
		return nil, err
	}
	return &pluginsdk.EncryptResponse{Ciphertext: key.EncryptedDataKey()}, nil
}

func (hcvaultPlugin) Unwrap(ctx context.Context, req pluginsdk.DecryptRequest[hcvaultConfig]) (*pluginsdk.DecryptResponse, error) {
	key, err := hcvault.NewMasterKeyFromURI(req.Configuration.URI)
	if err != nil {
		return nil, err
	}
	key.SetEncryptedDataKey(req.Ciphertext)
	plaintext, err := key.Decrypt()
	if err != nil {
		return nil, err
	}
	return &pluginsdk.DecryptResponse{Plaintext: plaintext}, nil
}
