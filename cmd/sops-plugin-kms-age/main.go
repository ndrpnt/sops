package main

import (
	"context"
	"fmt"
	"os"

	"github.com/getsops/sops/v3/cmd/sops-plugin-kms-age/internal/age"
	"github.com/getsops/sops/v3/pluginsdk"
)

func main() {
	os.Exit(pluginsdk.Run(agePlugin{}))
}

type ageConfig struct {
	Recipient string `json:"recipient"`
}

type agePlugin struct{}

func configuredKey(config *ageConfig) (*age.MasterKey, error) {
	if config == nil {
		return nil, fmt.Errorf("recipient is required")
	}
	return age.MasterKeyFromRecipient(config.Recipient)
}

func (agePlugin) Wrap(ctx context.Context, req pluginsdk.EncryptRequest[ageConfig]) (*pluginsdk.EncryptResponse, error) {
	key, err := configuredKey(req.Configuration)
	if err != nil {
		return nil, err
	}
	if err := key.Encrypt(req.Plaintext); err != nil {
		return nil, err
	}
	return &pluginsdk.EncryptResponse{Ciphertext: key.EncryptedDataKey()}, nil
}

func (agePlugin) Unwrap(ctx context.Context, req pluginsdk.DecryptRequest[ageConfig]) (*pluginsdk.DecryptResponse, error) {
	key, err := configuredKey(req.Configuration)
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
