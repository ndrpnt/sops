package main

import (
	"context"
	"os"

	"github.com/getsops/sops/v3/cmd/sops-plugin-kms-pgp/internal/pgp"
	"github.com/getsops/sops/v3/pluginsdk"
)

func main() {
	os.Exit(pluginsdk.Run(pgpPlugin{}))
}

type pgpConfig struct {
	Fingerprint string `json:"fingerprint"`
}

type pgpPlugin struct{}

func (pgpPlugin) Wrap(ctx context.Context, req pluginsdk.EncryptRequest[pgpConfig]) (*pluginsdk.EncryptResponse, error) {
	key := pgp.NewMasterKeyFromFingerprint(req.Configuration.Fingerprint)
	if err := key.Encrypt(req.Plaintext); err != nil {
		return nil, err
	}
	return &pluginsdk.EncryptResponse{Ciphertext: key.EncryptedDataKey()}, nil
}

func (pgpPlugin) Unwrap(ctx context.Context, req pluginsdk.DecryptRequest[pgpConfig]) (*pluginsdk.DecryptResponse, error) {
	key := pgp.NewMasterKeyFromFingerprint(req.Configuration.Fingerprint)
	key.SetEncryptedDataKey(req.Ciphertext)
	plaintext, err := key.Decrypt()
	if err != nil {
		return nil, err
	}
	return &pluginsdk.DecryptResponse{Plaintext: plaintext}, nil
}
