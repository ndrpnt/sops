package main

import (
	"context"
	"fmt"
	"os"

	sdk "github.com/getsops/sops/v3/pluginsdk"
	key_manager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
)

func main() {
	plugin, err := New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugin error: instantiating Scaleway Key Manager client: %v\n", err)
		os.Exit(1)
	}
	os.Exit(sdk.Run(plugin))
}

type scwConfig struct {
	ID             string `json:"id"`
	Region         string `json:"region"`
	AssociatedData []byte `json:"associated_data"`
}

type scwPlugin struct {
	client *key_manager.API
}

// FIXME: quick-and-dirty config loading that is broken in many ways.
func New() (*scwPlugin, error) {
	config, err := scw.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("loading Scaleway config: %v", err)
	}
	configProfile, err := config.GetActiveProfile()
	if err != nil {
		return nil, fmt.Errorf("getting active Scaleway profile: %v", err)
	}
	profile := scw.MergeProfiles(configProfile, scw.LoadEnvProfile())
	client, err := scw.NewClient(
		scw.WithProfile(profile),
		scw.WithUserAgent("sops-kms-plugin-scw"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating Scaleway client: %v", err)
	}
	return &scwPlugin{client: key_manager.NewAPI(client)}, nil
}

func (p *scwPlugin) Wrap(ctx context.Context, req sdk.EncryptRequest[scwConfig]) (*sdk.EncryptResponse, error) {
	resp, err := p.client.Encrypt(&key_manager.EncryptRequest{
		KeyID:          req.Configuration.ID,
		Plaintext:      req.Plaintext,
		AssociatedData: &req.Configuration.AssociatedData,
		Region:         scw.Region(req.Configuration.Region),
	}, scw.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("encrypting with Scaleway Key Manager: %v", err)
	}
	return &sdk.EncryptResponse{Ciphertext: resp.Ciphertext}, nil
}

func (p *scwPlugin) Unwrap(ctx context.Context, req sdk.DecryptRequest[scwConfig]) (*sdk.DecryptResponse, error) {
	resp, err := p.client.Decrypt(&key_manager.DecryptRequest{
		KeyID:          req.Configuration.ID,
		Ciphertext:     req.Ciphertext,
		AssociatedData: &req.Configuration.AssociatedData,
		Region:         scw.Region(req.Configuration.Region),
	}, scw.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("decrypting with Scaleway Key Manager: %v", err)
	}
	return &sdk.DecryptResponse{Plaintext: resp.Plaintext}, nil
}
