/*
Package kms contains an implementation of the github.com/getsops/sops/v3.MasterKey
interface that encrypts and decrypts the data key using AWS KMS with the SDK
for Go V2.
*/
package plugin // import "github.com/getsops/sops/v3/kms"

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"google.golang.org/protobuf/proto"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

const pluginEnvKey = "__SOPS_PLUGIN"

var pluginEnv = []string{pluginEnvKey + "=1"}

type MasterKey struct {
	PluginName    string
	Configuration map[string]any
	encryptedKey  []byte
}

// NewMasterKey creates a new MasterKey from an ARN, role and context, setting
// the creation date to the current date.
func NewMasterKey(pluginName string, additionalConfig map[string]any) (*MasterKey, error) {
	return &MasterKey{
		PluginName:    pluginName,
		Configuration: additionalConfig,
	}, nil
}

// Encrypt takes a SOPS data key, encrypts it with KMS and stores the result
// in the EncryptedKey field.
//
// Consider using EncryptContext instead.
func (key *MasterKey) Encrypt(dataKey []byte) error {
	return key.EncryptContext(context.Background(), dataKey)
}

// EncryptContext takes a SOPS data key, encrypts it with KMS and stores the result
// in the EncryptedKey field.
func (key *MasterKey) EncryptContext(ctx context.Context, dataKey []byte) error {
	protoConfig, err := structpb.NewStruct(key.Configuration)
	if err != nil {
		return fmt.Errorf("failed to build config struct: %v", err)
	}
	req := &EncryptRequest{
		Plaintext:     dataKey,
		Configuration: protoConfig,
	}

	protoReq, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal EncryptRequest: %v", err)
	}

	protoResp, err := callPlugin(ctx, key.PluginName, "encrypt", protoReq)
	if err != nil {
		return fmt.Errorf("failed to call plugin: %v", err)
	}

	resp := &EncryptResponse{}
	err = proto.Unmarshal(protoResp, resp)
	if err != nil {
		return fmt.Errorf("failed to unmarshal EncryptResponse: %v", err)
	}

	key.SetEncryptedDataKey(resp.Ciphertext)
	return nil
}

// EncryptIfNeeded encrypts the provided SOPS data key, if it has not been
// encrypted yet.
func (key *MasterKey) EncryptIfNeeded(dataKey []byte) error {
	if key.encryptedKey == nil {
		return key.Encrypt(dataKey)
	}
	return nil
}

// EncryptedDataKey returns the encrypted data key this master key holds.
func (key *MasterKey) EncryptedDataKey() []byte {
	return key.encryptedKey
}

// SetEncryptedDataKey sets the encrypted data key for this master key.
func (key *MasterKey) SetEncryptedDataKey(enc []byte) {
	key.encryptedKey = enc
}

// Decrypt decrypts the EncryptedKey with a newly created AWS KMS config, and
// returns the result.
//
// Consider using DecryptContext instead.
func (key *MasterKey) Decrypt() ([]byte, error) {
	return key.DecryptContext(context.Background())
}

// DecryptContext decrypts the EncryptedKey with a newly created AWS KMS config, and
// returns the result.
func (key *MasterKey) DecryptContext(ctx context.Context) ([]byte, error) {
	protoConfig, err := structpb.NewStruct(key.Configuration)
	if err != nil {
		return nil, fmt.Errorf("failed to build config struct: %v", err)
	}
	req := &DecryptRequest{
		Ciphertext:    key.encryptedKey,
		Configuration: protoConfig,
	}

	protoReq, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DecryptRequest: %v", err)
	}

	protoResp, err := callPlugin(ctx, key.PluginName, "decrypt", protoReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call plugin: %v", err)
	}

	resp := &DecryptResponse{}
	err = proto.Unmarshal(protoResp, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal DecryptResponse: %v", err)
	}

	return resp.Plaintext, nil
}

// NeedsRotation returns whether the data key needs to be rotated or not.
func (key *MasterKey) NeedsRotation() bool {
	return false
}

// ToString converts the key to a string representation.
func (key *MasterKey) ToString() string {
	return string(key.encryptedKey)
}

// ToMap converts the MasterKey to a map for serialization purposes.
func (key MasterKey) ToMap() map[string]interface{} {
	// Instancie Map vide
	// return map[string]interface{}{}
	return map[string]interface{}{"coucou": 4}
}

// TypeToIdentifier returns the string identifier for the MasterKey type.
func (key *MasterKey) TypeToIdentifier() string {
	return "plugin"
}

func callPlugin(_ context.Context, name string, command string, req []byte) ([]byte, error) {
	switch command {
	case "encrypt":
		cmd := exec.Command(name, "-c", "encrypt")
		cmd.Env = pluginEnv
		cmd.Stdin = bytes.NewReader(req)
		return cmd.Output()
	case "decrypt":
		cmd := exec.Command(name, "-c", "decrypt")
		cmd.Env = pluginEnv
		cmd.Stdin = bytes.NewReader(req)
		return cmd.Output()
	default:
		panic("unrecognized command")
	}
}
