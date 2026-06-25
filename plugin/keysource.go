/*
Package kms contains an implementation of the github.com/getsops/sops/v3.MasterKey
interface that encrypts and decrypts the data key using AWS KMS with the SDK
for Go V2.
*/
package plugin // import "github.com/getsops/sops/v3/kms"

import (
	"context"
	"fmt"
)

type MasterKey struct {
	encryptedKey []byte
	name         string
}

// NewMasterKey creates a new MasterKey from an ARN, role and context, setting
// the creation date to the current date.
func NewMasterKey(name string) (*MasterKey, error) {
	return &MasterKey{name: name}, nil
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
	// Logique à implémenter pour chiffrer la dataKey à priori
	key.SetEncryptedDataKey(dataKey)
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
	return key.encryptedKey, nil
}

// NeedsRotation returns whether the data key needs to be rotated or not.
func (key *MasterKey) NeedsRotation() bool {
	return false
}

// ToString converts the key to a string representation.
func (key *MasterKey) ToString() string {
	return fmt.Sprintf("coucou, je suis la clé: %s", key.name)
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
