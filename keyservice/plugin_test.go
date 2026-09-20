package keyservice

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestPluginRequestCancellation(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)
	t.Setenv("SOPS_PLUGIN_KMS_CANCELED_EXEC", exe)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	key := &Key{KeyType: &Key_PluginKey{PluginKey: &PluginKey{
		PluginName: "canceled", Configuration: &structpb.Struct{},
	}}}
	server := &Server{}
	_, err = server.Encrypt(ctx, &EncryptRequest{Key: key, Plaintext: []byte("test")})
	require.ErrorContains(t, err, context.Canceled.Error())
	_, err = server.Decrypt(ctx, &DecryptRequest{Key: key, Ciphertext: []byte("test")})
	require.ErrorContains(t, err, context.Canceled.Error())
}
