package plugin

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestMain(m *testing.M) {
	if os.Getenv(pluginEnvKey) == "1" {
		if err := mockPlugin(); err != nil {
			fmt.Fprintf(os.Stderr, "mock-plugin: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestMasterKey_DecryptContext(t *testing.T) {
	require.NoError(t, os.Setenv("SOPS_PLUGIN_KMS_DUMMY_EXEC", os.Args[0]))
	masterKey, err := NewMasterKey(
		"dummy",
		map[string]any{"suffix": "ouiiiiii"},
	)
	require.NoError(t, err)

	err = masterKey.EncryptContext(t.Context(), []byte("my_key"))
	require.NoError(t, err)
	require.Equal(t, []byte("my_keyouiiiiii"), masterKey.encryptedKey)

	dataKey, err := masterKey.DecryptContext(t.Context())
	require.NoError(t, err)
	require.Equal(t, []byte("my_key"), dataKey)
}

func mockPlugin() error {
	if argc := len(os.Args); argc != 3 {
		return fmt.Errorf("invalid argument count: %d\n", argc)
	}
	arg1, arg2 := os.Args[1], os.Args[2]
	if arg1 != "-c" {
		return fmt.Errorf("invalid first argument: %s\n", arg1)
	}
	switch arg2 {
	case "encrypt":
		if err := encrypt(); err != nil {
			return fmt.Errorf("encrypt failed: %v\n", err)
		}
	case "decrypt":
		if err := decrypt(); err != nil {
			return fmt.Errorf("decrypt failed: %v\n", err)
		}
	default:
		return fmt.Errorf("invalid second argument: %s\n", arg2)
	}
	return nil
}

func encrypt() error {
	protoReq, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	req := &EncryptRequest{}
	err = proto.Unmarshal(protoReq, req)
	if err != nil {
		return fmt.Errorf("failed to unmarshal EncryptRequest: %v", err)
	}

	respEncryptStr := string(req.Plaintext) + req.Configuration.AsMap()["suffix"].(string)
	resp := &EncryptResponse{Ciphertext: []byte(respEncryptStr)}
	protoResp, err := proto.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal EncryptResponse: %v", err)
	}

	if _, err := os.Stdout.Write(protoResp); err != nil {
		return fmt.Errorf("failed to write to stdout: %w", err)
	}

	return nil
}

func decrypt() error {
	protoReq, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	req := &DecryptRequest{}
	err = proto.Unmarshal(protoReq, req)
	if err != nil {
		return fmt.Errorf("failed to unmarshal DecryptRequest: %v", err)
	}

	respDecrypted := strings.TrimSuffix(string(req.Ciphertext), req.Configuration.AsMap()["suffix"].(string))
	resp := &DecryptResponse{Plaintext: []byte(respDecrypted)}
	protoResp, err := proto.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal DecryptResponse: %v", err)
	}

	if _, err := os.Stdout.Write(protoResp); err != nil {
		return fmt.Errorf("fail to write to stdout: %w", err)
	}

	return nil
}
