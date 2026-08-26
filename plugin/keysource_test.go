package plugin

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

// TestCallPluginHelper is skipped unless GO_WANT_HELPER_PROCESS env var is set.
// os.Exit must be called to bypass go test pretty printing.
func TestCallPluginHelper(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	// In the plugin helper, arguments are offsetted by "-test.run=..." and "--".
	arg1 := os.Args[3]
	arg2 := os.Args[4]
	if arg1 != "-c" {
		fmt.Fprintf(os.Stderr, "bad first argument: %s\n", arg1)
		os.Exit(1)
	}
	switch arg2 {
	case "encrypt":
		if err := encrypt(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "decrypt":
		if err := decrypt(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "bad second argument: %s\n", arg2)
		os.Exit(1)
	}
	os.Exit(0)
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

func TestMasterKey_DecryptContext(t *testing.T) {
	masterKey, err := NewMasterKey("plugin_name", map[string]any{
		"suffix": "ouiiiiii",
	})
	assert.NoError(t, err)

	masterKey.execCommand = func(name string, arg ...string) *exec.Cmd {
		assert.Equal(t, "plugin_name", name)
		cmd := exec.Command(
			os.Args[0],
			append([]string{"-test.run=TestCallPluginHelper", "--"}, arg...)...,
		)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
		return cmd
	}

	err = masterKey.EncryptContext(t.Context(), []byte("my_key"))
	assert.NoError(t, err)
	assert.Equal(t, []byte("my_keyouiiiiii"), masterKey.encryptedKey)

	dataKey, err := masterKey.DecryptContext(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, []byte("my_key"), dataKey)
}
