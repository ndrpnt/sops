package pluginsdk_test

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/getsops/sops/v3/plugin"
	sdk "github.com/getsops/sops/v3/pluginsdk"
	"github.com/stretchr/testify/require"
)

// Use the test executable as a real SDK plugin.
func TestMain(m *testing.M) {
	if os.Getenv("SOPS_SDK_TEST_PROCESS") == "host" {
		_ = os.Setenv("SOPS_SDK_TEST_PROCESS", "1")
		key, err := plugin.NewMasterKey("sdktest", map[string]any{
			"mode": "wait", "ready": os.Getenv("SOPS_SDK_TEST_READY"),
		})
		if err == nil {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			err = key.EncryptContext(ctx, nil)
			wasCanceled := ctx.Err() != nil
			stop()
			if wasCanceled && err != nil {
				os.Exit(0)
			}
		}
		os.Exit(1)
	}
	if os.Getenv("SOPS_SDK_TEST_PROCESS") == "1" {
		runner := sdk.Runner[testConfig]{
			Plugin: testPlugin{},
		}
		os.Exit(runner.Run())
	}
	os.Exit(m.Run())
}

type testConfig struct {
	Mode  string `json:"mode"`
	Ready string `json:"ready"`
}

type testPlugin struct{}

func (testPlugin) Wrap(ctx context.Context, req sdk.EncryptRequest[testConfig]) (*sdk.EncryptResponse, error) {
	if req.Configuration.Mode == "wait" || req.Configuration.Mode == "ignore" {
		if err := os.WriteFile(req.Configuration.Ready, nil, 0o600); err != nil {
			return nil, err
		}
		if req.Configuration.Mode == "ignore" {
			for {
				time.Sleep(time.Hour)
			}
		}
		<-ctx.Done()
		if err := os.WriteFile(req.Configuration.Ready+".canceled", nil, 0o600); err != nil {
			return nil, err
		}
		return nil, ctx.Err()
	}
	cwd, err := os.Getwd()
	return &sdk.EncryptResponse{Ciphertext: []byte(cwd)}, err
}

func (testPlugin) Unwrap(ctx context.Context, req sdk.DecryptRequest[testConfig]) (*sdk.DecryptResponse, error) {
	return &sdk.DecryptResponse{Plaintext: req.Ciphertext}, nil
}

func testKey(t *testing.T, config map[string]any) *plugin.MasterKey {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	t.Setenv("SOPS_SDK_TEST_PROCESS", "1")
	t.Setenv("SOPS_PLUGIN_KMS_SDKTEST_EXEC", exe)
	key, err := plugin.NewMasterKey("sdktest", config)
	require.NoError(t, err)
	return key
}

func TestWorkingDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	cwd, err := os.Getwd()
	require.NoError(t, err)
	key := testKey(t, map[string]any{})
	require.NoError(t, key.Encrypt([]byte("test")))
	require.Equal(t, cwd, string(key.EncryptedDataKey()))
	plaintext, err := key.Decrypt()
	require.NoError(t, err)
	require.Equal(t, cwd, string(plaintext))
}

func TestCancellation(t *testing.T) {
	for _, mode := range []string{"wait", "ignore"} {
		t.Run(mode, func(t *testing.T) {
			ready := filepath.Join(t.TempDir(), "ready")
			key := testKey(t, map[string]any{"mode": mode, "ready": ready})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- key.EncryptContext(ctx, []byte("test")) }()
			require.Eventually(t, func() bool {
				_, err := os.Stat(ready)
				return err == nil
			}, 10*time.Second, 10*time.Millisecond)
			cancel()
			select {
			case err := <-done:
				require.Error(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("plugin did not stop after cancellation")
			}
			if mode == "wait" && runtime.GOOS != "windows" {
				_, err := os.Stat(ready + ".canceled")
				require.NoError(t, err, "SDK must cancel the operation before exit")
			}
		})
	}
}

func TestHostSignals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process signals are not supported on Windows")
	}
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			ready := filepath.Join(t.TempDir(), "ready")
			_ = testKey(t, map[string]any{})
			t.Setenv("SOPS_SDK_TEST_PROCESS", "host")
			t.Setenv("SOPS_SDK_TEST_READY", ready)
			exe, err := os.Executable()
			require.NoError(t, err)
			cmd := exec.CommandContext(t.Context(), exe)
			require.NoError(t, cmd.Start())
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			require.Eventually(t, func() bool {
				_, err := os.Stat(ready)
				return err == nil
			}, 10*time.Second, 10*time.Millisecond)
			require.NoError(t, cmd.Process.Signal(sig))
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("host did not stop after signal")
			}
			_, err = os.Stat(ready + ".canceled")
			require.NoError(t, err)
		})
	}
}
