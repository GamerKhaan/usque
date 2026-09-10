package cmd

import (
	"strings"
	"testing"

	"github.com/Diniboy1123/usque/config"
	"github.com/spf13/cobra"
)

func TestSOCKSCommandsFailWithoutConfig(t *testing.T) {
	oldLoaded := config.ConfigLoaded
	config.ConfigLoaded = false
	t.Cleanup(func() { config.ConfigLoaded = oldLoaded })
	for _, command := range []*cobra.Command{socksCmd, l4SocksCmd} {
		t.Run(command.Name(), func(t *testing.T) {
			if command.RunE == nil {
				t.Fatal("command does not return startup failures")
			}
			if err := command.RunE(command, nil); err == nil || !strings.Contains(err.Error(), "config not loaded") {
				t.Fatalf("missing config error=%v", err)
			}
		})
	}
}

func TestSOCKSCommandsRejectNonPositiveDialTimeout(t *testing.T) {
	oldLoaded := config.ConfigLoaded
	config.ConfigLoaded = true
	t.Cleanup(func() { config.ConfigLoaded = oldLoaded })
	for _, command := range []*cobra.Command{socksCmd, l4SocksCmd} {
		t.Run(command.Name(), func(t *testing.T) {
			flag := command.Flags().Lookup("dial-timeout")
			previous := flag.Value.String()
			t.Cleanup(func() { _ = flag.Value.Set(previous) })
			if err := flag.Value.Set("0s"); err != nil {
				t.Fatal(err)
			}
			if err := command.RunE(command, nil); err == nil || !strings.Contains(err.Error(), "dial-timeout must be positive") {
				t.Fatalf("invalid timeout error=%v", err)
			}
		})
	}
}
