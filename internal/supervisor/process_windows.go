//go:build windows

package supervisor

import (
	"os"
	"os/exec"
)

func configureProcess(_ *exec.Cmd) {}
func terminationSignal() os.Signal { return os.Interrupt }

// Production runs on Linux. Go does not support forwarding console signals to
// arbitrary child processes on Windows; portable lifecycle tests use Kill.
func signalProcess(cmd *exec.Cmd, _ os.Signal) error { return cmd.Process.Kill() }
func killProcess(cmd *exec.Cmd) error                { return cmd.Process.Kill() }
