//go:build !windows

package supervisor

import (
	"os"
	"os/exec"
	"syscall"
)

func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminationSignal() os.Signal { return syscall.SIGTERM }

func signalProcess(cmd *exec.Cmd, sig os.Signal) error {
	unixSignal, ok := sig.(syscall.Signal)
	if !ok {
		unixSignal = syscall.SIGTERM
	}
	return syscall.Kill(-cmd.Process.Pid, unixSignal)
}

// Kill the process group even after its leader has exited, so subprocesses do
// not survive an unexpected child exit or a graceful shutdown of the leader.
func killProcess(cmd *exec.Cmd) error {
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
