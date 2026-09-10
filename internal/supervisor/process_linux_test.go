//go:build linux

package supervisor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func awaitFile(t *testing.T, path string) string {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return string(data)
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", path)
		case <-ticker.C:
		}
	}
}

func TestTerminationSignalsPropagateAndChildIsReaped(t *testing.T) {
	for _, sig := range []os.Signal{syscall.SIGTERM, os.Interrupt} {
		t.Run(sig.String(), func(t *testing.T) {
			c := testConfig(t)
			ready, received := filepath.Join(t.TempDir(), "ready"), filepath.Join(t.TempDir(), "signal")
			run := runTestSupervisor(t, Runner{Config: c, command: func() *exec.Cmd {
				return helperCommand("sleep", "USQUE_TEST_READY="+ready, "USQUE_TEST_SIGNAL="+received)
			}, Probe: func(context.Context) error { return nil }})
			first := awaitState(t, run, func(s State) bool { return s.ChildPID > 0 })
			awaitFile(t, ready)
			run.signals <- sig
			awaitState(t, run, func(s State) bool { return s.Status == "stopped" })
			if got := awaitFile(t, received); got != sig.String() {
				t.Fatalf("wanted signal %s, got %s", sig, got)
			}
			if err := syscall.Kill(first.ChildPID, 0); err == nil {
				t.Fatalf("child %d was not reaped", first.ChildPID)
			}
		})
	}
}

func TestShutdownTimeoutBeforeForceKill(t *testing.T) {
	c := testConfig(t)
	ready := filepath.Join(t.TempDir(), "ready")
	run := runTestSupervisor(t, Runner{Config: c, command: func() *exec.Cmd { return helperCommand("ignore", "USQUE_TEST_READY="+ready) }, Probe: func(context.Context) error { return nil }})
	first := awaitState(t, run, func(s State) bool { return s.ChildPID > 0 })
	awaitFile(t, ready)
	started := time.Now()
	run.signals <- syscall.SIGTERM
	awaitState(t, run, func(s State) bool { return s.Status == "stopped" })
	if elapsed := time.Since(started); elapsed < c.ShutdownTimeout || elapsed > 2*time.Second {
		t.Fatalf("shutdown timeout not respected: %s", elapsed)
	}
	if err := syscall.Kill(first.ChildPID, 0); err == nil {
		t.Fatalf("forced child %d survived", first.ChildPID)
	}
}

func TestProcessGroupCleanupDoesNotLeaveDescendantsRunning(t *testing.T) {
	c := testConfig(t)
	descendantPath := filepath.Join(t.TempDir(), "descendant")
	run := runTestSupervisor(t, Runner{Config: c, command: func() *exec.Cmd { return helperCommand("sleep", "USQUE_TEST_DESCENDANT="+descendantPath) }, Probe: func(context.Context) error { return nil }})
	descendant, err := strconv.Atoi(awaitFile(t, descendantPath))
	if err != nil {
		t.Fatal(err)
	}
	run.stop()
	awaitState(t, run, func(s State) bool { return s.Status == "stopped" })
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile("/proc/" + strconv.Itoa(descendant) + "/stat")
		if os.IsNotExist(err) {
			return
		}
		// An orphaned descendant can briefly remain a zombie until init reaps it.
		if err == nil {
			_, tail, ok := strings.Cut(string(data), ") ")
			if ok && strings.HasPrefix(tail, "Z ") {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("descendant %d still running after supervisor stopped", descendant)
}
