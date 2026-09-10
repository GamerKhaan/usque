package supervisor

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("USQUE_TEST_CHILD") != "1" {
		return
	}
	if os.Getenv("USQUE_TEST_MODE") == "exit" {
		os.Exit(23)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, terminationSignal())
	if os.Getenv("USQUE_TEST_MODE") == "ignore" {
		signal.Ignore(os.Interrupt, terminationSignal())
	}
	if marker := os.Getenv("USQUE_TEST_READY"); marker != "" {
		_ = os.WriteFile(marker, []byte("ready"), 0600)
	}
	if descendant := os.Getenv("USQUE_TEST_DESCENDANT"); descendant != "" {
		child := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		child.Env = []string{"USQUE_TEST_CHILD=1"}
		if err := child.Start(); err != nil {
			os.Exit(24)
		}
		if err := os.WriteFile(descendant, []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
			os.Exit(25)
		}
		go func() { _ = child.Wait() }()
	}
	sig := <-signals
	if marker := os.Getenv("USQUE_TEST_SIGNAL"); marker != "" {
		_ = os.WriteFile(marker, []byte(sig.String()), 0600)
	}
	os.Exit(0)
}

func helperCommand(mode string, extra ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), "USQUE_TEST_CHILD=1", "USQUE_TEST_MODE="+mode)
	cmd.Env = append(cmd.Env, extra...)
	return cmd
}

func testConfig(t *testing.T) Config {
	t.Helper()
	c, err := FromEnvironment(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	c.StatePath = filepath.Join(t.TempDir(), "status.json")
	c.HealthInterval = 15 * time.Millisecond
	c.HealthTimeout = 100 * time.Millisecond
	c.ShutdownTimeout = 150 * time.Millisecond
	c.BackoffMin = 40 * time.Millisecond
	c.BackoffMax = 160 * time.Millisecond
	c.HealthyReset = 70 * time.Millisecond
	return c
}

type runningTest struct {
	states  chan State
	stop    context.CancelFunc
	done    chan error
	signals chan os.Signal
}

func runTestSupervisor(t *testing.T, runner Runner) *runningTest {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	test := &runningTest{states: make(chan State, 1000), stop: cancel, done: make(chan error, 1), signals: make(chan os.Signal, 1)}
	runner.Logger = log.New(io.Discard, "", 0)
	runner.Output = io.Discard
	runner.random = func() float64 { return 0.5 }
	runner.onState = func(s State) { test.states <- s }
	go func() { test.done <- runner.Run(ctx, test.signals) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-test.done:
			if err != nil {
				t.Errorf("supervisor failed: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("supervisor did not stop and reap child")
		}
	})
	return test
}

func awaitState(t *testing.T, run *runningTest, predicate func(State) bool) State {
	t.Helper()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case state := <-run.states:
			if predicate(state) {
				return state
			}
		case <-timeout.C:
			t.Fatal("timed out waiting for supervisor state")
		}
	}
}

func TestChildStartsAndStopsCleanly(t *testing.T) {
	c := testConfig(t)
	run := runTestSupervisor(t, Runner{Config: c, command: func() *exec.Cmd { return helperCommand("sleep") }, Probe: func(context.Context) error { return nil }})
	state := awaitState(t, run, func(s State) bool { return s.Status == "healthy" })
	if state.ChildPID <= 0 || state.RestartCount != 0 {
		t.Fatalf("unexpected state: %+v", state)
	}
	run.stop()
	awaitState(t, run, func(s State) bool { return s.Status == "stopped" })
	persisted, err := ReadState(c.StatePath)
	if err != nil || persisted.ChildPID != 0 || persisted.Status != "stopped" {
		t.Fatalf("state after cleanup: %+v %v", persisted, err)
	}
}

func TestUnexpectedChildExitRestartsWithIncreasingBackoff(t *testing.T) {
	c := testConfig(t)
	run := runTestSupervisor(t, Runner{Config: c, command: func() *exec.Cmd { return helperCommand("exit") }, Probe: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }})
	var delays []time.Duration
	started := time.Now()
	for count := uint64(1); count <= 3; count++ {
		state := awaitState(t, run, func(s State) bool { return s.Status == "backoff" && s.RestartCount == count })
		delay, err := time.ParseDuration(state.Backoff)
		if err != nil {
			t.Fatal(err)
		}
		delays = append(delays, delay)
	}
	if delays[0] != c.BackoffMin || delays[1] != 2*c.BackoffMin || delays[2] != c.BackoffMax {
		t.Fatalf("backoff did not grow: %v", delays)
	}
	if time.Since(started) < 3*c.BackoffMin {
		t.Fatal("rapid restart spin")
	}
	awaitState(t, run, func(s State) bool { return s.ChildPID > 0 && s.RestartCount == 3 })
}

func TestSingleTemporaryFailureDoesNotRestart(t *testing.T) {
	c := testConfig(t)
	var probes atomic.Int32
	run := runTestSupervisor(t, Runner{Config: c, command: func() *exec.Cmd { return helperCommand("sleep") }, Probe: func(context.Context) error {
		if probes.Add(1) == 2 {
			return errors.New("temporary interruption")
		}
		return nil
	}})
	initial := awaitState(t, run, func(s State) bool { return s.Status == "unhealthy" })
	recovered := awaitState(t, run, func(s State) bool { return s.Status == "healthy" })
	if initial.ConsecutiveFailures != 1 || recovered.RestartCount != 0 || recovered.ChildPID != initial.ChildPID || recovered.ConsecutiveFailures != 0 {
		t.Fatalf("temporary failure restarted child: %+v", recovered)
	}
}

func TestConsecutiveFailuresRestartLiveChild(t *testing.T) {
	c := testConfig(t)
	var probes atomic.Int32
	run := runTestSupervisor(t, Runner{Config: c, command: func() *exec.Cmd { return helperCommand("sleep") }, Probe: func(context.Context) error {
		probes.Add(1)
		return errors.New("HTTPS data path failed")
	}})
	first := awaitState(t, run, func(s State) bool { return s.ChildPID > 0 })
	failed := awaitState(t, run, func(s State) bool { return s.Status == "backoff" })
	if failed.ConsecutiveFailures != c.HealthFailures || probes.Load() != int32(c.HealthFailures) {
		t.Fatalf("wrong threshold: %+v probes=%d", failed, probes.Load())
	}
	second := awaitState(t, run, func(s State) bool { return s.ChildPID > 0 && s.RestartCount == 1 })
	if second.ChildPID == first.ChildPID {
		t.Fatal("unhealthy child was not replaced")
	}
}

func TestHungProbeUsesTimeoutAndRestarts(t *testing.T) {
	c := testConfig(t)
	c.HealthFailures = 1
	var active atomic.Int32
	run := runTestSupervisor(t, Runner{Config: c, command: func() *exec.Cmd { return helperCommand("sleep") }, Probe: func(ctx context.Context) error {
		active.Add(1)
		defer active.Add(-1)
		<-ctx.Done()
		return ctx.Err()
	}})
	awaitState(t, run, func(s State) bool { return s.Status == "backoff" })
	if active.Load() != 0 {
		t.Fatal("probe goroutine survived restart")
	}
	awaitState(t, run, func(s State) bool { return s.RestartCount == 1 && s.ChildPID > 0 })
	run.stop()
	awaitState(t, run, func(s State) bool { return s.Status == "stopped" })
	if active.Load() != 0 {
		t.Fatal("probe goroutine survived shutdown")
	}
}

func TestBackoffResetsOnlyAfterSustainedHealth(t *testing.T) {
	c := testConfig(t)
	c.HealthFailures = 1
	var probes atomic.Int32
	run := runTestSupervisor(t, Runner{Config: c, command: func() *exec.Cmd { return helperCommand("sleep") }, Probe: func(context.Context) error {
		n := probes.Add(1)
		if n <= 2 || n == 12 {
			return errors.New("interruption")
		}
		return nil
	}})
	first := awaitState(t, run, func(s State) bool { return s.Status == "backoff" && s.RestartCount == 1 })
	second := awaitState(t, run, func(s State) bool { return s.Status == "backoff" && s.RestartCount == 2 })
	third := awaitState(t, run, func(s State) bool { return s.Status == "backoff" && s.RestartCount == 3 })
	if first.Backoff != c.BackoffMin.String() || second.Backoff != (2*c.BackoffMin).String() || third.Backoff != c.BackoffMin.String() {
		t.Fatalf("reset policy: %s, %s, %s", first.Backoff, second.Backoff, third.Backoff)
	}
}

func TestBriefHealthDoesNotResetBackoff(t *testing.T) {
	c := testConfig(t)
	c.HealthFailures = 1
	var probes atomic.Int32
	run := runTestSupervisor(t, Runner{Config: c, command: func() *exec.Cmd { return helperCommand("sleep") }, Probe: func(context.Context) error {
		if probes.Add(1)%2 == 0 {
			return nil
		}
		return errors.New("interruption")
	}})
	awaitState(t, run, func(s State) bool { return s.Status == "backoff" && s.RestartCount == 1 })
	second := awaitState(t, run, func(s State) bool { return s.Status == "backoff" && s.RestartCount == 2 })
	if second.Backoff != (2 * c.BackoffMin).String() {
		t.Fatalf("brief health incorrectly reset backoff: %s", second.Backoff)
	}
}

func TestBackoffJitterAndCap(t *testing.T) {
	for _, random := range []float64{0, 0.5, 0.999} {
		b := backoff{min: time.Second, max: 30 * time.Second, random: func() float64 { return random }}
		for range 100 {
			d := b.delay()
			if d < 800*time.Millisecond || d > 30*time.Second {
				t.Fatalf("jitter out of bounds: %s", d)
			}
		}
		b.reset()
		if d := b.delay(); d > 1200*time.Millisecond {
			t.Fatalf("reset failed: %s", d)
		}
	}
}

func TestStartFailureIsRateLimited(t *testing.T) {
	c := testConfig(t)
	missing := filepath.Join(t.TempDir(), "missing")
	run := runTestSupervisor(t, Runner{Config: c, command: func() *exec.Cmd { return exec.Command(missing) }})
	awaitState(t, run, func(s State) bool { return s.RestartCount == 1 })
	state := awaitState(t, run, func(s State) bool { return s.RestartCount == 2 })
	if state.ChildPID != 0 || state.Backoff != (2*c.BackoffMin).String() {
		t.Fatalf("bad start failure state: %+v", state)
	}
}
