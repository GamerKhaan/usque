package supervisor

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"os"
	"os/exec"
	"time"
)

type backoff struct {
	min, max, next time.Duration
	// random supplies a value in [0,1); tests can choose deterministic jitter.
	random func() float64
}

func (b *backoff) delay() time.Duration {
	if b.next == 0 {
		b.next = b.min
	}
	delay := time.Duration(float64(b.next) * (0.8 + 0.4*b.random()))
	if delay > b.max {
		delay = b.max
	}
	if b.next >= b.max/2 {
		b.next = b.max
	} else {
		b.next *= 2
	}
	return delay
}

func (b *backoff) reset() { b.next = b.min }

// Runner owns one child at a time. All state transitions happen in Run's
// goroutine; at most one context-bounded health check is outstanding.
type Runner struct {
	Config  Config
	Version string
	Logger  *log.Logger
	Output  io.Writer
	Probe   func(context.Context) error

	command func() *exec.Cmd
	onState func(State)
	random  func() float64
}

// Run blocks until cancellation or a stop signal, then reaps the child before
// returning. A signal channel preserves SIGINT versus SIGTERM when forwarding.
func (r *Runner) Run(ctx context.Context, signals <-chan os.Signal) error {
	if err := r.Config.Validate(); err != nil {
		return err
	}
	if r.Logger == nil {
		r.Logger = log.Default()
	}
	if r.Output == nil {
		r.Output = os.Stdout
	}
	if r.Probe == nil {
		p := Probe{Address: r.Config.SOCKSAddress(), URL: r.Config.HealthURL, Timeout: r.Config.HealthTimeout}
		r.Probe = func(ctx context.Context) error { _, err := p.Check(ctx); return err }
	}
	if r.command == nil {
		r.command = func() *exec.Cmd { return exec.Command(r.Config.Binary, r.Config.ChildArgs()...) }
	}
	if r.random == nil {
		r.random = rand.Float64
	}
	state := State{
		Version: r.Version, SupervisorPID: os.Getpid(), Status: "starting", StartedAt: time.Now().UTC(),
		Bind: r.Config.Bind, Port: r.Config.Port, Mode: r.Config.Mode,
	}
	if err := WriteState(r.Config.StatePath, state); err != nil {
		return err
	}
	publish := func() {
		state.UpdatedAt = time.Now().UTC()
		if err := WriteState(r.Config.StatePath, state); err != nil {
			r.Logger.Printf("runtime state update failed: %v", err)
		}
		if r.onState != nil {
			r.onState(state)
		}
	}
	defer func() { state.Status = "stopped"; state.ChildPID = 0; publish() }()
	b := backoff{min: r.Config.BackoffMin, max: r.Config.BackoffMax, random: r.random}
	if r.Config.AllowPublic {
		r.Logger.Print("WARNING: public SOCKS listening is enabled; traffic is unauthenticated and unencrypted")
	}
	if r.Config.Mode == "l4-socks" {
		r.Logger.Print("l4-socks is TCP-only and resolves destination names with the host resolver")
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-signals:
			return nil
		default:
		}
		cmd := r.command()
		configureProcess(cmd)
		cmd.Stdout, cmd.Stderr = r.Output, r.Output
		state.Status = "starting"
		state.ConsecutiveFailures = 0
		state.LastError = ""
		state.Backoff = "0s"
		err := cmd.Start()
		if err == nil {
			state.ChildPID = cmd.Process.Pid
			state.ChildStartedAt = time.Now().UTC()
			publish()
			r.Logger.Printf("child started pid=%d mode=%s socks=%s", cmd.Process.Pid, r.Config.Mode, r.Config.SOCKSAddress())
			wait := make(chan error, 1)
			go func() { wait <- cmd.Wait() }()
			reason, stop := r.monitor(ctx, signals, cmd, wait, &state, publish, &b)
			state.ChildPID = 0
			if stop {
				return nil
			}
			state.LastRestartReason = reason
		} else {
			state.LastRestartReason = fmt.Sprintf("child start failed: %v", err)
		}
		state.RestartCount++
		state.Status = "backoff"
		delay := b.delay()
		state.Backoff = delay.String()
		publish()
		r.Logger.Printf("restarting child: %s; restart_count=%d delay=%s", state.LastRestartReason, state.RestartCount, delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-signals:
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func (r *Runner) monitor(ctx context.Context, signals <-chan os.Signal, cmd *exec.Cmd, wait <-chan error, state *State, publish func(), b *backoff) (string, bool) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	var result <-chan error
	var cancel context.CancelFunc
	var healthySince time.Time
	// Cancellation joins the active probe goroutine. The production probe obeys
	// its context throughout SOCKS negotiation, TLS, response headers and body.
	finishProbe := func() {
		if cancel != nil {
			cancel()
			if result != nil {
				<-result
			}
			cancel, result = nil, nil
		}
	}
	defer finishProbe()
	for {
		select {
		case <-ctx.Done():
			finishProbe()
			r.stopChild(cmd, wait, terminationSignal())
			return "", true
		case sig := <-signals:
			finishProbe()
			r.stopChild(cmd, wait, sig)
			return "", true
		case err := <-wait:
			_ = killProcess(cmd)
			if err == nil {
				return "child exited unexpectedly with status 0", false
			}
			return fmt.Sprintf("child exited unexpectedly: %v", err), false
		case <-timer.C:
			probeCtx, probeCancel := context.WithTimeout(ctx, r.Config.HealthTimeout)
			cancel = probeCancel
			ch := make(chan error, 1)
			result = ch
			go func() { ch <- r.Probe(probeCtx) }()
		case err := <-result:
			cancel()
			cancel, result = nil, nil
			state.LastCheckedAt = time.Now().UTC()
			if err != nil {
				healthySince = time.Time{}
				state.ConsecutiveFailures++
				state.LastError = err.Error()
				state.Status = "unhealthy"
				r.Logger.Printf("health check failed (%d/%d): %v", state.ConsecutiveFailures, r.Config.HealthFailures, err)
				publish()
				if state.ConsecutiveFailures >= r.Config.HealthFailures {
					r.stopChild(cmd, wait, terminationSignal())
					return fmt.Sprintf("%d consecutive end-to-end health failures: %v", state.ConsecutiveFailures, err), false
				}
			} else {
				state.LastHealthyAt = state.LastCheckedAt
				if healthySince.IsZero() {
					healthySince = state.LastCheckedAt
				}
				if state.LastCheckedAt.Sub(healthySince) >= r.Config.HealthyReset {
					b.reset()
				}
				if state.Status != "healthy" {
					r.Logger.Print("end-to-end SOCKS HTTPS/WARP health restored")
				}
				state.Status, state.LastError = "healthy", ""
				state.ConsecutiveFailures = 0
				publish()
			}
			timer.Reset(r.Config.HealthInterval)
		}
	}
}

func (r *Runner) stopChild(cmd *exec.Cmd, wait <-chan error, sig os.Signal) {
	r.Logger.Printf("stopping child pid=%d signal=%s", cmd.Process.Pid, sig)
	if err := signalProcess(cmd, sig); err != nil {
		r.Logger.Printf("child signal result: %v", err)
	}
	timer := time.NewTimer(r.Config.ShutdownTimeout)
	defer timer.Stop()
	select {
	case <-wait:
	case <-timer.C:
		r.Logger.Printf("child shutdown deadline exceeded; killing process group pid=%d", cmd.Process.Pid)
		_ = killProcess(cmd)
		<-wait
	}
	_ = killProcess(cmd)
}
