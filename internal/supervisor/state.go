package supervisor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// State contains operational facts only; credentials and child environment are
// deliberately excluded. It is replaced atomically for independent readers.
type State struct {
	Version             string    `json:"version"`
	SupervisorPID       int       `json:"supervisor_pid"`
	ChildPID            int       `json:"child_pid"`
	Status              string    `json:"status"`
	Bind                string    `json:"bind"`
	Port                int       `json:"port"`
	Mode                string    `json:"mode"`
	StartedAt           time.Time `json:"started_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	ChildStartedAt      time.Time `json:"child_started_at"`
	LastCheckedAt       time.Time `json:"last_checked_at"`
	LastHealthyAt       time.Time `json:"last_healthy_at"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	RestartCount        uint64    `json:"restart_count"`
	LastRestartReason   string    `json:"last_restart_reason,omitempty"`
	LastError           string    `json:"last_error,omitempty"`
	Backoff             string    `json:"backoff"`
}

func WriteState(path string, state State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".status-*")
	if err != nil {
		return fmt.Errorf("create runtime state: %w", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	// Operational state is readable by members of the service group.
	if err := f.Chmod(0640); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func ReadState(path string) (State, error) {
	var state State
	data, err := os.ReadFile(path)
	if err != nil {
		return state, fmt.Errorf("read supervisor runtime state: %w", err)
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, fmt.Errorf("invalid supervisor runtime state")
	}
	return state, nil
}
