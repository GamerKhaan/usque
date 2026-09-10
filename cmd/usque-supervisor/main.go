// usque-supervisor runs the production proxy and verifies its WARP data path.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal/supervisor"
)

var version = "dev"
var commit = "unknown"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if err := execute(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func execute(args []string) error {
	command := "run"
	if len(args) > 0 {
		command = args[0]
	}
	if command == "version" {
		fmt.Printf("usque-supervisor %s (%s)\n", version, commit)
		return nil
	}
	if command == "help" || command == "--help" || command == "-h" {
		fmt.Println("Usage: usque-supervisor [run|health|status|validate-config [path]|version]")
		fmt.Println("Service settings come from USQUE_* environment variables; see /etc/usque/service.env.")
		return nil
	}
	if command == "validate-config" {
		path := os.Getenv("USQUE_CONFIG")
		if path == "" {
			path = "/etc/usque/config.json"
		}
		if len(args) > 2 {
			return fmt.Errorf("usage: usque-supervisor validate-config [path]")
		}
		if len(args) == 2 {
			path = args[1]
		}
		cfg, err := config.ReadConfig(path)
		if err != nil {
			return err
		}
		if err := cfg.Validate(); err != nil {
			return err
		}
		fmt.Println("Configuration structure and key material: valid")
		return nil
	}
	if len(args) > 1 {
		return fmt.Errorf("unexpected arguments; use usque-supervisor --help")
	}
	cfg, err := supervisor.FromEnvironment(os.Getenv)
	if err != nil {
		return err
	}
	switch command {
	case "run":
		signals := make(chan os.Signal, 2)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(signals)
		runner := supervisor.Runner{Config: cfg, Version: version}
		return runner.Run(context.Background(), signals)
	case "health":
		probe := supervisor.Probe{Address: cfg.SOCKSAddress(), URL: cfg.HealthURL, Timeout: cfg.HealthTimeout}
		result, err := probe.Check(context.Background())
		if err != nil {
			return err
		}
		fmt.Printf("Status: healthy\nSOCKS5: %s\nWARP: %s\nHTTPS latency: %s\n", cfg.SOCKSAddress(), result.WARP, result.Latency)
		return nil
	case "status":
		state, err := supervisor.ReadState(cfg.StatePath)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(state)
	default:
		return fmt.Errorf("unknown command; use usque-supervisor --help")
	}
}
