package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
)

var l4SocksCmd = &cobra.Command{
	Use:   "l4-socks",
	Short: "Expose Warp as an L4 TCP-only SOCKS5 proxy",
	Long:  "TCP-only SOCKS5 proxy using direct HTTP/3 CONNECT streams. Doesn't require elevated privileges.",
	RunE: func(cmd *cobra.Command, args []string) error {
		dialTimeout, err := cmd.Flags().GetDuration("dial-timeout")
		if err != nil {
			return fmt.Errorf("get dial timeout: %w", err)
		}
		if dialTimeout <= 0 {
			return fmt.Errorf("dial-timeout must be positive")
		}
		opts, proxy, err := buildL4Proxy(cmd, "l4-socks")
		if err != nil {
			return err
		}

		addr := net.JoinHostPort(opts.bind, opts.port)
		server, err := internal.NewSOCKS5Server(internal.SOCKS5Config{
			Addr:     addr,
			Username: opts.username,
			Password: opts.password,
			DialTCP: func(ctx context.Context, network, address string) (net.Conn, error) {
				return proxy.DialContext(ctx, address)
			},
			TCPOnly:     true,
			DialTimeout: dialTimeout,
			Logger:      log.Default(),
		})
		if err != nil {
			return fmt.Errorf("failed to create SOCKS proxy: %w", err)
		}

		log.Printf("L4 SOCKS proxy listening on %s", addr)
		if err := server.Start(); err != nil {
			return fmt.Errorf("failed to start SOCKS proxy: %w", err)
		}
		return nil
	},
}

func init() {
	addL4ProxyFlags(l4SocksCmd, "1080", "SOCKS")
	l4SocksCmd.Flags().Duration("dial-timeout", 15*time.Second, "Maximum time for SOCKS DNS resolution and connection establishment")
	rootCmd.AddCommand(l4SocksCmd)
}
