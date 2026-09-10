package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var socksCmd = &cobra.Command{
	SilenceUsage:  true,
	SilenceErrors: true,
	Use:           "socks",
	Short:         "Expose Warp as a SOCKS5 proxy",
	Long:          "Dual-stack SOCKS5 proxy with optional authentication. Doesn't require elevated privileges.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !config.ConfigLoaded {
			return fmt.Errorf("config not loaded: please register first")
		}
		log.Println("Hint: l4-socks is faster for TCP-only SOCKS use cases.")
		dialTimeout, err := cmd.Flags().GetDuration("dial-timeout")
		if err != nil {
			return fmt.Errorf("get dial timeout: %w", err)
		}
		if dialTimeout <= 0 {
			return fmt.Errorf("dial-timeout must be positive")
		}

		sni, err := cmd.Flags().GetString("sni-address")
		if err != nil {
			return fmt.Errorf("failed to get SNI address: %w", err)
		}

		privKey, err := config.AppConfig.GetEcPrivateKey()
		if err != nil {
			return fmt.Errorf("failed to get private key: %w", err)
		}
		peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
		if err != nil {
			return fmt.Errorf("failed to get public key: %w", err)
		}

		cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to generate cert: %w", err)
		}

		insecure, err := cmd.Flags().GetBool("insecure")
		if err != nil {
			return fmt.Errorf("failed to get insecure flag: %w", err)
		}

		tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni, insecure)
		if err != nil {
			return fmt.Errorf("failed to prepare TLS config: %w", err)
		}

		keepalivePeriod, err := cmd.Flags().GetDuration("keepalive-period")
		if err != nil {
			return fmt.Errorf("failed to get keepalive period: %w", err)
		}
		initialPacketSize, err := cmd.Flags().GetUint16("initial-packet-size")
		if err != nil {
			return fmt.Errorf("failed to get initial packet size: %w", err)
		}

		bindAddress, err := cmd.Flags().GetString("bind")
		if err != nil {
			return fmt.Errorf("failed to get bind address: %w", err)
		}

		port, err := cmd.Flags().GetString("port")
		if err != nil {
			return fmt.Errorf("failed to get port: %w", err)
		}

		connectPort, err := cmd.Flags().GetInt("connect-port")
		if err != nil {
			return fmt.Errorf("failed to get connect port: %w", err)
		}

		useHTTP2, err := cmd.Flags().GetBool("http2")
		if err != nil {
			return fmt.Errorf("failed to get HTTP/2 flag: %w", err)
		}

		useIPv6, err := cmd.Flags().GetBool("ipv6")
		if err != nil {
			return fmt.Errorf("failed to get ipv6 flag: %w", err)
		}

		endpoint, err := config.SelectEndpointFromConfig(useHTTP2, useIPv6, connectPort)
		if err != nil {
			return fmt.Errorf("failed to select endpoint: %w", err)
		}

		if insecure {
			config.WarnInsecure()
		}

		if useHTTP2 {
			config.LogHTTP2Endpoint(endpoint)
		}

		tunnelIPv4, err := cmd.Flags().GetBool("no-tunnel-ipv4")
		if err != nil {
			return fmt.Errorf("failed to get no tunnel IPv4: %w", err)
		}

		tunnelIPv6, err := cmd.Flags().GetBool("no-tunnel-ipv6")
		if err != nil {
			return fmt.Errorf("failed to get no tunnel IPv6: %w", err)
		}

		var localAddresses []netip.Addr
		if !tunnelIPv4 {
			v4, err := netip.ParseAddr(config.AppConfig.IPv4)
			if err != nil {
				return fmt.Errorf("failed to parse IPv4 address: %w", err)
			}
			localAddresses = append(localAddresses, v4)
		}
		if !tunnelIPv6 {
			v6, err := netip.ParseAddr(config.AppConfig.IPv6)
			if err != nil {
				return fmt.Errorf("failed to parse IPv6 address: %w", err)
			}
			localAddresses = append(localAddresses, v6)
		}

		dnsServers, err := cmd.Flags().GetStringArray("dns")
		if err != nil {
			return fmt.Errorf("failed to get DNS servers: %w", err)
		}

		var dnsAddrs []netip.Addr
		for _, dns := range dnsServers {
			addr, err := netip.ParseAddr(dns)
			if err != nil {
				return fmt.Errorf("failed to parse DNS server: %w", err)
			}
			dnsAddrs = append(dnsAddrs, addr)
		}

		var dnsTimeout time.Duration
		if dnsTimeout, err = cmd.Flags().GetDuration("dns-timeout"); err != nil {
			return fmt.Errorf("failed to get DNS timeout: %w", err)
		}

		localDNS, err := cmd.Flags().GetBool("local-dns")
		if err != nil {
			return fmt.Errorf("failed to get local-dns flag: %w", err)
		}

		systemDNS, err := cmd.Flags().GetBool("system-dns")
		if err != nil {
			return fmt.Errorf("failed to get system-dns flag: %w", err)
		}
		if systemDNS && !localDNS {
			log.Println("Warning: --system-dns only applies with -l; ignoring")
			systemDNS = false
		}

		mtu, err := cmd.Flags().GetInt("mtu")
		if err != nil {
			return fmt.Errorf("failed to get MTU: %w", err)
		}
		if mtu != 1280 {
			log.Println("Warning: MTU is not the default 1280. This is not supported. Packet loss and other issues may occur.")
		}

		var username string
		var password string
		if u, err := cmd.Flags().GetString("username"); err == nil && u != "" {
			username = u
		}
		if p, err := cmd.Flags().GetString("password"); err == nil && p != "" {
			password = p
		}

		reconnectDelay, err := cmd.Flags().GetDuration("reconnect-delay")
		if err != nil {
			return fmt.Errorf("failed to get reconnect delay: %w", err)
		}

		udpTimeout, err := cmd.Flags().GetDuration("udp-timeout")
		if err != nil {
			return fmt.Errorf("failed to get UDP timeout: %w", err)
		}
		if udpTimeout <= 0 {
			log.Println("Warning: --udp-timeout is 0; idle UDP ASSOCIATE exchanges will never expire. Memory will grow under heavy UDP traffic (DHT, uTP, etc.).")
		}

		alwaysReconnect, err := cmd.Flags().GetBool("always-reconnect")
		if err != nil {
			return fmt.Errorf("failed to get always-reconnect flag: %w", err)
		}

		onConnect, err := cmd.Flags().GetString("on-connect")
		if err != nil {
			return fmt.Errorf("failed to get on-connect flag: %w", err)
		}

		onDisconnect, err := cmd.Flags().GetString("on-disconnect")
		if err != nil {
			return fmt.Errorf("failed to get on-disconnect flag: %w", err)
		}

		hookEnv := map[string]string{
			"USQUE_MODE": "socks",
			"USQUE_IPV4": config.AppConfig.IPv4,
			"USQUE_IPV6": config.AppConfig.IPv6,
		}

		tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, mtu)
		if err != nil {
			return fmt.Errorf("failed to create virtual TUN device: %w", err)
		}
		defer func() { _ = tunDev.Close() }()

		tunnelCtx, cancelTunnel := context.WithCancel(cmd.Context())
		defer cancelTunnel()
		go api.MaintainTunnel(tunnelCtx, api.MaintainTunnelConfig{
			TLSConfig:         tlsConfig,
			KeepalivePeriod:   keepalivePeriod,
			InitialPacketSize: initialPacketSize,
			Endpoint:          endpoint,
			Device:            api.NewNetstackAdapter(tunDev),
			MTU:               mtu,
			ReconnectDelay:    reconnectDelay,
			AlwaysReconnect:   alwaysReconnect,
			UseHTTP2:          useHTTP2,
			OnConnect:         onConnect,
			OnDisconnect:      onDisconnect,
			HookEnv:           hookEnv,
		})

		resolver := &internal.TunnelDNSResolver{
			DNSAddrs:      dnsAddrs,
			Timeout:       dnsTimeout,
			UseOSResolver: localDNS && systemDNS,
		}
		if !localDNS {
			resolver.TunNet = tunNet
		}

		server, err := internal.NewSOCKS5Server(internal.SOCKS5Config{
			Addr:        net.JoinHostPort(bindAddress, port),
			Username:    username,
			Password:    password,
			Resolver:    resolver,
			TunNet:      tunNet,
			UDPTimeout:  udpTimeout,
			DialTimeout: dialTimeout,
			Logger:      log.New(internal.NewTZStampWriter(os.Stderr), "socks5: ", 0),
		})
		if err != nil {
			return fmt.Errorf("failed to create SOCKS proxy: %w", err)
		}

		log.Printf("SOCKS proxy listening on %s:%s", bindAddress, port)
		if err := server.Start(); err != nil {
			return fmt.Errorf("failed to start SOCKS proxy: %w", err)
		}
		return nil
	},
}

func init() {
	socksCmd.Flags().StringP("bind", "b", "0.0.0.0", "Address to bind the SOCKS proxy to")
	socksCmd.Flags().StringP("port", "p", "1080", "Port to listen on for SOCKS proxy")
	socksCmd.Flags().StringP("username", "u", "", "Username for proxy authentication (specify both username and password to enable)")
	socksCmd.Flags().StringP("password", "w", "", "Password for proxy authentication (specify both username and password to enable)")
	socksCmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	socksCmd.Flags().StringArrayP("dns", "d", []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}, "DNS servers for the tunnel stack; with -l also used for SOCKS name lookups (unless --system-dns)")
	socksCmd.Flags().DurationP("dns-timeout", "t", 2*time.Second, "Timeout for DNS queries")
	socksCmd.Flags().Duration("dial-timeout", 15*time.Second, "Maximum time for SOCKS DNS resolution and connection establishment")
	socksCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	socksCmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	socksCmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	socksCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	socksCmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	socksCmd.Flags().IntP("mtu", "m", 1280, "MTU for MASQUE connection")
	socksCmd.Flags().Uint16P("initial-packet-size", "i", 0, "Custom initial packet size for MASQUE connection (default: auto with PMTU discovery)")
	socksCmd.Flags().DurationP("reconnect-delay", "r", 1*time.Second, "Delay between reconnect attempts")
	socksCmd.Flags().Duration("udp-timeout", 60*time.Second, "Idle read deadline for each remote UDP relay (SOCKS5 ASSOCIATE). Shorter frees memory sooner; raise (e.g. 300s) if a quiet peer needs longer silence. 0 disables the deadline and risks unbounded growth under DHT/uTP")
	socksCmd.Flags().Bool("always-reconnect", false, "Always reconnect after tunnel loss, even when idle")
	socksCmd.Flags().Bool("http2", false, "Use HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC."+config.EndpointHelpSuffixH2)
	socksCmd.Flags().Bool("insecure", false, "Disable endpoint certificate pinning and trust any certificate")
	socksCmd.Flags().BoolP("local-dns", "l", false, "Do not send proxy DNS through the tunnel; use -d over the host instead. Add --system-dns to use the OS resolver instead of -d")
	socksCmd.Flags().Bool("system-dns", false, "With -l, resolve names via the OS (e.g. /etc/resolv.conf) instead of -d")
	socksCmd.Flags().String("on-connect", "", "Path to an executable to run after each successful tunnel connect (no args; context via USQUE_* env vars)")
	socksCmd.Flags().String("on-disconnect", "", "Path to an executable to run after each tunnel disconnect (no args; context via USQUE_* env vars)")
	rootCmd.AddCommand(socksCmd)
}
