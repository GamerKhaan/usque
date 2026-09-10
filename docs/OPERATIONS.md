# Operating the Ubuntu service

Use `sudo usquectl status`, `sudo usquectl health`, `sudo usquectl doctor` and
`sudo usquectl logs` before changing settings. Status is a snapshot; `health`
always performs a new request. A listener or systemd `active` state alone does
not prove WARP connectivity.

## Recovery behavior

The supervisor probes immediately on child start, then waits 20 seconds after
each probe finishes. Probes expire after 8 seconds and three consecutive failures
restart the child. A temporary failure clears on the next successful probe.
Retries use exponential backoff around 1 to 30 seconds with jitter; sustained
healthy probes for 2 minutes reset it. A failed request may therefore recover
without a restart, and a persistent hang normally takes roughly a minute or more
to detect. Established connections are lost during a child restart.

SIGTERM/SIGINT is forwarded to the child process group. The supervisor waits the
configured shutdown timeout before forcing cleanup. The systemd unit has a final
90-second stop deadline for the whole cgroup; keep the supervisor's timeout below
that limit. systemd restarts the supervisor if it exits. No shell session is part
of the service lifecycle.

## Startup or registration fails

Confirm Ubuntu/systemd, architecture, free port 903, DNS, correct system clock,
and HTTPS access to GitHub and the Cloudflare registration API. Registration
uses a bounded personal WARP registration/enrollment. Raw registration output is
kept private during the attempt and discarded; the terminal gives a failure and
recovery action. Retry with `sudo usquectl register` after resolving the cause.
An existing config is preserved even if invalid; use `import-config` to replace it.

```bash
sudo /opt/usque/current/usque-supervisor validate-config /etc/usque/config.json
sudo stat -c '%U:%G %a' /etc/usque/config.json
sudo systemctl show usque -p User -p Group -p AmbientCapabilities -p MainPID
sudo ss -lntup 'sport = :903'
```

Expected config mode is `root:usque 640`. The service runs as `usque` with only
`CAP_NET_BIND_SERVICE`, needed for port 903 on stock Ubuntu. No TUN device or
`CAP_NET_ADMIN` is required. A structural config check validates format and keys,
not whether Cloudflare still accepts the account; HTTPS readiness tests the latter.

## HTTPS stalls while the tunnel says connected

The health probe uses `https://www.cloudflare.com/cdn-cgi/trace`, remote hostname
SOCKS negotiation, normal TLS verification, and `warp=on`/`warp=plus`. It cannot
silently fall back to the host's HTTP proxy or a redirected URL. Missing WARP
confirmation is unhealthy. The trace target is configurable but must be an HTTPS
hostname URL without credentials/query/fragment; do not weaken it to plain HTTP.

Upstream [#123](https://github.com/Diniboy1123/usque/issues/123) reported a gVisor
HTTPS stall at MTU 1280. In staging, back up `service.env`, test `USQUE_MTU=1200`,
then `1000`, restarting and checking HTTPS and your actual workload each time.
Restore 1280 if it does not help. The maintainer later suggested QUIC initial packet
size 1350 with MTU 1280 in a private test. That is a separate transport setting,
not evidence that lowering MTU always fixes the issue. This fork does not change
initial packet size or the global MTU default without reproduction evidence.

For full `socks`, `USQUE_HTTP2=true` is an alternative when QUIC is blocked or
unstable. This setting is rejected for `l4-socks`. Destination DNS is tunneled in
full socks by default; L4's upstream implementation resolves destination names
locally. Never claim the L4 health check establishes DNS privacy through WARP.

## Choosing service DNS servers

`USQUE_DNS` in `/etc/usque/service.env` optionally selects up to eight literal
IPv4/IPv6 resolver addresses, separated by commas without spaces. An omitted or
empty value preserves the upstream Quad9 defaults. For example:

```ini
USQUE_DNS=1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001
```

Both modes pass these addresses to the core's repeatable `--dns` option. Full
`socks` sends DNS through WARP; `l4-socks` sends DNS over the host network by its
existing default. This setting does not edit `/etc/resolv.conf` or host DNS.
`usquectl status` and `doctor` show the configured selection. Back up
`service.env`, change one setting, restart with `sudo usquectl restart`, and check
`sudo usquectl health` plus representative application traffic. Resolver latency
and reachability depend on the network; a different provider is not a universal
performance fix.

Older releases such as `v4.2.1-gk.2` do not recognize `USQUE_DNS` in their
management tool. Before rolling back to one, restore a compatible backup of
`service.env` or back it up and remove the `USQUE_DNS=` line, even if it is empty.
The new rollback preflight refuses an incompatible target before changing the
active release. Removing the key restores upstream DNS defaults; WARP credentials
in `config.json` are unaffected.

## UDP and client compatibility

The full SOCKS listener supports TCP and UDP; L4 only supports TCP. Zero-source
UDP associations are bound to the TCP peer IP and claimed by a UDP source
endpoint under server-scoped synchronization. The TCP control connection must
remain open for its UDP association. SOCKS fragmentation is not implemented.
Multiple zero-source controls from the same IP have no on-wire correlation token;
first datagrams claim pending controls in order. Out-of-order first packets can
misassociate control lifetimes, so test parallel same-host client sessions.

The HTTPS probe cannot detect an isolated UDP forwarding failure. Test DNS/QUIC
or another controlled UDP application through your exact proxy chain and monitor
concurrent associations. Upstream client reports do not replace local validation.

## Interpreting logs while traffic still works

`address already in use` at startup means another TCP or UDP listener owns the
configured port. Inspect `sudo ss -lntup 'sport = :903'` and avoid running a second
manual proxy beside systemd. Listener announcements appear only after the required
socket binds succeed. A listener announcement still does not establish WARP readiness.

A SOCKS connection `context deadline exceeded` describes the bounded DNS/dial
attempt for that request. Compare fresh `usquectl health`, consecutive failures,
and the affected application before diagnosing a complete tunnel outage. Raising
the timeout can retain failed attempts longer; it does not repair an unreachable
destination.

`SOCKS UDP datagram ... failed during parsing: Bad Request` means the local listener
received an invalid SOCKS5 UDP frame. Check the client's UDP encapsulation. It is
not a Cloudflare HTTP response. The TCP control channel must also stay open for
UDP forwarding. Older fork releases printed only `Bad Request` for this path.

gVisor's `Martian packet dropped with loopback ... address` reports rejection of
an externally received packet carrying a loopback address. Keep that filter enabled.
Investigate the originating flow if application failures accompany it; silencing
the message by accepting external loopback traffic changes the isolation boundary.

The accompanying `Tunnel packet diagnostic` distinguishes `origin=local_icmp`
(locally generated packet-too-big feedback) from `origin=tunnel_ingress`
(received through MASQUE). It reports only outer IP version/protocol and ICMP
type/code when available, with bounded counters and a 30-second rate limit per
origin/protocol. Packet contents, destination addresses and domains are not logged;
packets still pass unchanged to normal netstack validation. This evidence helps
locate the problem without assuming every Martian message has the same cause.

Fatal TCP relay read/write failures now close both relay connections. Ordinary
FIN keeps the reverse response path open. Regression tests cover both error cleanup
and a response sent after request half-close. This fixes possible retained sockets
after errors; it does not imply every live timeout was caused by that defect.

## Updates, imports and rollback

`usquectl update` obtains the latest release from this fork, verifies SHA256, and
stages a version directory under `/opt/usque/releases`. Release switching uses an
atomic `current` symlink; `previous` identifies the prior known-good version. The
unit and binaries follow the same release. A failed health gate restores the
previous version and returns nonzero even if the restored version recovers.

`usquectl import-config /path/config.json` stages a copy, validates it, backs up
the previous config under `/etc/usque/backups`, installs it with restrictive
permissions, and restarts/revalidates. A failed gate restores the old config; with
no old config it removes the candidate and stops the service. Avoid editing
credentials in place; use this transaction for replacement.

If an outage affects both versions, rollback may restore the old files while the
network remains unhealthy. The command reports this distinction. Do not delete
the previous release or config backups during incident response.

## System settings and removal

The installer only raises UDP buffer ceilings below 7500000, preserving higher
runtime values and persisting managed values under
`/etc/sysctl.d/90-usque-buffers.conf`. No routing, firewall, MTU on host interfaces,
or DNS resolver settings are changed. The SOCKS MTU is internal to the netstack.

`usquectl uninstall` disables/removes the unit and command links, preserving the
system user, credentials, backups, release directories, and buffer settings.
Reinstall restores management. Remove retained data or sysctl configuration only
as a deliberate separate administrative action after securing necessary backups.
