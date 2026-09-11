# usque — supervised WARP for Ubuntu

A production-oriented public fork of [Diniboy1123/usque](https://github.com/Diniboy1123/usque), maintained by **GamerKhaan.ir**. It runs local SOCKS5 through Cloudflare WARP MASQUE and recovers when the child exits or stops carrying traffic.

**Default SOCKS5 endpoint: `127.0.0.1:903` (TCP and UDP).** No tmux, screen, Docker, or interactive shell is needed. Upstream generic CLI defaults remain unchanged.

```text
VLESS / Xray / sing-box / Hysteria
                  │
          SOCKS5 127.0.0.1:903
                  │
systemd → usque-supervisor → usque → Cloudflare WARP MASQUE
                   └── HTTPS trace through SOCKS → WARP verification
```

## Install

Ubuntu with systemd, amd64 or arm64:

```bash
curl -fsSL https://raw.githubusercontent.com/GamerKhaan/usque/main/install.sh | sudo bash
```

The installer downloads **this fork's release**, verifies SHA256 checksums, creates a dedicated `usque` user, stages registration when needed, enables systemd, and waits for HTTPS/WARP readiness. No Go toolchain is required. Reinstalling preserves configuration. Fresh personal WARP registration uses the upstream flow and accepts [Cloudflare's application terms](https://www.cloudflare.com/application/terms/); review them before installation.

Success is reported only after end-to-end validation:

```text
SOCKS5: 127.0.0.1:903
Status: healthy
```

Registration failure returns nonzero with recovery guidance. After correcting connectivity use `sudo usquectl register`. This preserves an existing config; explicit replacement uses `import-config`.

## What this fork adds

- Go supervision: graceful signals, bounded HTTPS probes, consecutive-failure recovery, jittered exponential backoff, runtime health and restart state.
- Bounded SOCKS dialing and concurrency-safe unspecified-source UDP ASSOCIATE handling.
- Prompt rejection of local-only tunnel destinations, reliable SOCKS failure replies, and packet diagnostics that omit addresses and payloads.
- Configurable service DNS and UDP buffer tuning that preserves larger host settings; see the [operations guide](docs/OPERATIONS.md#choosing-service-dns-servers).
- Hardened Ubuntu systemd deployment, protected credentials, journald, and management tooling.
- Verified transactional releases, automatic rollback on failed readiness, and explicit updates.
- Lifecycle, protocol, deployment transaction, and release packaging tests.

These safeguards improve recovery; they do not guarantee Cloudflare availability, preserve existing connections across restart, or prove UDP health. Run the [acceptance checklist](docs/ACCEPTANCE_TEST.md) on your host and client versions before rollout. See [upstream reliability notes](docs/UPSTREAM_RELIABILITY_NOTES.md) for remaining risks.

## Management

```bash
sudo usquectl status
sudo usquectl health
sudo usquectl doctor
sudo usquectl logs
sudo usquectl restart
sudo usquectl register
sudo usquectl import-config /path/to/config.json
sudo usquectl update
sudo usquectl rollback
sudo usquectl version
sudo usquectl uninstall
```

`health` makes a fresh HTTPS request through SOCKS5, requiring HTTP 200 and `warp=on` or `warp=plus`. The hostname is sent to SOCKS. Full `socks` resolves it through the WARP netstack. `l4-socks` uses local destination DNS and only supports TCP.

`status` shows systemd, mode/endpoint, release/core versions, and supervisor health/failures/restarts. Counters cover the current supervisor lifetime; journald retains earlier events. `doctor` checks the active service, configuration permissions, listeners on the configured address (including UDP for full SOCKS), and HTTPS/WARP. It also reports OS/architecture, UDP buffers, and journal errors without dumping credentials. Failed checks produce a nonzero exit status. Use `sudo` for protected state and logs.

## Configuration

| Path | Purpose | Ownership / mode |
| --- | --- | --- |
| `/etc/usque/config.json` | WARP key, token, endpoints | `root:usque`, `0640` |
| `/etc/usque/service.env` | Service settings; no credentials | `root:usque`, `0640` |
| `/etc/usque/backups/` | Configuration backups | `root:root`, directory `0700` |
| `/run/usque/status.json` | Runtime health/restart state | service-owned, private |
| `/opt/usque/releases/` | Immutable release payloads | root-owned |

Use `sudoedit /etc/usque/service.env`, then `sudo usquectl restart`. Use simple `KEY=value` lines without quotes or shell expansion. See the [complete profile](deploy/service.env).

| Setting | Default |
| --- | --- |
| `USQUE_BIND`, `USQUE_PORT`, `USQUE_MODE` | `127.0.0.1`, `903`, `socks` |
| `USQUE_HEALTH_INTERVAL`, `USQUE_HEALTH_TIMEOUT` | `20s`, `8s` |
| `USQUE_HEALTH_FAILURES` | `3` consecutive failures |
| `USQUE_DIAL_TIMEOUT`, `USQUE_SHUTDOWN_TIMEOUT` | `8s`, `8s` |
| `USQUE_BACKOFF_MIN`, `USQUE_BACKOFF_MAX` | `1s`, `30s` with jitter |
| `USQUE_HEALTHY_RESET` | `2m` sustained healthy probes |
| `USQUE_ALWAYS_RECONNECT`, `USQUE_HTTP2` | `true`, `false` |
| `USQUE_MTU` | `1280` |

Probe intervals start after completion of the previous probe. Short interruptions can clear before three failures; repeated failures retain increased backoff until sustained health. Restarts interrupt existing connections.

Full `socks` is the production default for UDP workloads. Set `USQUE_MODE=l4-socks` only for TCP-only workloads: MTU/reconnect flags do not apply, and HTTP/2 is unavailable. Full `socks` supports `USQUE_HTTP2=true` for testing TCP/TLS when UDP/QUIC is problematic.

## Xray, sing-box and Hysteria

These outbound fragments apply to services on the **same host/network namespace**. Keep your authenticated inbound and select the outbound using your routing rules. Avoid routing usque's own Cloudflare connections back to its SOCKS listener.

Current Xray (including a VLESS inbound):

```json
{"tag":"warp","protocol":"socks","settings":{"address":"127.0.0.1","port":903}}
```

sing-box:

```json
{"type":"socks","tag":"warp","server":"127.0.0.1","server_port":903,"version":"5"}
```

Hysteria 2 server:

```yaml
outbounds:
  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:903
```

Consult the current [Xray SOCKS schema](https://xtls.github.io/en/config/outbounds/socks.html), [sing-box SOCKS schema](https://sing-box.sagernet.org/configuration/outbound/socks/), and [Hysteria outbounds](https://v2.hysteria.network/docs/advanced/Full-Server-Config/#outbounds) for routing/version details. Older Xray releases may use a `settings.servers` array. Exercise TCP and UDP with your deployed versions; examples are not live client certification.

## Update and rollback

`sudo usquectl update` selects the latest release from **GamerKhaan/usque**, verifies the archive, stages a root-owned version directory, atomically changes the active release, restarts, and checks HTTPS/WARP. Failure restores the previous version and returns nonzero. `sudo usquectl rollback` health-checks the previous version in the same way. Both preserve configuration. A first installation has no previous version to restore.

No unattended updates are enabled. Upstream changes enter an integration branch and require review, tests and deployment validation before a fork release. Read [upstream synchronization](docs/UPSTREAM_SYNC.md).

## Troubleshooting and security

Start with `sudo usquectl doctor` and `sudo usquectl logs`. [Operations](docs/OPERATIONS.md) covers startup failures, HTTPS/MTU stalls, HTTP/2, and rollback.

The installer raises `net.core.rmem_max` and `net.core.wmem_max` to at least `7500000` only when needed, preserving larger values. Managed settings are in `/etc/sysctl.d/90-usque-buffers.conf`. Routing and firewall rules are not changed.

SOCKS has no authentication or encryption. **Other local users can use the loopback listener.** Public listening requires both an explicit bind change and `USQUE_ALLOW_PUBLIC=true`; protect it with a firewall and an authenticated encrypted frontend. Port 903 needs `CAP_NET_BIND_SERVICE` on stock Ubuntu. This is the unit's only capability; the supervisor and child run as `usque`, not root.

Never publish configuration, registration output, private keys, tokens, or license keys. Uninstall removes/disables the service and command links while preserving config, backups, releases, system user and buffer settings for deliberate recovery.

## Build, provenance and license

Go version is declared in `go.mod`. [CI](.github/workflows/ci.yml) and [GoReleaser](goreleaser.yml) test/build the fork. Linux amd64/arm64 release archives contain `usque`, `usque-supervisor`, `usquectl`, deployment files, documentation and MIT license; release assets include SHA256 checksums.

Initial upstream base: **v4.2.1**, `6aa03fc97d12848dce34eedbd187fb1077b5d1ea`. Original Git history and module path are retained for synchronization.

The original **MIT copyright notice and license** are preserved in [LICENSE.md](LICENSE.md). Upstream code and research are credited to [Diniboy1123 and contributors](https://github.com/Diniboy1123/usque). The [archived upstream README](docs/UPSTREAM_README.md) retains original acknowledgements and generic CLI documentation. GamerKhaan.ir maintains this fork's modifications; this does not imply authorship of upstream code. This project is independent of and not endorsed by Cloudflare.
