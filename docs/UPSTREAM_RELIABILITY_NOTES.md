# Upstream reliability review

Reviewed 2026-09-10. Base: upstream **v4.2.1**, commit
`6aa03fc97d12848dce34eedbd187fb1077b5d1ea`. This is an actual GitHub fork;
upstream authorship, history, module path and MIT notice are retained.

Issue reports describe specific environments, not universally reproduced defects.
Reviews included issue discussions, PR diffs, review comments, and current base
code. No open PR was blindly cherry-picked.

| Upstream item | Evidence / intent | Fork response |
| --- | --- | --- |
| [#49](https://github.com/Diniboy1123/usque/issues/49) | Reports show an alive process and connected logs with stuck proxied requests. Keepalive adjustments did not resolve every report. | A supervisor verifies fresh SOCKS HTTPS trace requests and WARP status; repeated failures restart the complete child. `--always-reconnect` is enabled in the service. |
| [PR #94](https://github.com/Diniboy1123/usque/pull/94) | Proposes explicit dial bounds plus UDP listener/advertised-address separation, alongside broader tunnel changes. | Adapt bounded dialing and compatible relay behavior; do not take unrelated tunnel changes or all public-binding options. Review notes are in CORE_RELIABILITY_REVIEW.md. |
| [PR #104](https://github.com/Diniboy1123/usque/pull/104), [#105](https://github.com/Diniboy1123/usque/issues/105) | UDP ASSOCIATE bind and source matching changes interact with clients that cannot specify their UDP source port before the association is established. | Test explicit and zero-source associations, relay endpoint ownership, and TCP-control lifetime. |
| [PR #107](https://github.com/Diniboy1123/usque/pull/107) | Accepts zero/unspecified source requests; discussion includes client success reports. | Preserve compatibility intent, add ownership synchronization and concurrent tests. User reports are not fork acceptance evidence. |
| [PR #118](https://github.com/Diniboy1123/usque/pull/118) | Addresses races while matching and claiming pending zero-source associations. | Server-scoped synchronization makes source lookup, claim, publication and cleanup atomic without a new singleflight dependency. |
| [#109](https://github.com/Diniboy1123/usque/issues/109) | Reports v3.0.1 working where v4.1/v4.2 do not; a commenter reports HTTP/2 working when HTTP/3 stalls. A dependency explanation is speculation. | Expose HTTP/2 for full socks, retain tested release rollback, and avoid attributing a universal root cause or downgrading dependencies without evidence. L4 remains HTTP/3 only. |
| [PR #116](https://github.com/Diniboy1123/usque/pull/116) | Open packet-handling refactor adds a shared reader/channel and changes close-error classification. Reviewed head `113311f6bafc46bed3983a024597bc0882dc51da`; no submitted review comments were returned. | Not adopted. Packet headroom, queued buffer ownership on failed connect, reader cancellation, and close-error compatibility need dedicated tests before changing this boundary. |
| [#123](https://github.com/Diniboy1123/usque/issues/123) | Reports HTTPS stalls with MTU 1280 in a gVisor embedding and improvement at 1000. The issue was withdrawn/closed; the maintainer later reported initial QUIC packet size 1350 with MTU 1280 working privately. | Preserve global MTU 1280. Allow service MTU experiments at 1200/1000 for matching symptoms. HTTPS probes detect TLS/data-plane stalls. Neither the reporter's PMTU explanation nor the maintainer's packet-size result has been independently validated here. |

## Locally carried patches

- Configurable `--dial-timeout` for full and L4 SOCKS; cancellation bounds TCP,
  DNS and UDP setup. Successful stream lifetime is separate from dial lifetime.
- Concurrency-safe zero-source UDP associations, source IP restriction, atomic
  claims and teardown of associated relay sockets with the TCP control channel.
- SOCKS startup errors return nonzero using scoped Cobra `RunE` handlers.
- Fatal TCP relay errors close both directions so the opposite reader cannot
  retain connections indefinitely. Normal TCP half-close remains supported;
  fault-injection and real TCP tests cover both behaviors.
- Listener announcements follow successful binds, and malformed UDP messages
  distinguish local SOCKS parsing from relay errors without logging payloads.
- Optional service DNS selection preserves the core defaults when unset, and
  validates literal resolver addresses before launching either SOCKS mode.
- Rate-limited loopback-source packet diagnostics distinguish locally generated
  ICMP from MASQUE ingress. Packet bytes and netstack filtering remain unchanged.
- Protected config persistence, receiver-based key parsing, strict bounded JSON
  reads, structural validation, and safe registration endpoint parsing/errors.
- Supervisor, service profile, installer, operations tools, tests and release CI.
- Tunnel packet-error counters with rate-limited journald output. These preserve
  the existing continue/reconnect classification rather than silently changing it.

The local commit log separates these areas. The module path stays upstream so
merges do not require import churn. The original license is unchanged.

## Tunnel audit and intentionally deferred changes

`MaintainTunnel` retries connection failures and some close errors but continues
after some non-close packet errors. Those paths now report operation and cumulative
error count with repeated messages limited to 30 seconds. Tests cover counting,
concurrency, cancellation of reconnect sleep, and packet-buffer headroom.

The upstream per-cycle `readMu` does not serialize a stale reader against readers
from later cycles despite its log comment. Blocking device reads and the wait for
`errChan` can also outlive cancellation. These are documented risks, not claims
that the current patch fixes tunnel lifecycle internals. The supervisor provides
a process boundary with a shutdown deadline and Linux process-group cleanup.
Systemd provides a final cgroup cleanup boundary if the supervisor dies.

PR #116 is invasive relative to this fork's initial reliability scope. In its
reviewed form, the outbound packet slice length/headroom and ownership during a
failed connect deserve focused validation. Changing from `connectip.CloseError`
to `net.ErrClosed` must also be tested against the pinned dependency. This fork
does not assert that either classification should replace the other globally.

We intentionally do not change the upstream MTU default, downgrade QUIC on the
basis of #109 speculation, change the generic SOCKS port, or auto-merge upstream.
HTTPS health proves one TCP/DNS/TLS path; it does not prove UDP ASSOCIATE forwarding,
all destinations, throughput, capacity or long-term stability.

## Next investigation

Perform a staging Ubuntu soak with real personal WARP credentials and exact
Xray/sing-box/Hysteria versions. Capture restart count, latency, RSS and concurrent
TCP/UDP results. Reproduce tunnel reader cancellation and MTU/initial-packet-size
behavior independently before introducing a separate tunnel refactor.
