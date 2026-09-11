# Validation evidence

Date: 2026-09-10. Upstream base: `v4.2.1`,
`6aa03fc97d12848dce34eedbd187fb1077b5d1ea`.

## 2026-09-11 follow-up and doctor regression

At 14:13 UTC a live Ubuntu recheck of `v4.2.1-gk.5` found the same child running
for about 23 hours. Its restart counter was one, from installation.
Two consecutive HTTPS probe timeouts overnight recovered on the next probe
without restarting the child. Four explicit destination tests (two IPv4 and two
IPv6 Cloudflare addresses, validated TLS and trace) all returned HTTP 200 with
`warp=on`, taking 110-139 ms. Eight SOCKS UDP DNS cases passed: zero/explicit
source association, domain/IP destination, each repeated twice. These are
bounded spot checks, not evidence that every client destination is reachable.

No recent kernel warnings or NIC error/drop counters were found in that sample.
Both UDP buffer ceilings were already 134217728 bytes, above the documented
minimum, so no additional sysctl tuning was warranted. Destination timeouts,
loopback-source ICMP diagnostics and invalid zero-domain UDP frames still occur;
this check does not establish that those upstream/client issues are resolved.

The doctor regression fixture reproduced a false success with an inactive
managed service and a successful independent proxy probe. The fix also requires
the configured TCP bind, the UDP bind for full SOCKS, and expected service.env
permissions. Eight new cases cover healthy full SOCKS, inactive service, absent
UDP, wrong bind, failed listener inspection, TCP-only mode, IPv6, and environment
permissions. All 41 deployment tests passed locally under MSYS; ShellCheck,
the complete Go suite, race tests, vet and golangci-lint passed on Windows.
The candidate doctor also returned zero against the live healthy Ubuntu service
without modifying or restarting it. The IPv6 filter was subsequently checked
against Ubuntu's actual `ss` parser and corrected to use brackets; Linux tests
now exercise that parser. The unreleased gk.6 workflow was cancelled before
publication. [Exact-tag gk.7 CI](https://github.com/GamerKhaan/usque/actions/runs/34610130512)
passed the full Go/race/vet/lint suite, 41 deployment tests, four hardened systemd
lifecycle groups, and both amd64/arm64 archive checks.

During the same audit, before deploying any update, the peer closed the gk.5
HTTP/3 stream at 14:25:31 UTC (`H3_REQUEST_CANCELLED`, remote application error
0x10c). Core logged a new MASQUE connection at 14:25:32, but the next three
HTTPS probes timed out. The supervisor stopped and replaced the child at
14:26:38-39; health returned at 14:26:59. This was an observed production failure
and automatic recovery, with no deliberate fault injection. A successful
reconnect log did not establish a working data path. The precise cause after
reconnect remains unproven; this release does not change the tunnel pumps.

The gk.7 health-gated update completed at 14:29:30 UTC with exit zero and both
configuration files byte-for-byte preserved. The previous release remained gk.5.
The installed doctor reported zero failed checks; an independent HTTPS probe
returned `warp=on` in 72 ms. The process remained unprivileged with only
CAP_NET_BIND_SERVICE, and TCP/UDP listeners remained on 127.0.0.1:903. No kernel,
firewall, routing, MTU or DNS setting was changed during this maintenance.

## Executed checks

The initial complete implementation at `8814b22bf4e955c948df49ea15e0bacdebf7652a`
passed [Ubuntu CI run 34482254817](https://github.com/GamerKhaan/usque/actions/runs/34482254817).
The runner was Ubuntu 24.04 / Linux amd64, with Go 1.26.3. The release workflow
reruns the complete suite at the exact release tag before publication; consult
the [Actions page](https://github.com/GamerKhaan/usque/actions) for subsequent runs.

| Command / check | Actual result |
| --- | --- |
| gofmt verification | Clean |
| `go mod verify` | Passed |
| `go vet ./...` | Exit 0 |
| `go test -count=1 ./...` | All five test-bearing packages passed; no failures |
| `CGO_ENABLED=1 go test -race -count=1 ./internal/... ./api ./config ./cmd` | All five packages passed; no race reports |
| golangci-lint v2.13.2 | 0 issues |
| Bash syntax and ShellCheck | Passed for installer, management library/tool, and shell tests |
| `bash tests/deployment_test.sh` | 28 tests passed |
| `systemd-analyze verify` | Passed |
| `CGO_ENABLED=0 go build -trimpath ./...` | Passed |
| Actual hardened-unit lifecycle test | All four acceptance groups passed (details below) |
| GoReleaser v2.18.1 snapshot | Built Linux amd64 and arm64, both core and supervisor |
| `python3 tests/check_release.py` | Both archives passed SHA256, ELF/executable, payload and license checks |

Windows amd64 with Go 1.27.1 also passed the full Go suite, vet, golangci-lint,
and the same race command with MSYS UCRT GCC/CGO enabled. Windows ran all 28
deployment tests using real temporary files/symlink switching and mocked system
services. MSYS substitutes unsupported O_NOFOLLOW/mode behavior, documented in
the test source; Linux CI exercises the native flags. Windows ShellCheck v0.11.0
and GoReleaser snapshot/archive checks passed.

Built Windows CLI invocations for `socks` and `l4-socks` with a missing config
both returned **exit 1**, as required. A subsequent scoped logging cleanup at
`1a3f60c` removed duplicated errors/usage dumps and passed `go test ./cmd`, lint,
and a repeated built-binary exit check.

## Actual systemd fixture evidence

The Ubuntu job starts the committed hardened unit and real supervisor, with a
test-only SOCKS child and locally generated trusted TLS trace endpoint. It checks:

1. User/parent ownership, `127.0.0.1:903`, only `CAP_NET_BIND_SERVICE`, fresh
   HTTPS through SOCKS, and verified fixture WARP status.
2. SIGKILL of the child causes an automatic replacement and fresh health.
3. SIGSTOP leaves the child alive but unusable; failed probes trigger bounded
   forced cleanup and a healthy replacement.
4. SIGTERM to the supervisor cleans up its child and systemd starts a new healthy
   supervisor/child pair.

All four printed PASS in the linked run. Separate Linux Go tests passed SIGINT/
SIGTERM forwarding, child reaping, forced-stop deadlines and process-group
descendant cleanup. Local HTTP/3 tests verified L4 handshake deadlines and that
successful streams survive dial-context expiry.

## Live WARP follow-up, 2026-09-10

An operator-provided Ubuntu 24.04 amd64 host already running `v4.2.1-gk.1` was
inspected during existing traffic. This was an inspection of an installed service,
not execution of the initial installer by the maintainer.

- `usquectl doctor` validated the config structure, root:usque 0640 ownership,
  unprivileged service, and TCP/UDP listening only on `127.0.0.1:903`.
- Six consecutive fresh HTTPS/WARP probes succeeded (82-324 ms), plus individual
  health checks. All confirmed `warp=on` with normal certificate verification.
- Eight real UDP DNS queries succeeded: zero-source and explicit-source
  associations, each with IP and domain destinations, repeated twice. UDP source
  ports differed from their TCP control ports. Replies matched DNS transaction ID,
  response flag, success code and expected relay source. Controls stayed open.
- Three 1 MiB HTTPS transfers completed with HTTP 200 and the exact expected size.

These bounded checks do not certify all client implementations, UDP concurrency,
peak throughput or long-term stability. The live service was not deliberately
killed or interrupted for failure injection during this inspection.

The follow-up TCP cleanup regression failed before the fix for both read and write
faults, then passed ten repetitions. A real TCP test confirms responses still work
after request FIN. The complete Go suite and internal race tests also passed locally.

### Live updates and DNS selection

The same host subsequently completed actual `usquectl update` transactions to
`v4.2.1-gk.2` and `v4.2.1-gk.3`. Fresh HTTPS checks confirmed `warp=on`, and SHA256
comparisons confirmed that both configuration files survived each update unchanged.
The previous release remained available. These successful updates do not establish
the behavior of a deliberately failed update on this live host.

After a separate backed-up environment edit, Cloudflare's four documented resolver
addresses were selected through `USQUE_DNS`. Fresh HTTPS and eight repeated SOCKS
UDP DNS cases passed. Before selection, 20/20 resolver queries through SOCKS/WARP
succeeded. Small cached IPv4 samples had median response times of 4.30-4.67 ms for
Cloudflare and 4.89-5.14 ms for Quad9; this is not a general performance guarantee.
Existing persisted receive/send buffer maxima were already 134217728 bytes, above
the recommended 7500000 minimum, so they were preserved.

The `v4.2.1-gk.3` release passed the complete
[Ubuntu release workflow](https://github.com/GamerKhaan/usque/actions/runs/34487715888),
including 33 deployment tests, race tests, the hardened systemd lifecycle fixture,
and checked release archives for both architectures.

### Bounded Martian-packet reproduction

One controlled SOCKS CONNECT to `0.0.0.0:9`, with no application data, reproduced
an ingress IPv4 ICMP destination/host-unreachable packet with a loopback source on
`v4.2.1-gk.3`. The netstack rejected it and the request ended after 8.008 seconds
without a SOCKS failure reply. This established two actionable paths: prevent
literal local-only destinations from entering the tunnel, and renew the protocol
reply deadline after dialing consumes its budget.

Automated regression tests cover the expired-dial reply, successful reply at the
deadline boundary, and remote cleanup if renewing the deadline fails. Actual
netstack tests verify that rejected TCP/UDP destinations emit no packets, legitimate
routed TCP still emits a SYN, and zero-source UDP association remains accepted.
Controlled local DNS tests cover loopback/unspecified answers in the local-resolver
branch; the default tunnel resolver's address fallback is left intact.

Additional natural ICMP reports were observed separately. The controlled test does
not establish that all such reports have the same cause. Quoted-destination class
diagnostics were added without recording addresses or changing packet validation.

The actual update to `v4.2.1-gk.4` subsequently passed fresh HTTPS readiness and
preserved both config files byte-for-byte. Seven controlled local-only destinations
received full SOCKS `RepNotAllowed` replies in 0.459-3.035 ms, including the earlier
unspecified-address reproduction. Eight repeated real UDP DNS cases passed;
`usquectl doctor` and three further HTTPS/WARP checks passed (70-82 ms). The previous
`gk.3` release remained available. Its exact-tag
[Ubuntu release CI](https://github.com/GamerKhaan/usque/actions/runs/34490030793)
passed the complete suite, systemd fixture, and both architecture builds.

Natural loopback-source ICMP reports later recurred while health remained good
with zero child restarts. Sampled quotations had private destinations; that class
alone cannot distinguish a private target from an assigned private tunnel address.
One 30.004-second passive header-only UDP sample observed 616 correctly framed
datagrams: 501 global and 115 private literal destinations. No parse-rejected
datagram was captured in that sample. Kernel filtering excluded domains and
application payload, and no capture file or address values were recorded. These
observations motivated local-address match labels and explicit parser reasons;
they do not justify blanket private-network blocking or accepting rewritten ICMP.

## Explicitly not established

- No real Cloudflare account was registered or live WARP credentials used during
  CI. The fixture's WARP response validates the probe implementation, not
  Cloudflare availability or real enrollment.
- No production Ubuntu host was initially installed or rebooted during this work.
  Host dependency installation, real registration and failed live-release rollback
  still need staging acceptance; transaction logic was tested with controlled mocks.
- No controlled end-to-end Xray, sing-box or Hysteria client soak was executed;
  direct SOCKS UDP checks on the operating host do not replace that acceptance.
- Linux arm64 artifacts were cross-built and inspected, not run on arm64 hardware.
- No throughput, capacity, uptime guarantee, or MTU/QUIC root-cause claim is made.

Complete [ACCEPTANCE_TEST.md](ACCEPTANCE_TEST.md), including a staging soak with
real TCP/UDP clients, before deploying production traffic.
