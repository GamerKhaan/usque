# SOCKS reliability review

Reviewed against upstream **v4.2.1**, commit
`6aa03fc97d12848dce34eedbd187fb1077b5d1ea`, on 2026-09-10. The upstream
README, MIT license, module versions, release configuration, relevant commands,
DNS/SOCKS implementations and CI were inspected before editing. GitHub PR
descriptions, file diffs, issue comments and available review/comment endpoints
were inspected directly. Upstream history and copyright remain intact.

## Upstream evidence and local decisions

| Reference | Reviewed intent/evidence | Fork decision |
| --- | --- | --- |
| [PR #94](https://github.com/Diniboy1123/usque/pull/94) (open, unmerged) | Separates UDP bind/advertise addresses and introduces bounded tunnel dialing. Its current diff also changes tunnel reconnect packet handling; its DNS call signatures differ from this base. | Adapt the timeout concept to the current code and expose `--dial-timeout` on both SOCKS commands. Do not apply the PR wholesale. Separate public UDP binding/advertising is outside the localhost production profile; the unrelated tunnel changes are excluded. |
| [Issue #105](https://github.com/Diniboy1123/usque/issues/105) (open) | Reports rejection of UDP sources not matching their TCP source port. Comments also report relay-cap exhaustion and differing symptoms/platforms. | Accept zero-source associations without dropping TCP association enforcement. Preserve the existing relay cap and idle timeout; this patch is not evidence that every UDP or throughput report is resolved. |
| [PR #104](https://github.com/Diniboy1123/usque/pull/104) (closed, unmerged) | Proposes an opt-in loose association mode. The maintainer redirected this work to #107 for default compatibility. | Adopt the intended compatibility without an extra opt-in flag. Do not copy its test connection whose read blocks indefinitely. |
| [PR #107](https://github.com/Diniboy1123/usque/pull/107) (open, unmerged) | Makes all-zero UDP ASSOCIATE support default. Comments report success with sing-box and Xray. Claiming, publishing and closing an association are separate operations in the proposed code. | Retain the default compatibility concept, with atomic lifecycle handling and local endpoint tests. The upstream client reports are useful evidence, not a real-client test of this fork. |
| [PR #118](https://github.com/Diniboy1123/usque/pull/118) (open, unmerged) | Adds package-global singleflight to prevent competing claims for one UDP source. No substantive review discussion or new test file was available. | Use one server-scoped mutex across lookup, claim, publication and removal. It provides the intended serialization without a new dependency, cross-server singleflight state, or a gap between pending removal and publication. |
| [Issue #109](https://github.com/Diniboy1123/usque/issues/109) (open) | Reports 3.0.1 working where 4.1/4.2 appear connected without traffic; a comment reports HTTP/2 working in an affected setup. A suggested QUIC/FIPS cause remains speculation. | Keep HTTP/2 selectable for full SOCKS and check actual HTTPS through the proxy. Do not downgrade dependencies or assert a root cause from these reports. L4 mode supports HTTP/3 only. |

## Patches carried locally

1. **Bounded SOCKS setup.** `--dial-timeout` defaults to 15 seconds and must be
   positive. One context bounds target DNS plus TCP/UDP establishment. Custom
   dialers receive that context directly; no timeout wrapper goroutine is used.
   Local resolver calls honor context cancellation, and competing DNS queries
   are canceled after resolution. SOCKS negotiation/request parsing and UDP
   writes also have deadlines. Established TCP transfers are not assigned the
   dial timeout as a lifetime limit.
2. **Atomic UDP ownership.** A `0.0.0.0:0` or `[::]:0` request is published before
   the success reply, then bound to the first datagram from the TCP peer's IP.
   Explicit source ports remain enforced; a supplied foreign source IP is
   rejected. Closing the control connection atomically removes ownership and
   cancels the relay sockets, including readers with no idle timeout. Repeated
   packets for one flow share its relay, and old flow cleanup cannot delete a
   newer association. Dialers are per server, removing the dependency's global
   dialer override from this wrapper.
3. **Startup failures.** Only the deployment's `socks` and `l4-socks` commands
   switch to `RunE`, allowing existing `main.go` to exit nonzero on missing
   configuration, invalid options, failed setup or listener binding. Full SOCKS
   tunnel maintenance receives a cancelable command context.
4. **Bounded L4 CONNECT handshake.** Code review found that passing a context
   to HTTP/3 `OpenRequestStream` only bounds stream allocation, not the following
   header write and response read. The local fix applies a temporary stream
   deadline and cancels both stream directions on context cancellation. It
   joins any running cancellation callback and clears the deadline before
   returning a successful connection. This is kept separate from the SOCKS
   association change and makes no tunnel packet-loop changes.

## Compatibility limits

All-zero UDP ASSOCIATE provides no identifier connecting an initial datagram
to one of several pending control connections from the same IP. Pending
associations are claimed in creation order; this cannot distinguish mutually
untrusted users behind one shared IP. Keep the production proxy on loopback.
Public exposure still requires a deliberate access-control design.

The generic CLI port remains 1080 and MTU remains 1280; the production profile
selects port 903. L4's upstream default resolves target hostnames locally, so
HTTPS through L4 verifies that the TCP path uses WARP but does not prove that DNS
itself traveled through WARP. Full `socks` uses tunnel DNS by default.

Tests use deadline-aware fake dialers, a real gVisor netstack that discards
outbound packets, local TCP/UDP endpoints, and a local HTTP/3 CONNECT server.
Coverage includes TCP/DNS/UDP timeout enforcement, concurrent claims and
claim/close races, strict explicit ports, burst relay reuse, UDP round trips,
control-close cleanup, missing configuration, occupied listeners, stalled L4
responses and established L4 stream survival past dial-context expiry. These
do not establish real Cloudflare availability, sustained production throughput,
or compatibility with every Xray/sing-box version. See the acceptance test
document for deployment validation.
