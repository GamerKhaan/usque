# Validation evidence

Date: 2026-09-10. Upstream base: `v4.2.1`,
`6aa03fc97d12848dce34eedbd187fb1077b5d1ea`.

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

## Explicitly not established

- No real Cloudflare account was registered or live WARP credentials used during
  CI. The fixture's WARP response validates the probe implementation, not
  Cloudflare availability or real enrollment.
- No production Ubuntu host was initially installed, rebooted or upgraded by the
  maintainer during the inspection above.
  Host dependency installation, real registration and failed live-release rollback
  still need staging acceptance; transaction logic was tested with controlled mocks.
- No controlled end-to-end Xray, sing-box or Hysteria client soak was executed;
  direct SOCKS UDP checks on the operating host do not replace that acceptance.
- Linux arm64 artifacts were cross-built and inspected, not run on arm64 hardware.
- No throughput, capacity, uptime guarantee, or MTU/QUIC root-cause claim is made.

Complete [ACCEPTANCE_TEST.md](ACCEPTANCE_TEST.md), including a staging soak with
real TCP/UDP clients, before deploying production traffic.
