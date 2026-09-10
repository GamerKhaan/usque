# Ubuntu acceptance checklist

Run on a staging Ubuntu amd64/arm64 host with systemd and real WARP credentials,
before moving production traffic. Record release/SHA, Ubuntu/kernel/architecture,
client versions, date, and actual output. This document is a test procedure,
not an assertion that a live acceptance run has passed. CI uses local fixtures.

## Install, ownership and readiness

```bash
curl -fsSL https://raw.githubusercontent.com/GamerKhaan/usque/main/install.sh | sudo bash
sudo usquectl version
sudo systemctl is-enabled usque
sudo systemctl is-active usque
sudo usquectl status
sudo usquectl health
sudo usquectl doctor
sudo systemctl show usque -p MainPID -p User -p Group -p AmbientCapabilities -p CapabilityBoundingSet
sudo ps -eo user,pid,ppid,args | grep '[u]sque'
sudo ss -lntup 'sport = :903'
sudo stat -c '%U:%G %a %n' /etc/usque /etc/usque/config.json /etc/usque/service.env
```

Expected: service enabled/active; supervisor and child owned by `usque`; only
`CAP_NET_BIND_SERVICE`; full SOCKS TCP and UDP bound to **127.0.0.1:903**, with
no wildcard or IPv6 listener on this port; config and service.env `root:usque 640`;
directory `root:usque 750`; status and new probe healthy. Inspect the entire
listener list with `sudo ss -lntup` for unexpected binds.

```bash
curl --fail --show-error --silent --max-time 15 \
  --socks5-hostname 127.0.0.1:903 https://www.cloudflare.com/cdn-cgi/trace
```

Require HTTP success and `warp=on` or `warp=plus`. This is a diagnostic curl test;
the running supervisor uses Go and does not require curl. Exercise HTTPS to your
actual destinations and UDP through the actual Xray/sing-box/Hysteria chain.
Record concurrent load, latency and RSS without exposing credentials.

## Child death and alive-but-hung recovery

```bash
child_before=$(sudo jq -r .child_pid /run/usque/status.json)
sudo kill -KILL "$child_before"
sleep 35
sudo usquectl status
sudo usquectl health
child_after=$(sudo jq -r .child_pid /run/usque/status.json)
test "$child_before" != "$child_after"
```

Require a new child PID, increased restart count, healthy HTTPS, and no remaining
old child. Verify journald records the exit and backoff.

To simulate a child that remains alive while all data handling hangs:

```bash
stuck_child=$(sudo jq -r .child_pid /run/usque/status.json)
sudo kill -STOP "$stuck_child"
sleep 120
sudo usquectl status
sudo usquectl health
! sudo kill -0 "$stuck_child" 2>/dev/null
```

Require three failed probes, timeout-bound shutdown/forced cleanup, restart and
recovery. If a check fails, explicitly `sudo kill -CONT "$stuck_child"` if it
still exists before further troubleshooting.

## Supervisor death and systemd recovery

```bash
supervisor_before=$(systemctl show usque -p MainPID --value)
sudo systemctl kill --kill-whom=main --signal=TERM usque
sleep 35
supervisor_after=$(systemctl show usque -p MainPID --value)
test "$supervisor_before" != "$supervisor_after"
sudo usquectl health
sudo journalctl -u usque --since '-5 minutes' --no-pager
```

Require child cleanup, a new supervisor, and healthy service. A deliberate
`systemctl stop` does not exercise automatic restart; it is an administrative stop.

## Temporary external network failure

Use a console-accessible staging VM. Block only packets owned by the `usque`
account, preserving loopback and the administrator's SSH session. Set a cleanup
trap before adding the temporary nftables table:

```bash
sudo bash <<'SH'
set -euo pipefail
if nft list table inet usque_acceptance >/dev/null 2>&1; then
  echo 'Refusing to modify an existing acceptance table.' >&2
  exit 1
fi
trap 'nft delete table inet usque_acceptance 2>/dev/null || true' EXIT
uid=$(id -u usque)
nft add table inet usque_acceptance
nft 'add chain inet usque_acceptance output { type filter hook output priority 0; policy accept; }'
nft add rule inet usque_acceptance output meta skuid "$uid" oifname != lo drop
sleep 10
nft delete table inet usque_acceptance
trap - EXIT
SH
sleep 35
sudo usquectl health
sudo usquectl status
```

Do not run if that table already exists. nftables must be installed for this test.
For a 10-second interruption, expect recovery without an unnecessary restart if
fewer than three probes failed. Repeat for 120 seconds to exercise sustained
failure and bounded backoff. Confirm host recovery and useful logs after removal.

## Reinstall, imports, updates and rollback

```bash
before=$(sudo sha256sum /etc/usque/config.json)
curl -fsSL https://raw.githubusercontent.com/GamerKhaan/usque/main/install.sh | sudo bash
test "$before" = "$(sudo sha256sum /etc/usque/config.json)"
sudo usquectl health
sudo usquectl update
sudo usquectl version
sudo usquectl health
sudo usquectl rollback
sudo usquectl version
sudo usquectl health
test "$before" = "$(sudo sha256sum /etc/usque/config.json)"
```

An actual update/rollback requires two distinct fork releases. On the first
release, expect `rollback` to report no previous version; do not record a pass for
an unavailable scenario. To exercise automatic failed-release rollback, use an
isolated test release source and a candidate whose child fails its probe; do not
publish a deliberately broken release to the public latest-release channel.
The local deployment transaction tests cover this condition with controlled
fixtures: `bash tests/deployment_test.sh`.

For config imports, use a private staged copy. First try an invalid JSON file:
expect nonzero and byte-for-byte preservation of the current config. Then import
a structurally valid but unusable staging WARP config: expect failed HTTPS and
automatic restoration from the protected backup. Never print config contents.

## Reboot

```bash
sudo reboot
# After reconnecting:
sudo systemctl is-active usque
sudo usquectl status
sudo usquectl health
```

Require automatic service startup and HTTPS/WARP recovery without starting any
manual shell process. Finish with at least a 24-hour staging soak across idle
periods, mixed TCP/UDP traffic, network interruption, and repeat TLS transfers.
