#!/usr/bin/env bash
# Run only on an ephemeral Ubuntu Actions runner. Never uses WARP credentials.
set -Eeuo pipefail

[[ ${GITHUB_ACTIONS:-} == true && $EUID -eq 0 ]] || {
    echo 'This test requires root on an ephemeral GitHub Actions runner.' >&2
    exit 1
}
[[ $# -eq 2 && -f $1 && -f $2 ]] || {
    echo 'Usage: systemd_smoke.sh <built-supervisor> <built-fake-usque>' >&2
    exit 1
}
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
for path in /etc/usque /opt/usque /var/lib/usque /run/usque /etc/systemd/system/usque.service; do
    [[ ! -e $path ]] || { echo "Refusing to overwrite existing path: $path" >&2; exit 1; }
done
! id usque >/dev/null 2>&1 || { echo 'Refusing to use an existing usque account.' >&2; exit 1; }

cleanup() {
    local result=$?
    if (( result != 0 )); then
        systemctl status usque --no-pager || true
        journalctl -u usque --no-pager -n 100 || true
    fi
    systemctl stop usque || true
    systemctl disable usque >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/usque.service
    systemctl daemon-reload
    # These exact directories were checked absent before this test created them.
    rm -rf /etc/usque /opt/usque /var/lib/usque /run/usque
    userdel usque || true
    exit "$result"
}
trap cleanup EXIT

useradd --system --user-group --home-dir /var/lib/usque --shell /usr/sbin/nologin usque
install -d -m 0750 -o root -g usque /etc/usque
install -d -m 0755 /opt/usque/current
install -d -m 0750 -o usque -g usque /var/lib/usque
install -m 0755 "$1" /opt/usque/current/usque-supervisor
install -m 0755 "$2" /opt/usque/current/usque
GITHUB_ACTIONS=true /opt/usque/current/usque --init-ca /var/lib/usque
chown usque:usque /var/lib/usque/test-ca.crt /var/lib/usque/test-key.pem
install -m 0644 "$repo/deploy/usque.service" /etc/systemd/system/usque.service
cat > /etc/usque/service.env <<'ENV'
GITHUB_ACTIONS=true
SSL_CERT_FILE=/var/lib/usque/test-ca.crt
USQUE_BIND=127.0.0.1
USQUE_PORT=903
USQUE_MODE=socks
USQUE_HEALTH_URL=https://trace.invalid/cdn-cgi/trace
USQUE_HEALTH_INTERVAL=1s
USQUE_HEALTH_TIMEOUT=1s
USQUE_HEALTH_FAILURES=2
USQUE_SHUTDOWN_TIMEOUT=2s
USQUE_BACKOFF_MIN=1s
USQUE_BACKOFF_MAX=3s
USQUE_HEALTHY_RESET=10s
ENV
chown root:usque /etc/usque/service.env
chmod 0640 /etc/usque/service.env
systemd-analyze verify /etc/systemd/system/usque.service
systemctl daemon-reload
systemctl enable --now usque

state_value() {
    python3 - "$1" <<'PY'
import json, sys
with open('/run/usque/status.json', encoding='utf-8') as f:
    print(json.load(f)[sys.argv[1]])
PY
}

wait_healthy() {
    local old_child=${1:-0} old_supervisor=${2:-0}
    for _ in {1..60}; do
        if python3 - "$old_child" "$old_supervisor" <<'PY'
import datetime, json, sys
try:
    with open('/run/usque/status.json', encoding='utf-8') as f:
        s = json.load(f)
    age = (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(s['last_healthy_at'].replace('Z', '+00:00'))).total_seconds()
    assert s['status'] == 'healthy' and 0 <= age < 5
    assert s['child_pid'] > 0 and s['child_pid'] != int(sys.argv[1])
    assert s['supervisor_pid'] > 0 and s['supervisor_pid'] != int(sys.argv[2])
except (OSError, ValueError, KeyError, AssertionError):
    sys.exit(1)
PY
        then
            systemctl is-active --quiet usque
            return
        fi
        sleep 1
    done
    echo 'Timed out waiting for fresh end-to-end supervisor health.' >&2
    return 1
}

wait_healthy
supervisor=$(state_value supervisor_pid)
child=$(state_value child_pid)
[[ $(ps -o user= -p "$supervisor" | xargs) == usque ]]
[[ $(ps -o user= -p "$child" | xargs) == usque ]]
[[ $(ps -o ppid= -p "$child" | xargs) == "$supervisor" ]]
[[ $(ss -H -lnt 'sport = :903' | awk '{print $4}') == 127.0.0.1:903 ]]
python3 - "$child" <<'PY'
import sys
with open('/proc/' + sys.argv[1] + '/status', encoding='utf-8') as f:
    fields = dict(line.split(':', 1) for line in f if ':' in line)
assert int(fields['CapEff'].strip(), 16) == 1 << 10, 'only CAP_NET_BIND_SERVICE is needed'
PY
runuser -u usque -- env SSL_CERT_FILE=/var/lib/usque/test-ca.crt \
    USQUE_HEALTH_URL=https://trace.invalid/cdn-cgi/trace \
    /opt/usque/current/usque-supervisor health
echo 'PASS: hardened unit, ownership, loopback port 903, capabilities and real SOCKS HTTPS probe'

kill -KILL "$child"
wait_healthy "$child"
echo 'PASS: unexpected child exit recovery'
child=$(state_value child_pid)
kill -STOP "$child"
wait_healthy "$child"
if kill -0 "$child" 2>/dev/null; then echo 'Old hung child survived cleanup.' >&2; exit 1; fi
echo 'PASS: live hung child health failure recovery and cleanup'

supervisor=$(state_value supervisor_pid)
child=$(state_value child_pid)
kill -TERM "$supervisor"
wait_healthy "$child" "$supervisor"
if kill -0 "$child" 2>/dev/null; then echo 'Old child survived supervisor cleanup.' >&2; exit 1; fi
echo 'PASS: supervisor SIGTERM cleanup and systemd recovery'
journalctl -u usque --no-pager -n 30
