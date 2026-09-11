#!/usr/bin/env bash
# Shared implementation for the installed management tool. Sourcing this file
# defines functions only; tests substitute paths and system services explicitly.
REPO=GamerKhaan/usque
ROOT=/opt/usque
ETC=/etc/usque
STATE=/var/lib/usque
UNIT=/etc/systemd/system/usque.service
BIN=/usr/local/bin
SYSCTL_FILE=/etc/sysctl.d/90-usque-buffers.conf
READY_TIMEOUT=120

say() { printf '%s\n' "$*"; }
die() { say "usque: $*" >&2; exit 1; }
require_root() { [[ $EUID -eq 0 ]] || die 'this command requires sudo'; }
lock_operations() {
  mkdir -p /run/lock
  exec 9>/run/lock/usque.lock
  flock -n 9 || die 'another installation or management operation is running'
}

load_env() {
  local line key value
  export USQUE_CONFIG="$ETC/config.json" USQUE_BINARY="$ROOT/current/usque" USQUE_STATE=/run/usque/status.json
  export USQUE_BIND=127.0.0.1 USQUE_PORT=903 USQUE_MODE=socks USQUE_DNS=
  [[ -e $ETC/service.env ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    [[ $line =~ ^(USQUE_[A-Z0-9_]+)=(.*)$ ]] || { say 'Invalid service.env line; use KEY=value with no shell syntax.' >&2; return 1; }
    key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}
    case "$key" in
      USQUE_CONFIG|USQUE_BINARY|USQUE_STATE|USQUE_BIND|USQUE_PORT|USQUE_MODE|USQUE_DNS|USQUE_ALLOW_PUBLIC|USQUE_HEALTH_URL|USQUE_HEALTH_INTERVAL|USQUE_HEALTH_TIMEOUT|USQUE_HEALTH_FAILURES|USQUE_DIAL_TIMEOUT|USQUE_SHUTDOWN_TIMEOUT|USQUE_BACKOFF_MIN|USQUE_BACKOFF_MAX|USQUE_HEALTHY_RESET|USQUE_ALWAYS_RECONNECT|USQUE_MTU|USQUE_HTTP2) ;;
      *) say "Unsupported service.env key: $key" >&2; return 1 ;;
    esac
    # systemd EnvironmentFile and the management tool deliberately share this
    # simple format. Never execute configuration as shell code.
    [[ $value != *[[:space:]\"\'\`\$\\]* ]] || { say "Invalid service.env value for $key" >&2; return 1; }
    export "$key=$value"
  done < "$ETC/service.env"
  [[ $USQUE_CONFIG == "$ETC/config.json" && $USQUE_BINARY == "$ROOT/current/usque" ]] || {
    say 'Keep USQUE_CONFIG and USQUE_BINARY at their managed paths.' >&2; return 1;
  }
}

probe() { "$ROOT/current/usque-supervisor" health; }
wait_healthy() {
  local until_time=$((SECONDS + READY_TIMEOUT)) runtime main_pid
  while ((SECONDS < until_time)); do
    runtime=$("$ROOT/current/usque-supervisor" status 2>/dev/null) || runtime='{}'
    main_pid=$(systemctl show usque.service --property=MainPID --value) || main_pid=0
    if [[ $main_pid =~ ^[1-9][0-9]*$ ]] &&
       jq -e --argjson pid "$main_pid" '.status == "healthy" and .supervisor_pid == $pid' <<< "$runtime" >/dev/null 2>&1 &&
       systemctl is-active --quiet usque.service && probe >/dev/null 2>&1; then
      say "SOCKS5: ${USQUE_BIND:-127.0.0.1}:${USQUE_PORT:-903}"
      say 'Status: healthy'
      return 0
    fi
    sleep 3
  done
  say "HTTPS through SOCKS/WARP did not become healthy within ${READY_TIMEOUT}s." >&2
  say 'Inspect: sudo usquectl doctor; sudo usquectl logs' >&2
  return 1
}

show_version() {
  printf 'Release: '; cat "$ROOT/current/VERSION"
  "$ROOT/current/usque-supervisor" version
  "$ROOT/current/usque" version
  if [[ -L $ROOT/previous ]]; then printf 'Previous release: '; cat "$ROOT/previous/VERSION"; fi
}
show_status() {
  systemctl --no-pager --full status usque.service || true
  printf '\nSOCKS5: %s:%s\nMode: %s\n' "$USQUE_BIND" "$USQUE_PORT" "$USQUE_MODE"
  printf 'Configured DNS servers: %s\n' "${USQUE_DNS:-core defaults (Quad9)}"
  show_version
  "$ROOT/current/usque-supervisor" status || true
}
doctor() {
  local failures=0 current_permissions listeners protocol options
  say '=== Service and runtime ==='
  show_status || failures=$((failures + 1))
  if ! systemctl is-active --quiet usque.service; then
    say 'Managed usque.service is not active; an independent proxy probe cannot establish service health.'
    failures=$((failures + 1))
  fi
  say '=== Host ==='
  uname -sm
  if [[ -r /etc/os-release ]]; then grep -E '^(PRETTY_NAME|ID|VERSION_ID)=' /etc/os-release; fi
  say '=== Config (contents are never displayed) ==='
  if [[ -f $ETC/config.json ]]; then
    current_permissions=$(stat -c '%U:%G %a' "$ETC/config.json") || current_permissions=unreadable
    say "Config ownership/mode: $current_permissions; expected root:usque 640"
    [[ $current_permissions == 'root:usque 640' ]] || failures=$((failures + 1))
    "$ROOT/current/usque-supervisor" validate-config "$ETC/config.json" || failures=$((failures + 1))
  else
    say 'Config missing. Recovery: sudo usquectl register'
    failures=$((failures + 1))
  fi
  if [[ -f $ETC/service.env ]]; then
    current_permissions=$(stat -c '%U:%G %a' "$ETC/service.env") || current_permissions=unreadable
    say "Service environment ownership/mode: $current_permissions; expected root:usque 640"
    [[ $current_permissions == 'root:usque 640' ]] || failures=$((failures + 1))
  else
    say 'Service environment missing: /etc/usque/service.env'
    failures=$((failures + 1))
  fi
  say '=== TCP / UDP listeners ==='
  listeners=$(ss -H -lntu "sport = :$USQUE_PORT") || failures=$((failures + 1))
  say "$listeners"
  for protocol in TCP UDP; do
    [[ $protocol != UDP || $USQUE_MODE == socks ]] || continue
    if [[ $protocol == TCP ]]; then options=-lnt; else options=-lnu; fi
    # Let ss parse/canonicalize IPv4 and IPv6 addresses. A wildcard listener
    # must not satisfy a configured loopback bind; full socks also requires UDP.
    if ! listeners=$(ss -H "$options" "src = $USQUE_BIND and sport = :$USQUE_PORT"); then
      say "Cannot inspect the configured $protocol listener."
      failures=$((failures + 1))
    elif [[ -z $listeners ]]; then
      say "Missing $protocol listener on $USQUE_BIND:$USQUE_PORT."
      failures=$((failures + 1))
    fi
  done
  say '=== DNS through SOCKS and HTTPS/WARP data path ==='
  say "Configured DNS servers: ${USQUE_DNS:-core defaults (Quad9)}"
  probe || failures=$((failures + 1))
  say 'The HTTPS probe sends the target hostname to SOCKS. Full socks resolves it in the tunnel;'
  say 'l4-socks uses the core resolver behavior (currently local DNS by default).'
  say '=== UDP buffer ceilings ==='
  sysctl net.core.rmem_max net.core.wmem_max || true
  say 'Recommended minimum: 7500000 for each; larger values are preserved.'
  say '=== MTU / transport guidance ==='
  say "Configured MTU: ${USQUE_MTU:-1280}; HTTP/2: ${USQUE_HTTP2:-false}"
  say 'For reproducible HTTPS/TLS stalls with full socks at MTU 1280 (upstream #123),'
  say 'test USQUE_MTU=1200, then 1000 in /etc/usque/service.env and sudo usquectl restart.'
  say 'Compare HTTPS results and restore 1280 if this does not help. l4-socks is TCP only.'
  say 'The normal HTTPS probe does not test UDP relay functionality; test UDP from your actual client.'
  say '=== Recent journal warnings/errors ==='
  # Go log messages written to stderr are often classified as info by journald.
  journalctl -u usque.service --since '-15 min' --no-pager -n 200 |
    grep -Ei 'error|fail|timeout|timed out|unhealthy|restart|closed|martian|tunnel packet diagnostic' | tail -n 40 || true
  say "Doctor checks failed: $failures"
  ((failures == 0))
}

prepare_host() {
  local account_shell path
  for path in "$ROOT" "$ROOT/releases" "$ROOT/backups" "$ETC" "$ETC/backups" "$ETC/config.json" "$ETC/service.env" "$STATE"; do
    [[ ! -L $path ]] || die "refusing managed path that is a symlink: $path"
  done
  if ! id -u usque >/dev/null 2>&1; then
    useradd --system --user-group --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin usque || return 1
  fi
  [[ $(id -u usque) != 0 ]] || die 'the usque account must not be root'
  getent group usque >/dev/null || die 'the dedicated usque group is missing'
  [[ $(id -gn usque) == usque ]] || die 'the usque account must use the usque primary group'
  account_shell=$(getent passwd usque | cut -d: -f7)
  [[ $account_shell == /usr/sbin/nologin || $account_shell == /sbin/nologin || $account_shell == /bin/false ]] || die 'existing usque user must have a non-login shell'
  install -d -o root -g root -m 0755 "$ROOT" "$ROOT/releases" "$BIN" || return 1
  install -d -o root -g usque -m 0750 "$ETC" || return 1
  install -d -o root -g root -m 0700 "$ETC/backups" || return 1
  install -d -o usque -g usque -m 0750 "$STATE" || return 1
}

tune_buffers() {
  local key current content='' saved=''
  # Preserve entries written by a previous installation. Avoid reducing larger
  # runtime values even when this machine already has an older tuning file.
  for key in net.core.rmem_max net.core.wmem_max; do
    current=$(sysctl -n "$key") || return 1
    [[ $current =~ ^[0-9]+$ ]] || return 1
    if [[ -f $SYSCTL_FILE ]]; then
      saved=$(awk -v key="$key" '$1 == key && $2 == "=" {print $3}' "$SYSCTL_FILE")
    else saved=''; fi
    if ((current < 7500000)); then
      sysctl -w "$key=7500000" || return 1
      current=7500000
      content+="$key = $current"$'\n'
    elif [[ -n $saved ]]; then
      content+="$key = $current"$'\n'
    fi
  done
  if [[ -n $content ]]; then
    printf '# Managed by usquectl; UDP buffer ceilings only.\n%s' "$content" > "$SYSCTL_FILE.tmp" || return 1
    chmod 0644 "$SYSCTL_FILE.tmp" || return 1
    mv -f -- "$SYSCTL_FILE.tmp" "$SYSCTL_FILE" || return 1
  fi
}

validate_tag() { [[ $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; }
release_path() {
  local path tag
  path=$(readlink -f -- "$1") || return 1
  [[ $path == "$ROOT/releases/"* && -f $path/VERSION ]] || return 1
  tag=${path#"$ROOT/releases/"}
  validate_tag "$tag" && [[ $(cat "$path/VERSION") == "$tag" ]] || return 1
  printf '%s\n' "$path"
}
atomic_link() {
  local target=$1 link=$2
  ln -s -- "$target" "$link.new.$$" || return 1
  if ! mv -Tf -- "$link.new.$$" "$link"; then
    rm -f -- "$link.new.$$"
    return 1
  fi
}
files_equal() {
  local first second
  first=$(sha256sum -- "$1") && second=$(sha256sum -- "$2") && [[ ${first%% *} == "${second%% *}" ]]
}
store_release() {
  local source=$1 tag=$2 pending file
  validate_tag "$tag" || { say 'Unsupported release tag' >&2; return 1; }
  if [[ -d $ROOT/releases/$tag ]]; then
    # Versions are immutable. An interrupted prior download never reaches here.
    [[ $(cat "$ROOT/releases/$tag/VERSION") == "$tag" ]] || return 1
    for file in usque usque-supervisor usquectl deploy/lib.sh deploy/service.env deploy/usque.service LICENSE.md README.md; do
      if [[ ! -f $ROOT/releases/$tag/$file || -L $ROOT/releases/$tag/$file ]] ||
         ! files_equal "$source/$file" "$ROOT/releases/$tag/$file"; then
        say "Cached release $tag differs from its verified artifact; refusing to overwrite it." >&2
        return 1
      fi
    done
    return 0
  fi
  pending=$(mktemp -d "$ROOT/releases/.pending.XXXXXX") || return 1
  if ! install -m 0755 "$source/usque" "$source/usque-supervisor" "$source/usquectl" "$pending/" ||
     ! install -m 0644 "$source/LICENSE.md" "$source/README.md" "$pending/" ||
     ! install -d -m 0755 "$pending/deploy" ||
     ! install -m 0644 "$source/deploy/lib.sh" "$source/deploy/service.env" "$source/deploy/usque.service" "$pending/deploy/"; then
    rm -rf -- "$pending"
    return 1
  fi
  if ! printf '%s\n' "$tag" > "$pending/VERSION" ||
     ! chmod 0644 "$pending/VERSION" || ! chmod 0755 "$pending" ||
     ! chown -R root:root "$pending" || ! mv -- "$pending" "$ROOT/releases/$tag"; then
    rm -rf -- "$pending"
    return 1
  fi
}

install_links() {
  local executable
  for executable in usque usque-supervisor usquectl; do
    backup_existing_link "$BIN/$executable" "$ROOT/current/$executable" || return 1
    atomic_link "$ROOT/current/$executable" "$BIN/$executable" || return 1
  done
  backup_existing_link "$UNIT" "$ROOT/current/deploy/usque.service" || return 1
  atomic_link "$ROOT/current/deploy/usque.service" "$UNIT"
}
backup_existing_link() {
  local path=$1 expected=$2
  if [[ -e $path || -L $path ]]; then
    [[ ! -d $path || -L $path ]] || die "refusing to replace directory: $path"
    if [[ ! -L $path || $(readlink -- "$path") != "$expected" ]]; then
      install -d -o root -g root -m 0700 "$ROOT/backups" || return 1
      cp -a -- "$path" "$ROOT/backups/$(basename -- "$path").$(date -u +%Y%m%dT%H%M%S).$$" || return 1
    fi
  fi
}
switch_release() {
  local next=$1 old=${2:-} previous_before='' reason='New release failed health validation.'
  # Older management tools reject unknown service.env keys even when their
  # supervisor ignores them. Reject an incompatible switch before changing the
  # active release instead of leaving rollback management unusable.
  if [[ -f $ETC/service.env ]] && grep -q '^USQUE_DNS=' "$ETC/service.env" &&
     ! grep -qw 'USQUE_DNS' "$next/deploy/lib.sh"; then
    say 'Target release does not support USQUE_DNS. Current release was not changed.' >&2
    say 'Back up /etc/usque/service.env, remove its USQUE_DNS line (restoring core DNS defaults), then retry rollback.' >&2
    return 1
  fi
  if [[ -L $ROOT/previous ]]; then
    previous_before=$(release_path "$ROOT/previous") || { say 'Previous release metadata is invalid; refusing activation.' >&2; return 1; }
  elif [[ -e $ROOT/previous ]]; then
    say 'Previous release metadata must be a managed symlink.' >&2
    return 1
  fi
  if ! atomic_link "$next" "$ROOT/current"; then
    say 'Could not activate the new release; current release was not changed.' >&2
    return 1
  fi
  if systemctl daemon-reload && systemctl restart usque.service && wait_healthy; then
    if [[ -z $old || $old == "$next" ]] || atomic_link "$old" "$ROOT/previous"; then
      say "Active release: $(cat "$next/VERSION")"
      return 0
    fi
    reason='New release was healthy, but publishing previous-version metadata failed.'
  fi
  say "$reason Restoring the previous release." >&2
  if [[ -n $old ]]; then
    if ! atomic_link "$old" "$ROOT/current"; then
      say "CRITICAL: could not restore current release to $old. Service will be disabled." >&2
      systemctl disable --now usque.service || say 'CRITICAL: disabling the service also failed; stop it manually.' >&2
      return 1
    fi
    if [[ -n $previous_before ]]; then
      atomic_link "$previous_before" "$ROOT/previous" || say 'Previous-version metadata could not be restored; current binaries were restored.' >&2
    elif [[ -L $ROOT/previous ]]; then
      rm -f -- "$ROOT/previous" || say 'Could not remove incomplete previous-version metadata.' >&2
    fi
    if ! systemctl daemon-reload || ! systemctl restart usque.service || ! wait_healthy; then
      say 'Previous release restored, but it is also unhealthy; inspect usquectl doctor.' >&2
    fi
  else
    systemctl disable --now usque.service || true
    say 'Service disabled because initial end-to-end validation failed.' >&2
  fi
  return 1
}

register_config() {
  local stage result=0
  if [[ -e $ETC/config.json ]]; then
    say 'Existing config preserved. Use import-config to replace it explicitly.'
    "$ROOT/current/usque-supervisor" validate-config "$ETC/config.json"
    return
  fi
  # The service user can traverse this root-owned parent but cannot rename its
  # children or replace the root-owned log/candidate. The account subdirectory
  # is the only writable staging area exposed to the registration process.
  stage=$(mktemp -d "$ETC/.registration.XXXXXX") || return 1
  if ! chown root:usque "$stage" || ! chmod 0710 "$stage" ||
     ! install -d -o usque -g usque -m 0700 "$stage/account"; then
    rm -rf -- "$stage"
    return 1
  fi
  say 'Registering personal WARP using the upstream flow and Cloudflare application terms:'
  say 'https://www.cloudflare.com/application/terms/'
  # The staged account is never placed in production until structural validation
  # succeeds. Upstream output is not copied into a potentially public terminal.
  timeout --signal=TERM --kill-after=8s 120s runuser -u usque -- \
    "$ROOT/current/usque" -c "$stage/account/config.json" register --accept-tos > "$stage/registration.log" 2>&1 || result=$?
  # Read using the service user's permissions into a root-owned immutable copy:
  # even a replaced/symlinked source cannot make root disclose another secret.
  if ((result == 0)); then
    timeout --signal=TERM --kill-after=8s 8s runuser -u usque -- \
      head -c 1048577 -- "$stage/account/config.json" > "$stage/candidate.json" || result=$?
  fi
  if ((result != 0)) || ! "$ROOT/current/usque-supervisor" validate-config "$stage/candidate.json"; then
    rm -rf -- "$stage"
    say "WARP registration failed (exit $result). Check host internet access and registration rate limits." >&2
    say 'Recovery: sudo usquectl register' >&2
    return 1
  fi
  if ! install -o root -g usque -m 0640 "$stage/candidate.json" "$ETC/config.json.new" ||
     ! mv -f -- "$ETC/config.json.new" "$ETC/config.json"; then
    rm -rf -- "$stage"
    return 1
  fi
  rm -rf -- "$stage"
}

import_config() {
  local source=$1 backup='' had_config=false
  [[ -f $source && ! -L $source ]] || { say 'Import requires a regular config file.' >&2; return 1; }
  # Stage with root-only access before validating. Refuse a swapped symlink and
  # cap input size so an untrusted source cannot disclose root-readable data to
  # the service group or fill the filesystem while root imports it.
  install -o root -g root -m 0600 /dev/null "$ETC/config.json.import" || return 1
  if ! dd if="$source" of="$ETC/config.json.import" iflag=nofollow,count_bytes count=1048577 status=none; then
    rm -f -- "$ETC/config.json.import"
    return 1
  fi
  if ! "$ROOT/current/usque-supervisor" validate-config "$ETC/config.json.import"; then
    rm -f -- "$ETC/config.json.import"
    return 1
  fi
  if [[ -f $ETC/config.json ]]; then
    had_config=true
    backup=$(mktemp "$ETC/backups/config.XXXXXXXX.json") || return 1
    install -o root -g root -m 0600 "$ETC/config.json" "$backup" || return 1
  fi
  chown root:usque "$ETC/config.json.import" && chmod 0640 "$ETC/config.json.import" || return 1
  mv -f -- "$ETC/config.json.import" "$ETC/config.json" || return 1
  if systemctl restart usque.service && wait_healthy; then
    say 'Config import is healthy.'
    return 0
  fi
  say 'Imported config failed end-to-end validation; restoring the previous config.' >&2
  if $had_config; then
    if ! install -o root -g usque -m 0640 "$backup" "$ETC/config.json.restore" ||
       ! mv -f -- "$ETC/config.json.restore" "$ETC/config.json"; then
      say "CRITICAL: restoring the prior config failed. Backup retained at $backup. Service will be disabled." >&2
      systemctl disable --now usque.service || say 'CRITICAL: disabling the service also failed; stop it manually.' >&2
      return 1
    fi
    if ! systemctl restart usque.service || ! wait_healthy; then say 'Previous config restored but service is unhealthy; run usquectl doctor.' >&2; fi
  else
    rm -f -- "$ETC/config.json" || say 'Could not remove the invalid imported config.' >&2
    systemctl stop usque.service || true
  fi
  return 1
}

install_release() {
  local source=$1 tag=$2 old=''
  prepare_host || return 1
  if [[ -L $ROOT/current ]]; then
    old=$(release_path "$ROOT/current") || { say 'Current release metadata is invalid; refusing installation.' >&2; return 1; }
  elif [[ -e $ROOT/current ]]; then
    say 'Current release must be a managed symlink; refusing to replace this path.' >&2
    return 1
  fi
  store_release "$source" "$tag" || return 1
  if [[ ! -e $ETC/service.env ]]; then install -o root -g usque -m 0640 "$source/deploy/service.env" "$ETC/service.env" || return 1; fi
  if [[ -e $ETC/config.json ]]; then chown root:usque "$ETC/config.json" && chmod 0640 "$ETC/config.json" || return 1; fi
  load_env || return 1
  tune_buffers || return 1
  # Registration uses the new binary on first installation; existing production
  # releases remain active until their replacement has been fully staged.
  if [[ -z $old ]]; then atomic_link "$ROOT/releases/$tag" "$ROOT/current" || return 1; fi
  install_links || return 1
  systemctl daemon-reload || return 1
  if ! register_config; then
    [[ -n $old ]] || systemctl disable --now usque.service || true
    return 1
  fi
  systemctl enable usque.service || return 1
  switch_release "$ROOT/releases/$tag" "$old" || return 1
  say 'Manage: sudo usquectl status | health | doctor | logs | restart | update | rollback'
}

fetch() { curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --retry 3 "$1" -o "$2"; }
latest_release() {
  local output=$1
  fetch "https://api.github.com/repos/$REPO/releases/latest" "$output" || return 1
  jq -er '.tag_name' "$output"
}
download_release() {
  local work=$1 tag=$2 arch artifact base hash
  validate_tag "$tag" || return 1
  case $(uname -m) in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) return 1;; esac
  artifact="usque_${tag#v}_linux_${arch}.tar.gz"
  base="https://github.com/$REPO/releases/download/$tag"
  fetch "$base/$artifact" "$work/$artifact" || return 1
  fetch "$base/checksums.txt" "$work/checksums.txt" || return 1
  hash=$(awk -v file="$artifact" '$2 == file || $2 == "*" file {print $1}' "$work/checksums.txt")
  [[ $hash =~ ^[0-9a-fA-F]{64}$ ]] || { say 'Missing or ambiguous checksum' >&2; return 1; }
  printf '%s  %s\n' "$hash" "$work/$artifact" | sha256sum --check --status || { say 'Checksum mismatch' >&2; return 1; }
  tar -tzf "$work/$artifact" > "$work/paths" || return 1
  if LC_ALL=C grep -Eq '(^/|(^|/)\.\.(/|$)|\\)' "$work/paths"; then return 1; fi
  tar -tvzf "$work/$artifact" > "$work/modes" || return 1
  if LC_ALL=C grep -Eq '^[^-d]' "$work/modes"; then return 1; fi
  mkdir "$work/payload" || return 1
  tar -xzf "$work/$artifact" --no-same-owner --no-same-permissions -C "$work/payload" -- \
    usque usque-supervisor usquectl deploy/lib.sh deploy/service.env deploy/usque.service LICENSE.md README.md
}
update_release() {
  local work tag old result=0
  old=$(release_path "$ROOT/current") || die 'no valid current release'
  work=$(mktemp -d) || return 1
  tag=$(latest_release "$work/release.json") || { rm -rf -- "$work"; return 1; }
  validate_tag "$tag" || { rm -rf -- "$work"; die 'unsupported release tag'; }
  if [[ $(cat "$old/VERSION") == "$tag" ]]; then
    rm -rf -- "$work"
    say "Already using $tag."
    probe
    return
  fi
  if download_release "$work" "$tag" && store_release "$work/payload" "$tag"; then
    switch_release "$ROOT/releases/$tag" "$old" || result=$?
  else result=1; fi
  rm -rf -- "$work"
  return "$result"
}
rollback_release() {
  local old next
  old=$(release_path "$ROOT/current") || die 'no valid current release'
  next=$(release_path "$ROOT/previous") || die 'no previous known-good release is available'
  [[ $old != "$next" ]] || die 'current and previous release are identical'
  switch_release "$next" "$old"
}
uninstall_service() {
  local executable
  systemctl disable --now usque.service
  rm -f -- "$UNIT"
  for executable in usque usque-supervisor usquectl; do
    if [[ -L $BIN/$executable && $(readlink -- "$BIN/$executable") == "$ROOT/current/$executable" ]]; then rm -f -- "$BIN/$executable"; fi
  done
  systemctl daemon-reload
  # Retain accounts, releases, config, backups and current buffer limits. This
  # makes uninstall reversible and avoids silently destroying credentials.
  say 'Service and command links removed. Configuration/backups in /etc/usque and releases in /opt/usque are preserved.'
  say 'UDP buffer ceilings and the dedicated system account are preserved. Reinstall to restore service.'
}
