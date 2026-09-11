#!/usr/bin/env bash
# Tests use a private temporary filesystem and shell mocks. Never invoke the
# installer against the host filesystem or real systemd/Cloudflare services.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

if [[ ${1:-} != --case ]]; then
  for script in "$repo/install.sh" "$repo/scripts/usquectl" "$repo/deploy/lib.sh"; do bash -n "$script"; done
  cases=(env_defaults env_injection env_unknown env_dns env_dns_legacy env_dns_injection
    atomic_switch switch_rollback switch_success switch_restart_error switch_unsupported_dns switch_supported_dns
    switch_activate_error switch_previous_error switch_restore_error
    import_invalid import_rollback import_success import_restore_error register_preserves register_failure
    buffers_increase buffers_preserve archive_valid archive_bad_checksum archive_link
    archive_traversal release_immutable update_failure update_success rollback_failure install_links_error install_idempotent
    doctor_healthy doctor_inactive doctor_missing_udp doctor_wrong_bind doctor_ss_failure doctor_l4 doctor_ipv6 doctor_env_permissions)
  passed=0
  for test_name in "${cases[@]}"; do
    if bash "$0" --case "$test_name"; then
      printf 'PASS %s\n' "$test_name"
      passed=$((passed + 1))
    else printf 'FAIL %s\n' "$test_name" >&2; exit 1; fi
  done
  printf '%s deployment tests passed\n' "$passed"
  exit 0
fi

# shellcheck source=deploy/lib.sh
source "$repo/deploy/lib.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
ROOT="$work/opt/usque"
ETC="$work/etc/usque"
STATE="$work/var/lib/usque"
BIN="$work/usr/local/bin"
UNIT="$work/systemd/usque.service"
SYSCTL_FILE="$work/sysctl.conf"
mkdir -p "$ROOT/releases/v1.0.0" "$ROOT/releases/v2.0.0" "$ROOT/releases/v0.9.0" "$ETC/backups" "$STATE" "$BIN" "$(dirname "$UNIT")"
printf 'v1.0.0\n' > "$ROOT/releases/v1.0.0/VERSION"
printf 'v2.0.0\n' > "$ROOT/releases/v2.0.0/VERSION"
printf 'v0.9.0\n' > "$ROOT/releases/v0.9.0/VERSION"
for version in v1.0.0 v2.0.0 v0.9.0; do
  mkdir -p "$ROOT/releases/$version/deploy"
  cp "$repo/deploy/lib.sh" "$ROOT/releases/$version/deploy/lib.sh"
done
atomic_link "$ROOT/releases/v1.0.0" "$ROOT/current"
atomic_link "$ROOT/releases/v0.9.0" "$ROOT/previous"
cat > "$ROOT/releases/v1.0.0/usque-supervisor" <<'MOCK'
#!/usr/bin/env bash
case $1 in
  validate-config) [[ -f $2 ]] && grep -q '"valid":true' "$2" ;;
  health) exit 0 ;;
  *) exit 1 ;;
esac
MOCK
chmod +x "$ROOT/releases/v1.0.0/usque-supervisor"
cp "$ROOT/releases/v1.0.0/usque-supervisor" "$ROOT/releases/v2.0.0/"

assert_equal() { [[ $1 == "$2" ]] || { printf 'Expected <%s>, got <%s>\n' "$2" "$1" >&2; exit 1; }; }
assert_fails() { if "$@"; then printf 'Unexpected success: %s\n' "$*" >&2; exit 1; fi; }
systemctl() { printf '%s\n' "$*" >> "$work/systemctl.calls"; }
chown() { :; }
# MSYS has no O_NOFOLLOW and maps POSIX mode 0710 poorly onto inherited Windows
# ACLs. Linux CI exercises both real flags/modes; the Windows transaction run
# retains bounded copies and substitutes a private owner-only staging mode.
fixture_msys=false
case $(uname -s) in
  MSYS*|MINGW*)
    fixture_msys=true
    dd() {
      local args=() arg
      for arg in "$@"; do
        [[ $arg != iflag=nofollow,count_bytes ]] || arg=iflag=count_bytes
        args+=("$arg")
      done
      command dd "${args[@]}"
    }
    chmod() {
      if [[ $1 == 0710 ]]; then shift; command chmod 0700 "$@"
      else command chmod "$@"; fi
    }
    ;;
esac
# Keep real install/mv/ln behavior but do not require privileged ownership or a
# host user named usque. Ownership is separately checked in Ubuntu acceptance.
install() {
  local args=()
  while (($#)); do
    case $1 in -o|-g) shift 2;; *) args+=("$1"); shift;; esac
  done
  if $fixture_msys && [[ " ${args[*]} " == *' -d '* ]]; then
    # MSYS install -d cannot chmod some nested directories on Windows ACLs.
    local dirs=()
    set -- "${args[@]}"
    while (($#)); do
      case $1 in -d) shift;; -m) shift 2;; *) dirs+=("$1"); shift;; esac
    done
    command mkdir -p "${dirs[@]}"
  else command install "${args[@]}"; fi
}
wait_healthy() { [[ $(cat "$ROOT/current/VERSION") != v2.0.0 ]]; }

case $2 in
  doctor_*)
    scenario=$2
    load_env
    printf '{"valid":true}\n' > "$ETC/config.json"
    printf 'USQUE_PORT=903\n' > "$ETC/service.env"
    [[ $scenario != doctor_l4 ]] || USQUE_MODE=l4-socks
    [[ $scenario != doctor_ipv6 ]] || USQUE_BIND=::1
    show_status() { :; }
    stat() {
      if [[ $scenario == doctor_env_permissions && ${*: -1} == "$ETC/service.env" ]]; then
        printf 'root:root 644\n'
      else printf 'root:usque 640\n'; fi
    }
    systemctl() { [[ $scenario != doctor_inactive ]]; }
    sysctl() { :; }
    journalctl() { :; }
    ss() {
      [[ $scenario != doctor_ss_failure ]] || return 1
      if [[ $* == *'src = '* ]]; then
        [[ $* == *"src = $USQUE_BIND and sport = :903"* ]] || return 1
        [[ $scenario != doctor_wrong_bind ]] || return 0
        if [[ $* == *'-lnu'* && ( $scenario == doctor_missing_udp || $scenario == doctor_l4 ) ]]; then return 0; fi
      fi
      printf 'LISTEN 0 128 %s:903 *:*\n' "$USQUE_BIND"
    }
    case $scenario in
      doctor_healthy|doctor_l4|doctor_ipv6) doctor > "$work/doctor.log" ;;
      *) assert_fails doctor > "$work/doctor.log" ;;
    esac
    ;;
  env_defaults)
    cp "$repo/deploy/service.env" "$ETC/service.env"
    # Managed paths differ only inside this temporary fixture.
    sed -i "s|/etc/usque/config.json|$ETC/config.json|;s|/opt/usque/current/usque|$ROOT/current/usque|" "$ETC/service.env"
    load_env
    assert_equal "$USQUE_PORT" 903
    assert_equal "$USQUE_MODE" socks
    assert_equal "$USQUE_HTTP2" false
    assert_equal "$USQUE_DNS" ''
    ;;
  env_injection)
    # Intentionally literal shell syntax tests that configuration is never run.
    # shellcheck disable=SC2016
    printf 'USQUE_PORT=$(touch %s/EXECUTED)\n' "$work" > "$ETC/service.env"
    assert_fails load_env
    [[ ! -e $work/EXECUTED ]]
    ;;
  env_unknown)
    printf 'LD_PRELOAD=/tmp/evil.so\n' > "$ETC/service.env"
    assert_fails load_env
    ;;
  env_dns)
    printf 'USQUE_DNS=1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001\n' > "$ETC/service.env"
    load_env
    assert_equal "$USQUE_DNS" '1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001'
    ;;
  env_dns_legacy)
    # An existing environment from an older installation needs no new key.
    printf 'USQUE_MODE=l4-socks\nUSQUE_PORT=903\n' > "$ETC/service.env"
    export USQUE_DNS=192.0.2.53
    load_env
    assert_equal "$USQUE_DNS" ''
    assert_equal "$USQUE_MODE" l4-socks
    rm "$ETC/service.env"
    export USQUE_DNS=192.0.2.53
    load_env
    assert_equal "$USQUE_DNS" ''
    ;;
  env_dns_injection)
    # shellcheck disable=SC2016
    printf 'USQUE_DNS=$(touch %s/EXECUTED)\n' "$work" > "$ETC/service.env"
    assert_fails load_env
    [[ ! -e $work/EXECUTED ]]
    ;;
  atomic_switch)
    atomic_link "$ROOT/releases/v2.0.0" "$ROOT/current"
    assert_equal "$(cat "$ROOT/current/VERSION")" v2.0.0
    ;;
  switch_rollback)
    assert_fails switch_release "$ROOT/releases/v2.0.0" "$ROOT/releases/v1.0.0"
    assert_equal "$(cat "$ROOT/current/VERSION")" v1.0.0
    assert_equal "$(cat "$ROOT/previous/VERSION")" v0.9.0
    assert_equal "$(grep -c '^restart' "$work/systemctl.calls")" 2
    ;;
  switch_success)
    wait_healthy() { return 0; }
    switch_release "$ROOT/releases/v2.0.0" "$ROOT/releases/v1.0.0"
    assert_equal "$(cat "$ROOT/current/VERSION")" v2.0.0
    assert_equal "$(cat "$ROOT/previous/VERSION")" v1.0.0
    ;;
  switch_unsupported_dns)
    printf '# Older release without DNS service settings\n' > "$ROOT/releases/v0.9.0/deploy/lib.sh"
    for dns in '' '1.1.1.1,1.0.0.1'; do
      printf 'USQUE_DNS=%s\n' "$dns" > "$ETC/service.env"
      cp "$ETC/service.env" "$work/env.before"
      assert_fails rollback_release
      assert_equal "$(cat "$ROOT/current/VERSION")" v1.0.0
      assert_equal "$(cat "$ROOT/previous/VERSION")" v0.9.0
      files_equal "$ETC/service.env" "$work/env.before"
      [[ ! -e $work/systemctl.calls ]]
    done
    # Removing the unsupported key deliberately restores the old defaults.
    printf '# Prior settings restored\n' > "$ETC/service.env"
    rollback_release
    assert_equal "$(cat "$ROOT/current/VERSION")" v0.9.0
    ;;
  switch_supported_dns)
    printf 'USQUE_DNS=1.1.1.1,1.0.0.1\n' > "$ETC/service.env"
    cp "$ETC/service.env" "$work/env.before"
    wait_healthy() { return 0; }
    switch_release "$ROOT/releases/v2.0.0" "$ROOT/releases/v1.0.0"
    assert_equal "$(cat "$ROOT/current/VERSION")" v2.0.0
    files_equal "$ETC/service.env" "$work/env.before"
    ;;
  switch_restart_error)
    systemctl() {
      printf '%s\n' "$*" >> "$work/systemctl.calls"
      [[ $1 != restart || $(cat "$ROOT/current/VERSION") != v2.0.0 ]]
    }
    assert_fails switch_release "$ROOT/releases/v2.0.0" "$ROOT/releases/v1.0.0"
    assert_equal "$(cat "$ROOT/current/VERSION")" v1.0.0
    assert_equal "$(cat "$ROOT/previous/VERSION")" v0.9.0
    assert_equal "$(grep -c '^restart' "$work/systemctl.calls")" 2
    ;;
  switch_activate_error|switch_previous_error|switch_restore_error)
    # Wrap the real filesystem mutation so failure injection covers precisely
    # one operation while all successful transitions still use real symlinks.
    eval "$(declare -f atomic_link | sed '1s/atomic_link/real_atomic_link/')"
    failure_case=$2
    atomic_link() {
      if [[ $failure_case == switch_activate_error && $2 == "$ROOT/current" ]]; then return 1; fi
      if [[ $failure_case == switch_previous_error && $1 == "$ROOT/releases/v1.0.0" && $2 == "$ROOT/previous" ]]; then return 1; fi
      if [[ $failure_case == switch_restore_error && $1 == "$ROOT/releases/v1.0.0" && $2 == "$ROOT/current" ]]; then return 1; fi
      real_atomic_link "$@"
    }
    if [[ $2 == switch_previous_error ]]; then wait_healthy() { return 0; }; fi
    assert_fails switch_release "$ROOT/releases/v2.0.0" "$ROOT/releases/v1.0.0"
    if [[ $2 == switch_restore_error ]]; then
      assert_equal "$(cat "$ROOT/current/VERSION")" v2.0.0
      grep -q '^disable --now usque.service$' "$work/systemctl.calls"
      assert_equal "$(grep -c '^restart' "$work/systemctl.calls")" 1
    else assert_equal "$(cat "$ROOT/current/VERSION")" v1.0.0; fi
    assert_equal "$(cat "$ROOT/previous/VERSION")" v0.9.0
    ;;
  import_invalid)
    printf '{"valid":true,"old":true}\n' > "$ETC/config.json"
    printf 'invalid\n' > "$work/import.json"
    assert_fails import_config "$work/import.json"
    grep -q '"old":true' "$ETC/config.json"
    [[ ! -e $work/systemctl.calls && ! -e $ETC/config.json.import ]]
    ;;
  import_rollback)
    printf '{"valid":true,"old":true}\n' > "$ETC/config.json"
    printf '{"valid":true,"new":true}\n' > "$work/import.json"
    wait_healthy() { grep -q '"old":true' "$ETC/config.json"; }
    assert_fails import_config "$work/import.json"
    grep -q '"old":true' "$ETC/config.json"
    assert_equal "$(find "$ETC/backups" -type f | wc -l | tr -d ' ')" 1
    assert_equal "$(grep -c '^restart' "$work/systemctl.calls")" 2
    ;;
  import_success)
    printf '{"valid":true,"old":true}\n' > "$ETC/config.json"
    printf '{"valid":true,"new":true}\n' > "$work/import.json"
    wait_healthy() { return 0; }
    import_config "$work/import.json"
    grep -q '"new":true' "$ETC/config.json"
    grep -q '"old":true' "$ETC"/backups/*
    ;;
  import_restore_error)
    printf '{"valid":true,"old":true}\n' > "$ETC/config.json"
    printf '{"valid":true,"new":true}\n' > "$work/import.json"
    wait_healthy() { return 1; }
    eval "$(declare -f install | sed '1s/install/real_install/')"
    install() {
      [[ ${*: -1} != "$ETC/config.json.restore" ]] || return 1
      real_install "$@"
    }
    assert_fails import_config "$work/import.json"
    grep -q '^disable --now usque.service$' "$work/systemctl.calls"
    assert_equal "$(grep -c '^restart' "$work/systemctl.calls")" 1
    grep -q '"old":true' "$ETC"/backups/*
    ;;
  register_preserves)
    printf '{"valid":true,"old":true}\n' > "$ETC/config.json"
    timeout() { say 'registration must not run' >&2; return 99; }
    register_config
    grep -q '"old":true' "$ETC/config.json"
    ;;
  register_failure)
    timeout() { return 7; }
    assert_fails register_config
    [[ ! -e $ETC/config.json ]]
    assert_equal "$(find "$STATE" -mindepth 1 | wc -l | tr -d ' ')" 0
    assert_equal "$(find "$ETC" -name '.registration.*' | wc -l | tr -d ' ')" 0
    ;;
  buffers_increase|buffers_preserve)
    printf '%s\n' 100000 > "$work/rmem"
    printf '%s\n' 16000000 > "$work/wmem"
    if [[ $2 == buffers_preserve ]]; then
      printf '%s\n' 32000000 > "$work/rmem"
      printf 'net.core.rmem_max = 7500000\n' > "$SYSCTL_FILE"
    fi
    sysctl() {
      local file
      case $2 in net.core.rmem_max*) file="$work/rmem";; net.core.wmem_max*) file="$work/wmem";; *) return 1;; esac
      if [[ $1 == -n ]]; then cat "$file"; else printf '%s\n' "${2#*=}" > "$file"; fi
    }
    tune_buffers
    tune_buffers
    assert_equal "$(cat "$work/wmem")" 16000000
    if [[ $2 == buffers_increase ]]; then assert_equal "$(cat "$work/rmem")" 7500000
    else assert_equal "$(cat "$work/rmem")" 32000000; fi
    grep -q "net.core.rmem_max = $(cat "$work/rmem")" "$SYSCTL_FILE"
    ! grep -q wmem "$SYSCTL_FILE"
    ;;
  archive_valid|archive_bad_checksum|archive_link|archive_traversal)
    mkdir -p "$work/source/deploy" "$work/assets" "$work/download"
    fixture_assets="$work/assets"
    for file in usque usque-supervisor usquectl deploy/lib.sh deploy/service.env deploy/usque.service LICENSE.md README.md; do
      printf 'fixture\n' > "$work/source/$file"
    done
    artifact=usque_2.0.0_linux_amd64.tar.gz
    if [[ $2 == archive_link ]]; then rm "$work/source/usque"; ln -s /etc/passwd "$work/source/usque"; fi
    if [[ $2 == archive_traversal ]]; then
      tar -czf "$work/assets/$artifact" -C "$work/source" --transform='s|^usque$|../usque|' usque
    else tar -czf "$work/assets/$artifact" -C "$work/source" usque usque-supervisor usquectl deploy LICENSE.md README.md; fi
    (cd "$work/assets"; sha256sum "$artifact" > checksums.txt)
    if [[ $2 == archive_bad_checksum ]]; then printf 'corrupt\n' >> "$work/assets/$artifact"; fi
    fetch() { cp "$fixture_assets/${1##*/}" "$2"; }
    uname() { printf 'x86_64\n'; }
    if [[ $2 == archive_valid ]]; then
      download_release "$work/download" v2.0.0
      [[ -f $work/download/payload/usque-supervisor ]]
    else assert_fails download_release "$work/download" v2.0.0; fi
    ;;
  release_immutable)
    mkdir -p "$work/source/deploy"
    for file in usque usque-supervisor usquectl deploy/lib.sh deploy/service.env deploy/usque.service LICENSE.md README.md; do
      printf 'fixture\n' > "$work/source/$file"
    done
    store_release "$work/source" v3.0.0
    store_release "$work/source" v3.0.0
    printf 'different\n' > "$work/source/usque"
    assert_fails store_release "$work/source" v3.0.0
    assert_equal "$(cat "$ROOT/releases/v3.0.0/usque")" fixture
    ;;
  update_failure|update_success)
    latest_release() { printf 'v2.0.0\n'; }
    download_release() { return 0; }
    store_release() { return 0; }
    if [[ $2 == update_success ]]; then
      wait_healthy() { return 0; }
      update_release
      assert_equal "$(cat "$ROOT/current/VERSION")" v2.0.0
      assert_equal "$(cat "$ROOT/previous/VERSION")" v1.0.0
    else
      assert_fails update_release
      assert_equal "$(cat "$ROOT/current/VERSION")" v1.0.0
    fi
    ;;
  rollback_failure)
    atomic_link "$ROOT/releases/v2.0.0" "$ROOT/previous"
    assert_fails rollback_release
    assert_equal "$(cat "$ROOT/current/VERSION")" v1.0.0
    assert_equal "$(cat "$ROOT/previous/VERSION")" v2.0.0
    ;;
  install_links_error)
    atomic_link() { printf '%s\n' "$2" >> "$work/link.calls"; return 1; }
    assert_fails install_links
    assert_equal "$(wc -l < "$work/link.calls" | tr -d ' ')" 1
    assert_equal "$(cat "$work/link.calls")" "$BIN/usque"
    [[ ! -e $UNIT && ! -L $UNIT ]]
    ;;
  install_idempotent)
    mkdir -p "$work/source/deploy"
    cp "$ROOT/releases/v1.0.0/usque-supervisor" "$work/source/usque-supervisor"
    for file in usque usquectl deploy/lib.sh deploy/usque.service LICENSE.md README.md; do printf 'fixture\n' > "$work/source/$file"; done
    cp "$repo/deploy/lib.sh" "$work/source/deploy/lib.sh"
    sed "s|/etc/usque/config.json|$ETC/config.json|;s|/opt/usque/current/usque|$ROOT/current/usque|" \
      "$repo/deploy/service.env" > "$work/source/deploy/service.env"
    rm "$ROOT/current" "$ROOT/previous"
    prepare_host() { :; }
    tune_buffers() { :; }
    timeout() {
      if [[ " $* " == *' head '* ]]; then command head -c 1048577 -- "${@: -1}"; return; fi
      printf 'registration\n' >> "$work/registration.calls"
      while (($#)); do
        if [[ $1 == -c ]]; then printf '{"valid":true,"original":true}\n' > "$2"; return 0; fi
        shift
      done
      return 1
    }
    install_release "$work/source" v4.0.0
    printf '# Administrator setting preserved\n' >> "$ETC/service.env"
    install_release "$work/source" v4.0.0
    assert_equal "$(cat "$ROOT/current/VERSION")" v4.0.0
    assert_equal "$(wc -l < "$work/registration.calls" | tr -d ' ')" 1
    grep -q '"original":true' "$ETC/config.json"
    grep -q 'Administrator setting preserved' "$ETC/service.env"
    assert_equal "$(readlink "$UNIT")" "$ROOT/current/deploy/usque.service"
    ;;
  *) printf 'Unknown test: %s\n' "$2" >&2; exit 1 ;;
esac
