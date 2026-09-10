#!/usr/bin/env bash
# Bootstrap only verified release artifacts; production hosts need no Go tools.
set -euo pipefail
umask 077

REPO=GamerKhaan/usque
fail() { printf 'usque installation failed: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail 'run with sudo bash'
[[ $(uname -s) == Linux ]] || fail 'only Linux is supported'
[[ -r /etc/os-release ]] || fail 'cannot determine the Linux distribution'
# This file is part of the operating system, not downloaded configuration.
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == ubuntu ]] || fail 'this installer currently supports Ubuntu'
[[ -d /run/systemd/system ]] || fail 'a running systemd host is required'
case $(uname -m) in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) fail 'supported architectures are amd64 and arm64' ;;
esac

packages=()
command -v curl >/dev/null || packages+=(curl)
command -v jq >/dev/null || packages+=(jq)
command -v tar >/dev/null || packages+=(tar)
command -v sha256sum >/dev/null || packages+=(coreutils)
command -v flock >/dev/null || packages+=(util-linux)
command -v runuser >/dev/null || packages+=(util-linux)
command -v useradd >/dev/null || packages+=(passwd)
command -v ss >/dev/null || packages+=(iproute2)
command -v sysctl >/dev/null || packages+=(procps)
[[ -s /etc/ssl/certs/ca-certificates.crt ]] || packages+=(ca-certificates)
if ((${#packages[@]})); then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
fi

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
fetch() { curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --retry 3 "$1" -o "$2"; }
fetch "https://api.github.com/repos/$REPO/releases/latest" "$work/release.json"
tag=$(jq -er '.tag_name' "$work/release.json")
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || fail 'release tag has an unsupported format'
artifact="usque_${tag#v}_linux_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"
fetch "$base/$artifact" "$work/$artifact"
fetch "$base/checksums.txt" "$work/checksums.txt"
hash=$(awk -v file="$artifact" '$2 == file || $2 == "*" file {print $1}' "$work/checksums.txt")
[[ $hash =~ ^[0-9a-fA-F]{64}$ ]] || fail 'checksum is missing or ambiguous'
printf '%s  %s\n' "$hash" "$work/$artifact" | sha256sum --check --status || fail 'release checksum mismatch'
# Reject links and traversal before extracting only the expected payload.
tar -tzf "$work/$artifact" > "$work/paths"
if LC_ALL=C grep -Eq '(^/|(^|/)\.\.(/|$)|\\)' "$work/paths"; then fail 'unsafe archive paths'; fi
tar -tvzf "$work/$artifact" > "$work/modes"
if LC_ALL=C grep -Eq '^[^-d]' "$work/modes"; then fail 'archive contains links or special files'; fi
mkdir "$work/payload"
tar -xzf "$work/$artifact" --no-same-owner --no-same-permissions -C "$work/payload" -- \
  usque usque-supervisor usquectl deploy/lib.sh deploy/service.env deploy/usque.service LICENSE.md README.md
chmod 0755 "$work/payload/usque" "$work/payload/usque-supervisor" "$work/payload/usquectl"
bash "$work/payload/usquectl" _install "$work/payload" "$tag"
