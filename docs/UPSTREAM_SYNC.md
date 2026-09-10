# Upstream synchronization and releases

Production follows reviewed releases of **GamerKhaan/usque**. No scheduler merges
upstream into `main`, and no host automatically installs an upstream commit.

```bash
git remote -v
# origin   https://github.com/GamerKhaan/usque.git
# upstream https://github.com/Diniboy1123/usque.git
git fetch upstream --tags
git switch main
git pull --ff-only origin main
git switch -c codex/integrate-upstream-VERSION
git log --oneline main..upstream/main
git diff main...upstream/main -- go.mod api internal cmd
# Select the actual reviewed upstream release tag, not the example below:
git merge --no-ff UPSTREAM_TAG
```

Resolve conflicts against the patch inventory in
[UPSTREAM_RELIABILITY_NOTES.md](UPSTREAM_RELIABILITY_NOTES.md). Inspect whether a
carried fix has landed upstream and remove duplication while retaining regression
tests. Preserve upstream commit authorship and license. Never force-push rewritten
upstream history. Record the new upstream base tag/SHA in the notes and README.

Validate on the integration branch:

```bash
test -z "$(gofmt -l $(git ls-files '*.go'))"
go mod verify
go vet ./...
go test -count=1 ./...
CGO_ENABLED=1 go test -race -count=1 ./internal/... ./api ./config ./cmd
golangci-lint run
shellcheck -x -P . install.sh scripts/usquectl deploy/lib.sh tests/*.sh
bash tests/deployment_test.sh
goreleaser check
goreleaser release --snapshot --clean
python3 tests/check_release.py
```

CI also exercises the hardened unit on an ephemeral Ubuntu runner with a local
SOCKS/TLS fixture. It never registers a real WARP account. Execute the
[manual acceptance checklist](ACCEPTANCE_TEST.md) in staging with real clients
and credentials before promoting a new upstream base to production.

Push the integration branch, open a pull request against the fork's `main`, review
conflicts/patches/test results, and merge only after acceptance. Then tag a fork
release, such as `v4.2.1-gk.2` for the next local patch set on the same upstream
base. The `-gk.N` suffix distinguishes fork patches from upstream versions.

```bash
git switch main
git pull --ff-only origin main
git tag vUPSTREAM-gk.N
git push origin main
git push origin vUPSTREAM-gk.N
```

Replace example tags with the actual reviewed version. The tag workflow reruns
quality checks before publishing both Linux architectures, documentation, scripts
and `checksums.txt`. Published service releases are explicitly marked eligible
for the fork's latest-release endpoint. Do not move a published tag or replace
its artifacts; publish a new tag to correct a release.

Hosts update only through `sudo usquectl update`, which validates HTTPS readiness
and restores the previous release on failure. Keep the previous release available
for `sudo usquectl rollback`. Configuration schema changes require an explicit
backward-compatibility/migration plan before release.
