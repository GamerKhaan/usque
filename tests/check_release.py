"""Verify the production archive contract after a GoReleaser snapshot/release."""
import hashlib
from pathlib import Path
import tarfile

dist = Path("dist")
checksums = dict(line.split()[::-1] for line in (dist / "checksums.txt").read_text().splitlines())
required = {"usque", "usque-supervisor", "usquectl", "deploy/lib.sh", "deploy/service.env", "deploy/usque.service", "LICENSE.md", "README.md"}
for arch in ("amd64", "arm64"):
    archives = list(dist.glob(f"usque_*_linux_{arch}.tar.gz"))
    assert len(archives) == 1, (arch, archives)
    archive = archives[0]
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == checksums[archive.name]
    with tarfile.open(archive) as tar:
        members = {entry.name: entry for entry in tar}
        assert required <= members.keys(), required - members.keys()
        assert all(entry.isfile() or entry.isdir() for entry in members.values())
        for binary in ("usque", "usque-supervisor", "usquectl"):
            assert members[binary].mode & 0o111, (binary, "not executable")
        for binary in ("usque", "usque-supervisor"):
            assert tar.extractfile(binary).read(4) == b"\x7fELF", (binary, "not ELF")
    print(f"PASS {archive.name}: checksum, binaries, scripts, unit, license")
