#!/usr/bin/env python3
"""Package a natively built CoreDNS binary with Blockinator and build metadata."""
import argparse
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile


def package_version():
    match = re.search(r"^## (\d+\.\d+\.\d+)\b", Path("CHANGELOG.md").read_text(), re.M)
    if not match:
        raise SystemExit("No release version found in CHANGELOG.md")
    version = match.group(1)
    tag = os.environ.get("RELEASE_TAG", "")
    if tag:
        version = tag.removeprefix("v")
        if version not in {match.group(1), match.group(1).removesuffix(".0")}:
            raise SystemExit(f"Release tag {tag!r} does not match changelog version {match.group(1)}")
    return version


def write_package(name, files, build_info):
    output = Path("dist")
    output.mkdir(exist_ok=True)
    archive_path = output / f"{name}.tar.gz"
    for source in files.values():
        if not source.is_file() or source.stat().st_size == 0:
            raise SystemExit(f"Required package file is missing or empty: {source}")
    with tarfile.open(archive_path, "w:gz") as archive:
        for target, source in files.items():
            archive.add(source, arcname=f"{name}/{target}", recursive=False)
        data = build_info.encode()
        entry = tarfile.TarInfo(f"{name}/BUILD-INFO.txt")
        entry.size = len(data)
        entry.mode = 0o644
        archive.addfile(entry, io.BytesIO(data))
    with tarfile.open(archive_path, "r:gz") as archive:
        expected = {f"{name}/{target}" for target in files} | {f"{name}/BUILD-INFO.txt"}
        if set(archive.getnames()) != expected or len(archive.getmembers()) != len(expected):
            raise SystemExit("Unexpected package layout")
        for member in archive.getmembers():
            if not member.isfile() or not member.size:
                raise SystemExit(f"Invalid package member: {member.name}")
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    archive_path.with_suffix(archive_path.suffix + ".sha256").write_text(
        f"{digest}  {archive_path.name}\n"
    )
    print(f"Created and validated {archive_path}")


def revision():
    return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", required=True, choices=["amd64", "arm64"])
    args = parser.parse_args()
    version = package_version()
    binary = Path("build/coredns")
    if not binary.is_file():
        raise SystemExit("Run tools/build.sh before packaging")
    plugins = subprocess.check_output([str(binary.resolve()), "-plugins"], text=True)
    if "blockinator" not in plugins.splitlines():
        raise SystemExit("CoreDNS binary does not contain the Blockinator plugin")
    # ELF e_machine is 62 for AMD64 and 183 for ARM64.
    header = binary.read_bytes()[:20]
    machine = int.from_bytes(header[18:20], "little")
    if header[:5] != b"\x7fELF\x02" or machine != {"amd64": 62, "arm64": 183}[args.arch]:
        raise SystemExit("CoreDNS binary does not match the requested Linux architecture")
    name = f"blockinator-coredns_v{version}_linux_{args.arch}"
    files = {path: Path(path) for path in ["README.md", "CHANGELOG.md", "LICENSE", "examples/Corefile"]}
    files.update({
        "coredns": binary,
        "CoreDNS-LICENSE": Path("build/coredns-source/LICENSE"),
        "build/go.mod": Path("build/coredns-source/go.mod"),
        "build/go.sum": Path("build/coredns-source/go.sum"),
        "build/plugin.cfg": Path("build/coredns-source/plugin.cfg"),
    })
    info = (f"Blockinator: {version}\nPlugin commit: {revision()}\nPlatform: linux/{args.arch}\n"
            "Build: CGO_ENABLED=0; CoreDNS source v1.14.7\n")
    info += subprocess.check_output(["go", "version", "-m", str(binary)], text=True)
    write_package(name, files, info)
