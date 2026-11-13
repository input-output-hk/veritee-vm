#!/usr/bin/env python3
"""Verify and stage the vendored Docker CE packages without network access."""

import argparse
import email.parser
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
KEYRING = HERE / "docker.gpg"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_file(path, digest, size=None):
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"Missing regular input file: {path.name}")
    if size is not None and path.stat().st_size != size:
        raise ValueError(f"Size mismatch: {path.name}")
    if sha256(path) != digest:
        raise ValueError(f"SHA-256 mismatch: {path.name}")


def filenames(lock):
    names = ["InRelease", "Packages.gz"] + [p["filename"] for p in lock["packages"]]
    if len(set(names)) != len(names) or any(
        not n or n in (".", "..") or Path(n).name != n for n in names
    ):
        raise ValueError("Duplicate or non-local input filenames")
    return names


def verify(directory, lock, keyring=KEYRING):
    expected = set(filenames(lock))
    if {p.name for p in directory.iterdir()} != expected:
        raise ValueError("Package input membership differs from the lock")
    if set(lock["metadata_sha256"]) != {"InRelease", "Packages.gz"}:
        raise ValueError("Both pinned repository metadata files are required")
    check_file(keyring, lock["upstream"]["keyring_sha256"])
    for name, digest in lock["metadata_sha256"].items():
        if name not in ("InRelease", "Packages.gz"):
            raise ValueError("Unexpected repository metadata")
        check_file(directory / name, digest)

    with tempfile.TemporaryDirectory() as temporary:
        release = Path(temporary) / "Release"
        result = subprocess.run(
            ["gpgv", "--homedir", temporary, "--keyring", str(keyring.resolve()),
             "--status-fd", "1", "--output", str(release), str(directory / "InRelease")],
            capture_output=True, text=True, check=True,
        )
        signatures = [line.split() for line in result.stdout.splitlines()
                      if line.startswith("[GNUPG:] VALIDSIG ")]
        if not any(s[-1] == lock["upstream"]["signing_key_fingerprint"] for s in signatures):
            raise ValueError("Repository signed by an unexpected key")
        fields = email.parser.Parser().parsestr(release.read_text())

    if fields["Suite"] != lock["upstream"]["suite"]:
        raise ValueError("Repository suite mismatch")
    entries = [line.split() for line in fields["SHA256"].splitlines() if line.strip()]
    index = [e for e in entries if e[2] == lock["upstream"]["index_path"]]
    if len(index) != 1:
        raise ValueError("Signed release does not identify exactly one package index")
    check_file(directory / "Packages.gz", index[0][0], int(index[0][1]))
    with gzip.open(directory / "Packages.gz", "rt") as stream:
        records = [email.parser.Parser().parsestr(p) for p in stream.read().split("\n\n")
                   if p.strip()]
    for package in lock["packages"]:
        matches = [p for p in records if p["Package"] == package["name"]
                   and p["Version"] == package["version"]
                   and p["Architecture"] == package["architecture"]]
        if len(matches) != 1:
            raise ValueError(f"Signed index package mismatch: {package['name']}")
        record = matches[0]
        if (record["Filename"] != package["upstream_path"]
                or record["SHA256"] != package["sha256"]
                or int(record["Size"]) != package["size"]):
            raise ValueError(f"Signed index identity mismatch: {package['name']}")
        path = directory / package["filename"]
        check_file(path, package["sha256"], package["size"])
        identity = subprocess.check_output(
            ["dpkg-deb", "--show", "--showformat=${Package}\n${Version}\n${Architecture}\n", str(path)],
            text=True,
        ).splitlines()
        if identity != [package["name"], package["version"], package["architecture"]]:
            raise ValueError(f"Package control identity mismatch: {package['name']}")


def stage(directory, destination, lock):
    """Expose only verified .deb files to mkosi's local package repository."""
    verify(directory, lock)
    if destination.exists():
        raise ValueError("Package destination must not already exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        staged = Path(temporary) / "packages"
        staged.mkdir()
        for package in lock["packages"]:
            path = staged / package["filename"]
            shutil.copyfile(directory / package["filename"], path)
            path.chmod(0o644)
            os.utime(path, (946684800, 946684800))
            check_file(path, package["sha256"], package["size"])
        staged.chmod(0o755)
        os.utime(staged, (946684800, 946684800))
        staged.rename(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=HERE / "lock.json")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify").add_argument("directory", type=Path, nargs="?", default=HERE / "packages")
    stage_parser = commands.add_parser("stage")
    stage_parser.add_argument("directory", type=Path)
    stage_parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    lock = json.loads(args.lock.read_text())
    if args.command == "verify":
        verify(args.directory, lock)
    else:
        stage(args.directory, args.destination, lock)


if __name__ == "__main__":
    main()
