from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import io
import lzma
import shutil
import struct
import tarfile
from datetime import datetime, timezone
from pathlib import Path


PACKAGE_ID = "com.adin.grokselection"
PACKAGE_VERSION = "2.0.1"
DEB_NAME = f"{PACKAGE_ID}_{PACKAGE_VERSION}_iphoneos-arm64.deb"

CONTROL = f"""Package: {PACKAGE_ID}
Name: Grok Selection Detector
Version: {PACKAGE_VERSION}
Architecture: iphoneos-arm64
Description: Native read-only Grok source-and-target selection detector for Grok 1.4.5 (4127).
Maintainer: adin
Author: adin
Section: Tweaks
Priority: optional
Depends: firmware (>= 17.0), ellekit
Tag: role::tweak
""".encode()

PLIST = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Filter</key>
    <dict>
        <key>Bundles</key>
        <array>
            <string>ai.x.GrokApp</string>
        </array>
    </dict>
</dict>
</plist>
"""


def tar_gz(files: list[tuple[str, bytes, int]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        directories: set[str] = set()
        for name, _, _ in files:
            for parent in reversed(Path(name).parents):
                value = parent.as_posix()
                if value in ("", ".") or value in directories:
                    continue
                directories.add(value)
                info = tarfile.TarInfo("./" + value)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.uid = 0
                info.gid = 0
                info.mtime = 0
                tar.addfile(info)

        for name, content, mode in files:
            info = tarfile.TarInfo("./" + Path(name).as_posix())
            info.size = len(content)
            info.mode = mode
            info.uid = 0
            info.gid = 0
            info.mtime = 0
            tar.addfile(info, io.BytesIO(content))

    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0) as stream:
        stream.write(raw.getvalue())
    return compressed.getvalue()


def ar_member(name: str, content: bytes) -> bytes:
    header = (
        (name + "/").ljust(16)
        + str(0).ljust(12)
        + str(0).ljust(6)
        + str(0).ljust(6)
        + oct(0o100644)[2:].ljust(8)
        + str(len(content)).ljust(10)
        + "`\n"
    ).encode("ascii")
    return header + content + (b"\n" if len(content) % 2 else b"")


def digest(data: bytes, algorithm: str) -> str:
    return hashlib.new(algorithm, data).hexdigest()


def release_lines(paths: list[Path], algorithm: str) -> list[str]:
    return [
        f" {digest(path.read_bytes(), algorithm)}"
        f" {path.stat().st_size:16d} {path.name}"
        for path in paths
    ]


def update_repo(repo_root: Path, deb: Path) -> None:
    repo_root = repo_root.resolve()
    debs = repo_root / "debs"
    debs.mkdir(parents=True, exist_ok=True)
    for old_deb in debs.glob(f"{PACKAGE_ID}_*_iphoneos-arm64.deb"):
        old_deb.unlink()

    destination = debs / deb.name
    shutil.copy2(deb, destination)
    deb_data = destination.read_bytes()
    packages_data = (
        CONTROL.decode().strip()
        + "\n"
        + f"Filename: debs/{destination.name}\n"
        + f"Size: {len(deb_data)}\n"
        + f"MD5sum: {digest(deb_data, 'md5')}\n"
        + f"SHA1: {digest(deb_data, 'sha1')}\n"
        + f"SHA256: {digest(deb_data, 'sha256')}\n"
        + f"SHA512: {digest(deb_data, 'sha512')}\n\n"
    ).encode()

    packages = repo_root / "Packages"
    packages.write_bytes(packages_data)
    (repo_root / "Packages.gz").write_bytes(
        gzip.compress(packages_data, compresslevel=9, mtime=0)
    )
    (repo_root / "Packages.bz2").write_bytes(
        bz2.compress(packages_data, compresslevel=9)
    )
    (repo_root / "Packages.xz").write_bytes(
        lzma.compress(packages_data, preset=9)
    )

    indexes = [
        repo_root / "Packages",
        repo_root / "Packages.gz",
        repo_root / "Packages.bz2",
        repo_root / "Packages.xz",
    ]
    date = datetime.now(timezone.utc).strftime(
        "%a, %d %b %Y %H:%M:%S +0000"
    )
    release = [
        "Origin: Adin",
        "Label: Adin Repo",
        "Suite: stable",
        "Version: 1.0",
        "Codename: adin",
        "Architectures: iphoneos-arm64",
        "Components: main",
        "Description: Personal rootless Sileo repository",
        f"Date: {date}",
        "MD5Sum:",
        *release_lines(indexes, "md5"),
        "SHA1:",
        *release_lines(indexes, "sha1"),
        "SHA256:",
        *release_lines(indexes, "sha256"),
        "SHA512:",
        *release_lines(indexes, "sha512"),
        "",
    ]
    (repo_root / "Release").write_text(
        "\n".join(release), encoding="utf-8", newline="\n"
    )

    index = repo_root / "index.html"
    if index.is_file():
        text = index.read_text(encoding="utf-8")
        text = text.replace(
            "Grok Selection Detector 1.0.1",
            f"Grok Selection Detector {PACKAGE_VERSION} Native",
        )
        text = text.replace(
            "Grok Selection Detector 2.0.0 Native",
            f"Grok Selection Detector {PACKAGE_VERSION} Native",
        )
        index.write_text(text, encoding="utf-8", newline="\n")

    (repo_root / "THIRD_PARTY_NOTICES.txt").write_text(
        "This package statically links the official Dobby library.\n\n"
        "Dobby project:\nhttps://github.com/jmpews/Dobby\n\n"
        "Dobby license:\n"
        "https://github.com/jmpews/Dobby/blob/master/LICENSE\n\n"
        "Dobby is distributed under the Apache License 2.0.\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dylib", required=True, type=Path)
    parser.add_argument("--output", default=Path("output"), type=Path)
    parser.add_argument("--repo-root", type=Path)
    args = parser.parse_args()

    dylib = args.dylib.resolve().read_bytes()

    control_archive = tar_gz([("control", CONTROL, 0o644)])
    data_archive = tar_gz([
        (
            "var/jb/Library/MobileSubstrate/DynamicLibraries/"
            "GrokSelectionNative.dylib",
            dylib,
            0o755,
        ),
        (
            "var/jb/Library/MobileSubstrate/DynamicLibraries/"
            "GrokSelectionNative.plist",
            PLIST,
            0o644,
        ),
    ])

    package = bytearray(b"!<arch>\n")
    package.extend(ar_member("debian-binary", b"2.0\n"))
    package.extend(ar_member("control.tar.gz", control_archive))
    package.extend(ar_member("data.tar.gz", data_archive))

    args.output.mkdir(parents=True, exist_ok=True)
    target = args.output / DEB_NAME
    target.write_bytes(package)
    if args.repo_root is not None:
        update_repo(args.repo_root, target)
    print(target)
    print(f"size={target.stat().st_size}")


if __name__ == "__main__":
    main()
