from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import io
import lzma
import re
import shutil
import struct
import tarfile
from datetime import datetime, timezone
from pathlib import Path


PACKAGE_ID = "com.adin.grokselection"
PACKAGE_VERSION = "3.0.3"
GADGET_VERSION = "17.16.4"
DEB_NAME = f"{PACKAGE_ID}_{PACKAGE_VERSION}_iphoneos-arm64.deb"
PROJECT_DIR = Path(__file__).resolve().parent

INSTALL_DIR = (
    "var/jb/Library/MobileSubstrate/DynamicLibraries"
)
GADGET_NAME = "GrokSelectionFrida"
GADGET_PATH = f"{INSTALL_DIR}/{GADGET_NAME}.dylib"
CONFIG_PATH = f"{INSTALL_DIR}/{GADGET_NAME}.config"
LOADER_NAME = "GrokSelectionLoader"
LOADER_PATH = f"{INSTALL_DIR}/{LOADER_NAME}.dylib"
PLIST_PATH = f"{INSTALL_DIR}/{LOADER_NAME}.plist"

# Generic shell: Gadget always loads bootstrap; user replaces user_script.js
BOOTSTRAP_NAME = "GrokSelectionBootstrap.js"
BOOTSTRAP_PATH = f"{INSTALL_DIR}/{BOOTSTRAP_NAME}"
USER_SCRIPT_NAME = "user_script.js"
USER_SCRIPT_PATH = f"{INSTALL_DIR}/{USER_SCRIPT_NAME}"
SHELL_CONFIG_NAME = "shell_config.json"
SHELL_CONFIG_PATH = f"{INSTALL_DIR}/{SHELL_CONFIG_NAME}"

CONTROL = f"""Package: {PACKAGE_ID}
Name: Grok Selection Detector
Version: {PACKAGE_VERSION}
Architecture: iphoneos-arm64
Description: Generic Frida Gadget shell for Grok (bootstrap + swappable user_script). Compatible with CLI-style Frida scripts.
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

CONFIG = f"""{{
  "interaction": {{
    "type": "script",
    "path": "/var/jb/Library/MobileSubstrate/DynamicLibraries/{BOOTSTRAP_NAME}",
    "on_change": "ignore"
  }},
  "teardown": "minimal",
  "runtime": "qjs",
  "code_signing": "optional"
}}
""".encode()


def tar_gz(files: list[tuple[str, bytes, int]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(
        fileobj=raw,
        mode="w",
        format=tarfile.GNU_FORMAT,
    ) as archive:
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
                archive.addfile(info)

        for name, content, mode in files:
            info = tarfile.TarInfo(
                "./" + Path(name).as_posix()
            )
            info.size = len(content)
            info.mode = mode
            info.uid = 0
            info.gid = 0
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))

    compressed = io.BytesIO()
    with gzip.GzipFile(
        fileobj=compressed,
        mode="wb",
        mtime=0,
    ) as stream:
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
    return header + content + (
        b"\n" if len(content) % 2 else b""
    )


def verify_gadget(data: bytes) -> None:
    if len(data) < 8:
        raise ValueError("Frida Gadget is too small")

    magic, count = struct.unpack(">II", data[:8])
    if magic not in (0xCAFEBABE, 0xCAFEBABF):
        raise ValueError(
            "Frida Gadget is not a universal Mach-O"
        )

    entry_size = 20 if magic == 0xCAFEBABE else 32
    cpu_types: set[int] = set()
    cursor = 8

    for _ in range(count):
        if cursor + entry_size > len(data):
            raise ValueError("Invalid universal Mach-O header")
        cpu_types.add(
            struct.unpack(">I", data[cursor : cursor + 4])[0]
        )
        cursor += entry_size

    if 0x0100000C not in cpu_types:
        raise ValueError("Frida Gadget has no arm64 slice")


def digest(data: bytes, algorithm: str) -> str:
    return hashlib.new(algorithm, data).hexdigest()


def release_lines(
    paths: list[Path],
    algorithm: str,
) -> list[str]:
    return [
        f" {digest(path.read_bytes(), algorithm)}"
        f" {path.stat().st_size:16d} {path.name}"
        for path in paths
    ]


def update_repo(repo_root: Path, deb: Path) -> None:
    repo_root = repo_root.resolve()
    debs = repo_root / "debs"
    debs.mkdir(parents=True, exist_ok=True)

    for old_deb in debs.glob(
        f"{PACKAGE_ID}_*_iphoneos-arm64.deb"
    ):
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
        gzip.compress(
            packages_data,
            compresslevel=9,
            mtime=0,
        )
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
        "\n".join(release),
        encoding="utf-8",
        newline="\n",
    )

    index = repo_root / "index.html"
    if index.is_file():
        raw = index.read_bytes()
        text: str | None = None
        for encoding in ("utf-8", "utf-8-sig", "utf-16", "utf-16-le"):
            try:
                text = raw.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        if text is None:
            raise ValueError("Unable to decode index.html")
        text = re.sub(
            r"Grok Selection Detector [^<]+",
            (
                "Grok Selection Detector "
                f"{PACKAGE_VERSION} Frida"
            ),
            text,
            count=1,
        )
        index.write_text(
            text,
            encoding="utf-8",
            newline="\n",
        )

    (repo_root / "THIRD_PARTY_NOTICES.txt").write_text(
        (
            "This package includes the official Frida Gadget "
            f"{GADGET_VERSION} binary.\n\n"
            "Frida project:\n"
            "https://github.com/frida/frida\n\n"
            "Frida license:\n"
            "https://github.com/frida/frida/blob/main/COPYING\n"
        ),
        encoding="utf-8",
        newline="\n",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--gadget",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--loader",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--output",
        default=Path("output"),
        type=Path,
    )
    parser.add_argument("--repo-root", type=Path)
    args = parser.parse_args()

    gadget = args.gadget.resolve().read_bytes()
    verify_gadget(gadget)
    loader = args.loader.resolve().read_bytes()

    bootstrap = (PROJECT_DIR / BOOTSTRAP_NAME).read_bytes()
    user_script = (PROJECT_DIR / USER_SCRIPT_NAME).read_bytes()
    shell_config = (PROJECT_DIR / SHELL_CONFIG_NAME).read_bytes()

    control_archive = tar_gz([
        ("control", CONTROL, 0o644),
    ])
    data_archive = tar_gz([
        (GADGET_PATH, gadget, 0o755),
        (CONFIG_PATH, CONFIG, 0o644),
        (LOADER_PATH, loader, 0o755),
        (PLIST_PATH, PLIST, 0o644),
        (BOOTSTRAP_PATH, bootstrap, 0o644),
        (USER_SCRIPT_PATH, user_script, 0o644),
        (SHELL_CONFIG_PATH, shell_config, 0o644),
    ])

    package = bytearray(b"!<arch>\n")
    package.extend(
        ar_member("debian-binary", b"2.0\n")
    )
    package.extend(
        ar_member("control.tar.gz", control_archive)
    )
    package.extend(
        ar_member("data.tar.gz", data_archive)
    )

    args.output.mkdir(parents=True, exist_ok=True)
    target = args.output / DEB_NAME
    target.write_bytes(package)

    if args.repo_root is not None:
        update_repo(args.repo_root, target)

    print(target)
    print(f"size={target.stat().st_size}")


if __name__ == "__main__":
    main()
