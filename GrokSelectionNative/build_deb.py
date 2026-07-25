from __future__ import annotations

import argparse
import gzip
import io
import struct
import tarfile
from pathlib import Path


PACKAGE_ID = "com.adin.grokselection"
PACKAGE_VERSION = "2.0.0"
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dylib", required=True, type=Path)
    parser.add_argument("--output", default=Path("output"), type=Path)
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
    print(target)
    print(f"size={target.stat().st_size}")


if __name__ == "__main__":
    main()
