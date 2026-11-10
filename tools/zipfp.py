#!/usr/bin/env python3
"""计算 APK 的 ZipEntry 指纹（契约 docs/04-契约.md §4.4）。

这是**唯一实现**：build.ps1 与 cli/litmus.py 都必须调它，保证逐字节一致。
算法：
    按 central directory 顺序遍历 entry
    line = f"{name}|{crc32:08x}|{size}|{compressedSize}|{method}\\n"
    fingerprint = sha256(utf8(concat(lines))).hexdigest()

用法：
    python tools/zipfp.py <apk>
"""
from __future__ import annotations

import hashlib
import sys
import zipfile


def zip_fingerprint(path: str) -> str:
    h = hashlib.sha256()
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            line = (
                f"{info.filename}|{info.CRC:08x}|{info.file_size}|"
                f"{info.compress_size}|{info.compress_type}\n"
            )
            h.update(line.encode("utf-8"))
    return h.hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python tools/zipfp.py <apk>", file=sys.stderr)
        return 2
    print(zip_fingerprint(sys.argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
