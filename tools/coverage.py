#!/usr/bin/env python3
"""覆盖度审计：目录 vs 实现 vs 攻击面。

回答三个问题：
  1. 目录里有几条、真实现了几条、缺的是哪些
  2. 每个类别里「能下结论的」（tier A/B）和「只能可疑的」（tier C）各占多少
  3. 已知攻击手法（ATTACKS）分别被哪些向量盯着 —— 这张表用来发现"完全没人看"的缺口

ATTACKS 是人工维护的：它代表我们**声称**要防的东西。改这个表比改代码更能反映产品野心，
所以每次加向量后跑一遍，看有没有哪一行是空的。

用法：
    python tools/coverage.py            # 人读表
    python tools/coverage.py --md       # markdown（贴进 docs）
    python tools/coverage.py --json
"""
from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VEC = ROOT / "schema" / "vectors.json"
PROBE_DIR = ROOT / "canary" / "src" / "io" / "litmus" / "core" / "probes"

CATEGORIES = [
    ("runtime-integrity", "运行时完整性"),
    ("injection", "注入痕迹"),
    ("package-integrity", "包完整性"),
    ("privilege", "提权面"),
    ("virtualization", "虚拟化/多开/模拟器"),
    ("environment", "环境面"),
]

# 攻击手法 -> 应该盯住它的向量（人工维护：这是「声称的覆盖面」）
ATTACKS: list[tuple[str, str, list[str]]] = [
    ("重打包 / 换签名", "改了 dex 或资源后用自己的证书重签", [
        "pkg.signature", "pkg.signing.v3", "pkg.cert.history",
        "pkg.codepath.hash", "pkg.zip.fingerprint", "pkg.dex", "pkg.manifest",
    ]),
    ("Frida ptrace 注入", "frida-server attach 或 spawn", [
        "rt.tracerpid", "rt.maps.anon_exec", "rt.thread.name", "rt.memfd",
        "inj.frida.port", "inj.frida.socket", "inj.module.paths",
    ]),
    ("Frida gadget 内存加载", "把 agent 放进 memfd / 匿名段，不落盘", [
        "rt.memfd", "rt.maps.anon_exec", "rt.maps.exec_files", "inj.elf.inline",
    ]),
    ("inline hook（Dobby/ShadowHook/whale）", "改写函数入口 16 字节放跳板", [
        "inj.elf.inline", "rt.maps.file_integrity", "rt.got.integrity",
    ]),
    ("PLT/GOT hook", "改 .got 槽指向自己的函数", [
        "rt.got.integrity", "rt.maps.file_integrity", "rt.vdso",
    ]),
    ("Java 层 hook（Xposed/LSPlant）", "改 ArtMethod 入口或 Instrumentation", [
        "rt.art.entrypoint", "rt.stack.frames", "inj.loader.solist",
    ]),
    ("Zygisk / Riru 模块", "进程启动早期注入，无文件痕迹", [
        "rt.maps.file_integrity", "rt.maps.deleted", "inj.module.marker",
        "inj.loader.solist", "inj.dex.inmemory",
    ]),
    ("root / KernelSU / APatch", "su 二进制、内核模块、能力位", [
        "priv.su", "priv.magisk", "priv.kernel", "priv.caps", "priv.props",
        "priv.mounts", "priv.selinux", "priv.proc.uid",
    ]),
    ("模拟器 / 云手机", "qemu 属性、goldfish 设备、GPU/传感器异常", [
        "virt.emulator.props", "virt.emulator.files", "virt.emulator.hardware",
    ]),
    ("多开 / 容器（VirtualApp）", "宿主代跑、uid 错位、进程名异常", [
        "virt.vapp", "virt.vapp.binder", "pkg.proc.name", "virt.multi.user",
    ]),
    ("调试器 attach", "ptrace、JDWP、debuggable 标志", [
        "rt.tracerpid", "env.debuggable", "env.developer",
    ]),
    ("syscall hook / 内核态劫持", "改 syscall 表或 seccomp 过滤", [
        "rt.timing", "rt.vdso", "priv.kernel",
    ]),
    ("DEX 内存加载 / 热修复", "不在磁盘上的 dex 被加载", [
        "inj.dex.inmemory", "pkg.dex", "pkg.codepath.hash",
    ]),
    ("Split APK 篡改", "只替换某个 split", ["pkg.split"]),
]


def load() -> tuple[list[dict], set[str]]:
    data = json.loads(VEC.read_text(encoding="utf-8"))
    impl: set[str] = set()
    for p in PROBE_DIR.glob("*.java"):
        impl |= set(re.findall(r'String\s+id\s*\(\s*\)\s*\{[^}]*return\s+"([^"]+)"',
                               p.read_text(encoding="utf-8", errors="replace")))
    return data["vectors"], impl


def main() -> int:
    vectors, impl = load()
    as_json = "--json" in sys.argv
    as_md = "--md" in sys.argv

    by_cat = collections.defaultdict(lambda: collections.Counter())
    for v in vectors:
        c = by_cat[v["category"]]
        c[v["tier"]] += 1
        c["impl" if v["id"] in impl else "todo"] += 1

    if as_json:
        print(json.dumps({
            "catalog": len(vectors), "implemented": len(impl),
            "categories": {k: dict(v) for k, v in by_cat.items()},
            "missing": [v["id"] for v in vectors if v["id"] not in impl],
        }, ensure_ascii=False, indent=2))
        return 0

    total = len(vectors)
    if as_md:
        print(f"| 类别 | 目录 | 已实现 | 待实现 | tier A | tier B | tier C | 可下结论(A+B) |")
        print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for cid, zh in CATEGORIES:
            c = by_cat[cid]
            n = c["A"] + c["B"] + c["C"]
            print(f"| {zh} (`{cid}`) | {n} | {c['impl']} | {c['todo']} | {c['A']} | {c['B']} | {c['C']} | {c['A']+c['B']} |")
        print(f"| **合计** | **{total}** | **{len(impl)}** | **{total-len(impl)}** | "
              f"**{sum(v['tier']=='A' for v in vectors)}** | **{sum(v['tier']=='B' for v in vectors)}** | "
              f"**{sum(v['tier']=='C' for v in vectors)}** | "
              f"**{sum(v['tier'] in ('A','B') for v in vectors)}** |")
        print()
        print("### 攻击手法覆盖")
        print()
        print("| 手法 | 说明 | 盯着它的向量 | 其中已实现 |")
        print("| --- | --- | ---: | ---: |")
        for name, desc, ids in ATTACKS:
            have = [i for i in ids if i in impl]
            print(f"| {name} | {desc} | {len(ids)} | {len(have)} |")
        return 0

    print(f"目录 {total} 条 / 已实现 {len(impl)} 条 / 缺口 {total - len(impl)} 条\n")
    print(f"{'类别':<20}{'计':>3}{'实现':>5}{'缺':>3}{'A':>4}{'B':>4}{'C':>4}   A+B 占比")
    for cid, zh in CATEGORIES:
        c = by_cat[cid]
        n = c["A"] + c["B"] + c["C"]
        ab = c["A"] + c["B"]
        print(f"{zh:<20}{n:>3}{c['impl']:>5}{c['todo']:>3}{c['A']:>4}{c['B']:>4}{c['C']:>4}   {ab*100//max(n,1)}%")

    print(f"\n{'攻击手法':<28}{'向量':>4}{'已实现':>6}")
    empty = []
    for name, _desc, ids in ATTACKS:
        have = [i for i in ids if i in impl]
        flag = "  ← 缺口" if not have else ""
        print(f"{name:<28}{len(ids):>4}{len(have):>6}{flag}")
        if not have:
            empty.append(name)
    if empty:
        print(f"\n[!] 完全没人盯的手法（{len(empty)}）：{', '.join(empty)}")

    missing = [v["id"] for v in vectors if v["id"] not in impl]
    if missing:
        print(f"\n[!] 目录里有、代码里没有（{len(missing)}）：")
        for m in missing:
            print("    -", m)
    return 0


if __name__ == "__main__":
    sys.exit(main())
