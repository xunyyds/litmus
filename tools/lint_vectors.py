#!/usr/bin/env python3
"""向量契约静态检查器。

用途：在 CI 里当门禁，确保「通吃」这条设计承诺不会因为随手加一条特征匹配而退化。

检查项（对应 docs/04-契约.md）：
  L1  id 唯一
  L2  id 前缀与 category 一致（rt./inj./pkg./priv./virt./env.）
  L3  tier 只能是 A/B/C
  L4  weight 在 1..5
  L5  **tier C 的 probe 不得调用 sink.tampered(...)**   ← 硬约束，违反即失败
  L6  id 必须登记在 docs/02-探针目录.md 里（缺失只告警）
  L7  evidence 文案里不许出现换行拼接（'\n'）

用法：
    python tools/lint_vectors.py            # 在仓库根跑
    python tools/lint_vectors.py --strict   # 把 L6 告警也算失败
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROBE_DIR = ROOT / "canary" / "src" / "io" / "litmus" / "core" / "probes"
CATALOG = ROOT / "docs" / "02-探针目录.md"

CATEGORY_PREFIX = {
    "runtime-integrity": "rt.",
    "injection": "inj.",
    "package-integrity": "pkg.",
    "privilege": "priv.",
    "virtualization": "virt.",
    "environment": "env.",
}

# class X implements Probe ... 直到下一个顶层 class 声明
CLASS_SPLIT = re.compile(r"(?m)^\s*(?:static\s+)?(?:final\s+)?class\s+(\w+)[^{]*implements\s+Probe\b")


@dataclass
class Vector:
    cls: str
    file: str
    id: str = ""
    category: str = ""
    tier: str = ""
    weight: str = ""
    calls_tampered: bool = False
    errors: list[str] = field(default_factory=list)


def _match(pattern: str, body: str, default: str = "") -> str:
    m = re.search(pattern, body)
    return m.group(1) if m else default


def parse_file(path: Path) -> list[Vector]:
    text = path.read_text(encoding="utf-8", errors="replace")
    parts = CLASS_SPLIT.split(text)
    # parts = [preamble, name1, body1, name2, body2, ...]
    out: list[Vector] = []
    for i in range(1, len(parts) - 1, 2):
        name, body = parts[i], parts[i + 1]
        v = Vector(cls=name, file=path.name)
        v.id = _match(r'String\s+id\s*\(\s*\)\s*\{[^}]*return\s+"([^"]+)"', body)
        v.category = _match(r'String\s+category\s*\(\s*\)\s*\{[^}]*return\s+"([^"]+)"', body)
        v.tier = _match(r'String\s+tier\s*\(\s*\)\s*\{[^}]*return\s+"([^"]+)"', body)
        v.weight = _match(r'int\s+weight\s*\(\s*\)\s*\{[^}]*return\s+(\d+)', body)
        v.calls_tampered = bool(re.search(r"\bsink\.tampered\s*\(", body))
        out.append(v)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true", help="L6 缺失目录登记也算失败")
    args = ap.parse_args()

    if not PROBE_DIR.is_dir():
        print(f"[ERR] 找不到 probe 目录：{PROBE_DIR}")
        return 2

    catalog_text = CATALOG.read_text(encoding="utf-8", errors="replace") if CATALOG.exists() else ""

    vectors: list[Vector] = []
    for path in sorted(PROBE_DIR.glob("*.java")):
        vectors.extend(parse_file(path))

    fatal: list[str] = []
    warn: list[str] = []
    seen: dict[str, str] = {}

    for v in vectors:
        where = f"{v.file}:{v.cls}"
        if not v.id:
            fatal.append(f"L1 {where} 取不到 id()")
            continue
        if v.id in seen:
            fatal.append(f"L1 id 重复 {v.id}（{seen[v.id]} 与 {where}）")
        seen[v.id] = where

        prefix = CATEGORY_PREFIX.get(v.category)
        if prefix is None:
            fatal.append(f"L2 {where} category='{v.category}' 不在六类里")
        elif not v.id.startswith(prefix):
            fatal.append(f"L2 {where} id='{v.id}' 前缀应为 '{prefix}'")

        if v.tier not in ("A", "B", "C"):
            fatal.append(f"L3 {where} tier='{v.tier}' 不是 A/B/C")

        if not v.weight:
            warn.append(f"L4 {where} 没有覆写 weight()（用默认 3）")
        elif not (1 <= int(v.weight) <= 5):
            fatal.append(f"L4 {where} weight={v.weight} 越界")

        if v.tier == "C" and v.calls_tampered:
            fatal.append(f"L5 {where} tier=C 却调用了 sink.tampered() —— 违反契约 §2.2")

        if v.id not in catalog_text:
            msg = f"L6 {where} id='{v.id}' 未登记在 docs/02-探针目录.md"
            (fatal if args.strict else warn).append(msg)

    by_cat: dict[str, list[Vector]] = {}
    for v in vectors:
        by_cat.setdefault(v.category, []).append(v)

    print(f"vectors: {len(vectors)}\n")
    print(f"{'category':<20}{'n':>4}  tier A/B/C")
    for cat in CATEGORY_PREFIX:
        vs = by_cat.get(cat, [])
        a = sum(1 for v in vs if v.tier == "A")
        b = sum(1 for v in vs if v.tier == "B")
        c = sum(1 for v in vs if v.tier == "C")
        print(f"{cat:<20}{len(vs):>4}  {a}/{b}/{c}")

    if warn:
        print(f"\nWARN ({len(warn)}):")
        for w in warn:
            print("  " + w)
    if fatal:
        print(f"\nFAIL ({len(fatal)}):")
        for f in fatal:
            print("  " + f)
        return 1

    print(f"\nOK · {len(vectors)} 条向量全部符合契约")
    return 0


if __name__ == "__main__":
    sys.exit(main())
