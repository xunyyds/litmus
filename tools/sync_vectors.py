#!/usr/bin/env python3
"""把「实现已落地但目录未登记」的向量补进 docs/02 主表，并重建 schema/vectors.json。

背景：探针实现（io.litmus.core.probes）与文档目录是两条并行线，合流时必然出现
「实现有、目录没有」的 id。CLI 的契约告警（向量不在 schema/vectors.json）就是这件事。

做法：以 docs/02-探针目录.md 的主表为**唯一人工可读源**，把新增行插进对应类别的表尾，
再从表里反向生成 vectors.json，保证两边永不漂移。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "02-探针目录.md"
VEC = ROOT / "schema" / "vectors.json"

# id, category, tier, weight, 判据, 依赖, 状态
NEW_ROWS = [
    ("rt.proc.pid", "runtime-integrity", "B", 2,
     "`Process.myPid()` 与 `/proc/self/stat` 里的 pid 必须一致；多个 pid 视图错位说明有进程伪装或 ptrace 侧通道",
     "java", "v0.1 基线"),
    ("rt.maps.exec_files", "runtime-integrity", "B", 3,
     "maps 中可执行 file-backed 段只允许来自 `codePath`、`/system`、`/apex`、`/vendor`；出现 `/data/local/tmp` 等可写目录即可执行代码落盘",
     "native", "v0.1 基线"),
    ("inj.module.marker", "injection", "C", 4,
     "已加载模块/映射路径里出现注入框架标记目录名（`/data/adb/modules`、`/data/local/tmp/`、`riru`、`zygisk` 等）",
     "native", "v0.1 基线"),
    ("pkg.proc.name", "package-integrity", "B", 3,
     "`Application.getProcessName()` 必须是包名本身或以 `<包名>:` 开头的子进程；出现宿主包名说明被容器代跑",
     "java", "v0.1 基线"),
    ("priv.proc.uid", "privilege", "A", 5,
     "`Process.myUid()` 必须落在普通应用 uid 区间且与 PMS 记录一致；容器/双开把 uid 换成宿主或隔离 uid 时该等式不成立",
     "java", "v0.1 基线"),
]

ROW_RE = re.compile(r"^\|\s*`([a-z][a-zA-Z0-9._]*)`\s*\|")


def parse_rows(text: str) -> list[tuple[str, str, str, int, str, str, str]]:
    out = []
    for line in text.splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cols) < 7:
            continue
        vid = cols[0].strip("`")
        out.append((vid, cols[1], cols[2], int(cols[3]) if cols[3].isdigit() else 3,
                    cols[4], cols[5], cols[6]))
    return out


def fix_notes(text: str) -> str:
    """把数不清的历史口径统一掉。"""
    text = text.replace("48 行主表", "53 行主表").replace("主表 **48 行**", "主表 **53 行**")
    text = text.replace("48 条", "53 条").replace("48 行", "53 行")
    return text


def main() -> int:
    text = DOC.read_text(encoding="utf-8")
    rows = parse_rows(text)
    have = {r[0] for r in rows}
    print(f"目录现有 {len(rows)} 条")

    missing = [r for r in NEW_ROWS if r[0] not in have]
    if missing:
        lines = text.splitlines()
        for vid, cat, tier, weight, why, dep, status in missing:
            prefix = {
                "runtime-integrity": "rt.", "injection": "inj.",
                "package-integrity": "pkg.", "privilege": "priv.",
                "virtualization": "virt.", "environment": "env.",
            }[cat]
            newline = f"| `{vid}` | {cat} | {tier} | {weight} | {why} | {dep} | {status} |"
            # 插到同类别的最后一行之后
            last = -1
            for i, ln in enumerate(lines):
                m = ROW_RE.match(ln)
                if m and ln.lstrip().startswith("| `" + prefix):
                    last = i
            if last < 0:
                print(f"  [!] 找不到 {prefix} 类别的表，跳过 {vid}")
                continue
            lines.insert(last + 1, newline)
            print(f"  [+] 插入 {vid} → 第 {last + 2} 行")
        text = "\n".join(lines) + "\n"
        text = fix_notes(text)
        DOC.write_text(text, encoding="utf-8")
        rows = parse_rows(text)
    else:
        print("无需插入")

    # 反向生成 vectors.json
    data = json.loads(VEC.read_text(encoding="utf-8"))
    old = {v["id"]: v for v in data.get("vectors", [])}
    # 人写的解释性字段（plain/bypass/fix）不在 docs 表里，重建时必须原样保留，
    # 否则每同步一次就要重新写 53 条人话。
    PRESERVE = ("plain", "bypass", "fix", "risk")

    def plane(vid: str, cat: str) -> str:
        if vid in old:
            return old[vid].get("plane", "self")
        if cat == "package-integrity" and vid in ("pkg.codepath.hash", "pkg.zip.fingerprint"):
            return "cli"
        if cat in ("privilege", "virtualization", "environment"):
            return "device"
        if vid in ("inj.frida.port", "inj.frida.socket", "inj.module.marker", "inj.module.paths"):
            return "device"
        return "self"

    entries = []
    for (vid, cat, tier, weight, why, _dep, _status) in rows:
        entry = {
            "id": vid, "category": cat, "plane": plane(vid, cat),
            "tier": tier, "weight": weight, "zh": why,
        }
        for k in PRESERVE:
            if vid in old and k in old[vid]:
                entry[k] = old[vid][k]
        entries.append(entry)
    data["vectors"] = entries
    data["count"] = len(entries)
    data["note"] = (
        "本文件由 tools/sync_vectors.py 从 docs/02-探针目录.md 的主表反向生成，"
        "不要手工编辑。目录 = 人工可读的唯一源；契约 §3 的命名规则约束 id 形态。"
    )
    VEC.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"vectors.json 已重建：{len(entries)} 条")

    by_cat: dict[str, int] = {}
    for e in entries:
        by_cat[e["category"]] = by_cat.get(e["category"], 0) + 1
    print("  " + " / ".join(f"{k}={v}" for k, v in by_cat.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
