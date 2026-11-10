#!/usr/bin/env python3
"""从 schema/vectors.json 生成 canary/src/io/litmus/core/VectorDocs.java。

为什么生成而不是手写：App 的详情卡文案、报告的「意味着什么」、文档的判据，
必须永远说的是同一件事。vectors.json 是唯一源，这里是它在 App 侧的投影。

字段：
    zh     一句话判据（来自 docs/02 主表，必填）
    plain  人话解释：这条红了意味着什么（缺失时回落 zh）
    bypass 怎么绕过 / 绕过会踩到哪条别的向量（缺失时给占位提示）

用法：
    python tools/gen_vector_docs.py           # 生成
    python tools/gen_vector_docs.py --check   # 只校验是否需要重新生成（CI 用）
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VEC = ROOT / "schema" / "vectors.json"
OUT = ROOT / "canary" / "src" / "io" / "litmus" / "core" / "VectorDocs.java"

HEADER = """package io.litmus.core;

import java.util.HashMap;
import java.util.Map;

/**
 * 向量的人话文案（构建期由 tools/gen_vector_docs.py 从 schema/vectors.json 生成）。
 *
 * <p><b>不要手工编辑本文件</b>：改 schema/vectors.json 里对应条目的
 * {@code zh} / {@code plain} / {@code bypass}，然后重跑生成器。
 *
 * <p>App 详情卡与 CLI 报告读的是同一份文案，这是「说法一致」的工程保证。
 */
public final class VectorDocs {

    private static final Map<String, String[]> DOC = new HashMap<>();

    static {
"""

FOOTER = """    }

    private VectorDocs() {
    }

    private static String get(String id, int idx) {
        if (id == null) {
            return "";
        }
        String[] v = DOC.get(id);
        return (v == null || idx >= v.length || v[idx] == null) ? "" : v[idx];
    }

    /** 一句话判据。 */
    public static String zh(String id) {
        return get(id, 0);
    }

    /** 人话解释：这条红了意味着什么（没有时回落判据）。 */
    public static String plain(String id) {
        String s = get(id, 1);
        return s.isEmpty() ? zh(id) : s;
    }

    /** 怎么绕过 / 绕过会踩到哪条别的向量。 */
    public static String bypass(String id) {
        String s = get(id, 2);
        return s.isEmpty()
                ? "暂无已整理的绕过路径；按「不变量」思路，要让它变绿必须同时让相关等式重新成立。"
                : s;
    }

    public static int size() {
        return DOC.size();
    }
}
"""

PLACEHOLDER_BYPASS = ""


def jstr(s: str) -> str:
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def render(data: dict) -> str:
    lines = [HEADER]
    for v in data["vectors"]:
        vid = v["id"]
        zh = v.get("zh", "")
        plain = v.get("plain", "")
        bypass = v.get("bypass", PLACEHOLDER_BYPASS)
        lines.append(
            f"        DOC.put({jstr(vid)},\n"
            f"                new String[]{{{jstr(zh)}, {jstr(plain)}, {jstr(bypass)}}});\n"
        )
    lines.append(FOOTER)
    return "".join(lines)


def main() -> int:
    check = "--check" in sys.argv
    data = json.loads(VEC.read_text(encoding="utf-8"))
    content = render(data)

    if check:
        if not OUT.exists():
            print(f"[FAIL] 缺少 {OUT.name}，请运行 python tools/gen_vector_docs.py")
            return 1
        if OUT.read_text(encoding="utf-8") != content:
            print(f"[FAIL] {OUT.name} 与 schema/vectors.json 不同步")
            return 1
        print(f"[OK] {OUT.name} 与 vectors.json 同步（{len(data['vectors'])} 条）")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(content, encoding="utf-8")

    missing_plain = [v["id"] for v in data["vectors"] if not v.get("plain")]
    missing_bypass = [v["id"] for v in data["vectors"] if not v.get("bypass")]
    print(f"已生成 {OUT.relative_to(ROOT)}：{len(data['vectors'])} 条")
    if missing_plain:
        print(f"  ! 缺 plain（会回落 zh）：{len(missing_plain)} 条 → {', '.join(missing_plain[:6])}…")
    if missing_bypass:
        print(f"  ! 缺 bypass（用占位文案）：{len(missing_bypass)} 条")
    return 0


if __name__ == "__main__":
    sys.exit(main())
