#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
litmus_report.py —— 报告渲染层：终端摘要表 / report.md / report.html / matrix.md。

为什么单独一层
-------------
评分（litmus_score.py）与设备驱动（litmus.py）都可能想「把同一份 run.json 打印出来」，
渲染逻辑抽出来以后 selftest 可以不碰 adb 就把四种产物全部生成一遍。

硬约束（都踩过坑）
----------------
* report.html **单文件**：CSS 内联、不引 CDN、不引 JS 库。条形图用 div 宽度做，
  这样报告能离线看、能塞进 issue、能在没有网络的客户现场打开。
* 中文对齐：终端表格用显示宽度（CJK 记 2 列）算 padding，否则「运行时完整性」
  和 "injection" 会错位。
* 所有文本按 UTF-8 写出、`ensure_ascii=False`（中文 evidence 不能变成 \\uXXXX）。
"""

from __future__ import annotations

import html
import re
import sys
import unicodedata
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import litmus_narrative as N  # noqa: E402  同目录模块：只负责「人话」，不碰评分与 IO

VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# 配色：Material 3 深色 token（与 App 侧同一套色，报告和 App 是一个产品）
# ---------------------------------------------------------------------------

M3 = {
    "surface": "#141218",
    "surface-container-lowest": "#0F0D13",
    "surface-container-low": "#1D1B20",
    "surface-container": "#211F26",
    "surface-container-high": "#2B2930",
    "on-surface": "#E6E0E9",
    "on-surface-variant": "#CAC4D0",
    "outline": "#938F99",
    "outline-variant": "#49454F",
    "primary": "#D0BCFF",
    "on-primary": "#381E72",
    "primary-container": "#4F378B",
    "on-primary-container": "#EADDFF",
    "clean": "#B6F09C",
    "suspect": "#F9E2AF",
    "tampered": "#FFB4AB",
    "unknown": "#938F99",
}

VERDICT_COLOR = {
    "CLEAN": M3["clean"],
    "SUSPECT": M3["suspect"],
    "TAMPERED": M3["tampered"],
    "UNKNOWN": M3["unknown"],
    "ERROR": M3["primary"],
    "FLAKY": M3["on-surface-variant"],
}

VERDICT_LABEL_ZH = {
    "CLEAN": "干净",
    "SUSPECT": "可疑",
    "TAMPERED": "篡改",
    "UNKNOWN": "未测",
    "ERROR": "错误",
    "FLAKY": "不稳定",
}

TIER_LABEL_ZH = {"A": "A 不变量", "B": "B 交叉", "C": "C 特征"}

ANSI = {
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "magenta": "\033[35m",
    "blue": "\033[34m",
    "gray": "\033[90m",
}

ANSI_BY_VERDICT = {
    "CLEAN": "green",
    "SUSPECT": "yellow",
    "TAMPERED": "red",
    "UNKNOWN": "gray",
    "ERROR": "magenta",
    "FLAKY": "blue",
}


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def disp_width(text: str) -> int:
    """终端显示宽度：CJK / 全角记 2 列，其余 1 列。"""
    w = 0
    for ch in str(text):
        w += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return w


def pad(text: str, width: int, align: str = "left") -> str:
    text = str(text)
    fill = max(0, width - disp_width(text))
    if align == "right":
        return " " * fill + text
    if align == "center":
        left = fill // 2
        return " " * left + text + " " * (fill - left)
    return text + " " * fill


def paint(text: str, color: str | None, enabled: bool = True) -> str:
    if not enabled or not color or color not in ANSI:
        return text
    return ANSI[color] + text + ANSI["reset"]


def _rgba(hex_color: str, alpha: float) -> str:
    """把 #RRGGBB 变成 rgba()，用于徽章底色（M3 里没有现成的低透明度容器色）。"""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return "rgba(%d,%d,%d,%.2f)" % (r, g, b, alpha)


def score_color(score) -> str:
    """M3 分数色阶（与类别细条同一口径）：≥85 clean / 60–84 suspect / <60 tampered。

    用 85 而不是 90 作为分界，是因为模型的满分需要 6 类全部干净才可能达到；
    85 分意味着「已经有一类明显掉分」，这时候颜色就该从绿变黄。
    """
    if score is None:
        return M3["unknown"]
    s = float(score)
    if s >= 85:
        return M3["clean"]
    if s >= 60:
        return M3["suspect"]
    return M3["tampered"]


def score_color_name(score) -> str:
    """终端 ANSI 版本（终端只有 16 色，做同样的三段映射）。"""
    if score is None:
        return "gray"
    s = float(score)
    if s >= 85:
        return "green"
    if s >= 60:
        return "yellow"
    return "red"


def fmt_score(score) -> str:
    return "—" if score is None else ("%.1f" % float(score))


def short(text: str, n: int = 120) -> str:
    t = " ".join(str(text or "").split())
    return t if len(t) <= n else t[: n - 1] + "…"


def esc(text) -> str:
    return html.escape(str(text if text is not None else ""), quote=True)


def md_cell(text) -> str:
    """markdown 表格单元：竖线要转义，换行要压平。"""
    return short(str(text or "").replace("|", "\\|"), 80)


def _run_meta(run_json: dict) -> dict:
    run = run_json.get("run") or {}
    dev = run.get("device") or {}
    return {
        "label": run.get("label") or "unlabeled",
        "framework": run.get("framework") or "-",
        "profile": run.get("profile") or (run_json.get("score") or {}).get("profile") or "standard",
        "serial": dev.get("serial") or "-",
        "model": dev.get("model") or "",
        "sdk": dev.get("sdk"),
        "release": dev.get("release") or "",
        "started": run.get("startedAt") or "-",
        "finished": run.get("finishedAt") or "-",
        "mode": run.get("mode") or "live",
        "source": run.get("reportSource") or "-",
        "cliVersion": run.get("cliVersion") or VERSION,
    }


def _device_line(meta: dict) -> str:
    bits = [str(meta.get("serial") or "").strip()]
    if meta["model"]:
        bits.append(str(meta["model"]))
    if meta["sdk"]:
        bits.append("SDK %s" % meta["sdk"])
    if meta["release"]:
        bits.append("Android %s" % meta["release"])
    # 离线复算没有序列号（"-"），别让报告出现「设备 - / …」
    return " / ".join(b for b in bits if b and b != "-")


# ---------------------------------------------------------------------------
# 终端摘要
# ---------------------------------------------------------------------------


_BREAK_CHARS = "，、；：,.; "


def _wrap_zh(text: str, width: int) -> list:
    """按显示宽度折行（中文按 2 列算），返回**不带缩进**的行。

    两个细节（都是「读起来像不像人话」的问题）：
      * 不用 textwrap：它按字符数折，中文行会比英文行明显更宽，终端里会歪；
      * 到边界时**回退到最近的中文标点**再断（最多回退 14 列），
        否则会出现「掉得最 / 狠」这种把词劈开的断法。
    """
    out = []
    cur = []
    cur_w = 0
    for ch in text:
        if ch == "\n":
            out.append("".join(cur))
            cur, cur_w = [], 0
            continue
        w = disp_width(ch)
        if cur_w + w > width and cur:
            cut = len(cur)
            for back in range(1, min(30, len(cur)) + 1):
                if cur[-back] in _BREAK_CHARS:
                    candidate = len(cur) - back + 1
                    # 只有在「回退后这一行不至于太短」时才按标点断，
                    # 否则会出现半行空白的难看法；宁可硬断也不要掏空行。
                    if sum(disp_width(c) for c in cur[:candidate]) >= width * 0.62:
                        cut = candidate
                    break
            out.append("".join(cur[:cut]))
            rest = cur[cut:]
            cur = list(rest)
            cur_w = sum(disp_width(c) for c in cur)
        cur.append(ch)
        cur_w += w
    if cur:
        out.append("".join(cur))
    return out or [""]


def conclusion_lines(run_json: dict, docs=None, width: int = 88) -> list:
    """终端用的「结论 / 建议」三行（规范 §10）：表格上方先给判断。

    规范要的是 3 行：结论两段（包状态 + 盲区）+ 建议一行。终端窄，按显示宽度折行，
    但折出来的续行统一缩进对齐到正文起点，不要出现「掉\n  得最狠」这种断词。
    """
    concl = N.conclusion(run_json, docs).split("\n")
    lines = []
    first = True
    for para in concl[:2]:
        prefix = "结论：" if first else " " * 6
        first = False
        avail = max(24, width - disp_width(prefix))
        for i, ln in enumerate(_wrap_zh(para.replace("**", ""), avail)):
            lines.append((prefix if i == 0 else " " * 6) + ln)
    adv = N.advice_line(run_json)
    avail = max(24, width - disp_width("建议："))
    for i, ln in enumerate(_wrap_zh(adv, avail)):
        lines.append(("建议：" if i == 0 else " " * 6) + ln)
    return lines


def to_terminal(run_json: dict, color: bool = True, docs=None) -> str:
    """终端摘要：结论/建议三行 → 分数 → 类别表 → 盲区/误报。"""
    meta = _run_meta(run_json)
    score = run_json.get("score") or {}
    cats = score.get("categories") or []
    lines = []

    head = "Litmus · %s" % meta["label"]
    lines.append("")
    lines.append(paint(head, "bold", color) + paint("  profile=%s  framework=%s" % (meta["profile"], meta["framework"]), "dim", color))
    lines.append(paint("设备  ", "dim", color) + _device_line(meta))
    lines.append(paint("时间  ", "dim", color) + "%s → %s  (报告来源: %s)" % (meta["started"], meta["finished"], meta["source"]))

    # ---- 先给结论与建议（规范 §10：在表格上方，3 行）----
    lines.append("")
    for ln in conclusion_lines(run_json, docs):
        if ln.startswith("结论："):
            lines.append(paint("结论：", "bold", color) + ln[len("结论："):])
        elif ln.startswith("建议："):
            lines.append(paint("建议：", "cyan", color) + ln[len("建议："):])
        else:
            lines.append(ln)

    litmus = score.get("litmus")
    raw = score.get("raw")
    big = paint("%.1f" % float(litmus or 0.0), score_color_name(litmus), color)
    tail = "/100"
    if score.get("baseline"):
        b = score["baseline"]
        tail += "   基线归一：raw %s → litmus %s（baseline raw %s）" % (fmt_score(raw), fmt_score(litmus), fmt_score(b.get("raw")))
    lines.append("")
    lines.append(paint("Litmus Score  ", "dim", color) + paint(big, "bold", color) + paint(tail, "dim", color))
    lines.append("")

    # ---- 类别表 ----
    headers = ["类别", "分数", "篡改", "可疑", "干净", "未测", "权重"]
    rows = []
    for c in cats:
        rows.append(
            [
                "%s %s" % (c.get("label") or c.get("id"), ""),
                fmt_score(c.get("score")),
                str(c.get("tampered", 0)),
                str(c.get("suspect", 0)),
                str(c.get("clean", 0)),
                str((c.get("unknown", 0) or 0) + (c.get("error", 0) or 0) + (c.get("flaky", 0) or 0)),
                "%.2f" % float(c.get("weight") or 0.0),
            ]
        )
    widths = []
    for i, h in enumerate(headers):
        w = disp_width(h)
        for r in rows:
            w = max(w, disp_width(r[i]))
        widths.append(w)

    def fmt_row(cells, colors=None):
        out = []
        for i, cell in enumerate(cells):
            align = "right" if i > 0 else "left"
            text = pad(cell, widths[i], align)
            if colors and colors.get(i):
                text = paint(text, colors[i], color)
            out.append(text)
        return "  " + "  ".join(out)

    lines.append(paint(fmt_row(headers), "bold", color))
    lines.append(paint("  " + "  ".join("-" * w for w in widths), "dim", color))
    for r, c in zip(rows, cats):
        colors = {1: score_color_name(c.get("score"))}
        if not c.get("counted"):
            colors[1] = "gray"
        lines.append(fmt_row(r, colors))

    counts = score.get("counts") or {}
    if counts:
        lines.append("")
        lines.append(
            paint(
                "向量 %d 条：干净 %d / 可疑 %d / 篡改 %d / 未测 %d / 错误 %d / 不稳定 %d"
                % (
                    counts.get("total", 0),
                    counts.get("clean", 0),
                    counts.get("suspect", 0),
                    counts.get("tampered", 0),
                    counts.get("unknown", 0),
                    counts.get("error", 0),
                    counts.get("flaky", 0),
                ),
                "dim",
                color,
            )
        )

    pm = run_json.get("packageModified") or {}
    line = "包状态  "
    if pm.get("modified"):
        # 用人话，不把 cli-expect-mismatch 这种内部枚举直接甩给用户（§10）
        line += paint("已改动", "red", color) + paint("（%s）" % N.reason_phrase(pm), "dim", color)
    else:
        line += paint("未改动 / 无法确认", "green", color)
    lines.append(line)

    # ---- 盲区 ----
    bs = run_json.get("blindSpots") or []
    lines.append("")
    if bs:
        lines.append(paint("盲区 %d 类（包已改动，但整类一条都没抓到）" % len(bs), "yellow", color))
        for b in bs:
            vecs = "、".join(b.get("vectors") or [])
            lines.append("  " + paint("▸ " + str(b.get("label") or b.get("category")), "yellow", color) + paint("  " + short(vecs, 100), "dim", color))
    else:
        lines.append(paint("盲区 0 类", "green" if pm.get("modified") else "dim", color) + paint("（%s）" % ("包被改动、无一类别满分" if pm.get("modified") else "包未被改动，盲区判定不适用"), "dim", color))

    # ---- 误报 ----
    fps = run_json.get("falsePositives") or []
    if fps:
        lines.append("")
        lines.append(paint("误报 %d 条（包没动、基线里也 TAMPERED → 环境固有噪声，不扣分只标注）" % len(fps), "gray", color))
        for f in fps:
            lines.append("  " + paint("▸ " + str(f.get("vector")), "gray", color) + paint("  " + short(f.get("evidence"), 90), "dim", color))
    elif run_json.get("score", {}).get("baseline"):
        lines.append(paint("误报 0 条", "green", color))

    problems = run_json.get("validation") or []
    if problems:
        lines.append("")
        lines.append(paint("契约告警 %d 条：" % len(problems), "magenta", color))
        for p in problems[:8]:
            lines.append("  " + paint("! " + short(p, 150), "magenta", color))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 样式（Material 3 深色 token，与 App 同一套；单文件内联，无外链无字体 CDN）
# ---------------------------------------------------------------------------

_CSS = """
:root{
  --surface:#141218;
  --surface-container-lowest:#0F0D13;
  --surface-container-low:#1D1B20;
  --surface-container:#211F26;
  --surface-container-high:#2B2930;
  --on-surface:#E6E0E9;
  --on-surface-variant:#CAC4D0;
  --outline:#938F99;
  --outline-variant:#49454F;
  --primary:#D0BCFF;
  --on-primary:#381E72;
  --primary-container:#4F378B;
  --on-primary-container:#EADDFF;
  --clean:#B6F09C;
  --suspect:#F9E2AF;
  --tampered:#FFB4AB;
  --unknown:#938F99;
  --err:#D0BCFF;
  --flaky:#CAC4D0;
  --r:16px;
  --r-hero:28px;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--surface);
  color:var(--on-surface);
  font-family:system-ui,"Segoe UI","Microsoft YaHei",sans-serif;
  font-size:14px;line-height:1.6;
  padding:0 0 56px;
  -webkit-font-smoothing:antialiased;
}
.wrap{max-width:1120px;margin:0 auto;padding:0 20px}
code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:12.5px}

/* 顶部：只有色阶，不用阴影、不用边框 */
.topbar{padding:22px 0 18px}
.brand{display:flex;align-items:center;gap:10px;color:var(--on-surface-variant);font-size:12px;letter-spacing:.5px;text-transform:uppercase}
.brand .dot{width:8px;height:8px;border-radius:50%;background:var(--primary)}
.brand .eyebrow{color:var(--primary)}

/* hero 卡：大分数 + 元信息 */
.hero{background:var(--surface-container-low);border-radius:var(--r-hero);padding:26px 28px;margin-bottom:14px}
.hero-main{display:flex;align-items:flex-end;gap:32px;flex-wrap:wrap}
.scorebox{display:flex;align-items:baseline;gap:10px}
.score-num{font-size:64px;font-weight:500;letter-spacing:-.02em;line-height:1;font-variant-numeric:tabular-nums}
.score-den{font-size:15px;color:var(--on-surface-variant)}
.score-cap{color:var(--on-surface-variant);font-size:12px;margin-top:10px;max-width:320px}
.metagrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px 24px;flex:1;min-width:300px}
.meta-k{color:var(--on-surface-variant);font-size:11px;letter-spacing:.5px;text-transform:uppercase}
.meta-v{font-size:13px;word-break:break-all;margin-top:2px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:18px}
.chip{display:inline-block;padding:3px 12px;border-radius:999px;background:var(--surface-container-high);color:var(--on-surface-variant);font-size:12px}
.chip.clean{background:rgba(182,240,156,.16);color:var(--clean)}
.chip.tampered{background:rgba(255,180,171,.16);color:var(--tampered)}
.chip.suspect{background:rgba(249,226,175,.16);color:var(--suspect)}
.chip.primary{background:var(--primary-container);color:var(--on-primary-container)}

/* KPI 小卡 */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(112px,1fr));gap:10px;margin:14px 0}
.kpi{background:var(--surface-container-low);border-radius:var(--r);padding:14px 16px}
.kpi .n{font-size:24px;font-weight:500;font-variant-numeric:tabular-nums;line-height:1.2}
.kpi .k{color:var(--on-surface-variant);font-size:11.5px;margin-top:4px;letter-spacing:.3px}

section{margin:26px 0 0}
h2{font-size:15px;font-weight:500;margin:0 0 12px;display:flex;align-items:center;gap:10px}
h2 .idx{display:inline-block;min-width:22px;text-align:center;color:var(--on-primary-container);background:var(--primary-container);border-radius:8px;font-size:11.5px;font-weight:500;padding:1px 6px}
.hint{color:var(--on-surface-variant);font-size:12.5px;margin:-4px 0 12px}
.card{background:var(--surface-container-low);border-radius:var(--r);overflow:hidden}

/* 类别细条：3px 高，圆角，色随分数 */
.bars{padding:10px 20px 14px}
.bar-row{display:grid;grid-template-columns:180px 1fr 58px 132px;align-items:center;gap:16px;padding:12px 0;border-bottom:1px solid var(--outline-variant)}
.bar-row:last-child{border-bottom:none}
.bar-name{font-size:13px}
.bar-name small{display:block;color:var(--on-surface-variant);font-size:11px;letter-spacing:.2px}
.bar-track{height:3px;background:var(--surface-container-high);border-radius:999px;overflow:hidden}
.bar-fill{height:100%;border-radius:999px}
.bar-val{text-align:right;font-weight:500;font-variant-numeric:tabular-nums;font-size:14px}
.bar-cnt{color:var(--on-surface-variant);font-size:11.5px;text-align:right;white-space:nowrap}
.bar-row.na .bar-name,.bar-row.na .bar-val{color:var(--on-surface-variant)}

/* 表格：无竖线，只有行分隔 */
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:11px 16px;text-align:left;border:0;border-bottom:1px solid var(--outline-variant);vertical-align:top}
th{background:var(--surface-container);color:var(--on-surface-variant);font-weight:500;font-size:12px;letter-spacing:.5px;text-transform:uppercase}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--surface-container)}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:500;letter-spacing:.3px}
.ev{color:var(--on-surface-variant);word-break:break-word;font-size:12.5px}
.cli-mark{display:inline-block;margin-left:6px;padding:0 6px;border-radius:6px;font-size:10.5px;background:var(--primary-container);color:var(--on-primary-container)}

/* 盲区：--suspect 左边框 + surface-container-high 底；误报：--unknown */
.flag{border-radius:var(--r);padding:16px 20px;margin:0 0 10px;background:var(--surface-container-high)}
.flag.blind{border-left:3px solid var(--suspect)}
.flag.fp{border-left:3px solid var(--unknown)}
.flag h3{margin:0 0 8px;font-size:14px;font-weight:500}
.flag p{margin:0 0 8px;color:var(--on-surface-variant);font-size:13px}
.flag .ids{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.flag .ids code{background:var(--surface-container-lowest);border-radius:6px;padding:2px 8px;color:var(--on-surface)}
.empty{color:var(--on-surface-variant);padding:16px 20px;background:var(--surface-container-low);border-radius:var(--r)}
.facts{margin:0;padding:16px 20px;color:var(--on-surface-variant);font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
footer{color:var(--on-surface-variant);font-size:11.5px;padding-top:20px;margin-top:30px;border-top:1px solid var(--outline-variant)}
h1{font-size:22px;font-weight:500;margin:10px 0 6px}
.meta{color:var(--on-surface-variant);font-size:12.5px}
.meta code{background:var(--surface-container-high);border-radius:6px;padding:1px 6px}
p{margin:0 0 12px}
.note{color:var(--on-surface-variant);font-size:12.5px;background:var(--surface-container);border-radius:var(--r);padding:12px 16px}
h3.sub{font-size:14px;font-weight:500;margin:20px 0 10px;color:var(--on-surface)}
h4{font-size:13.5px;font-weight:500;margin:0 0 8px}
ul.plain{margin:0 0 12px;padding-left:22px;color:var(--on-surface-variant)}
ul.plain li{margin:4px 0}
.flag.bad{border-left:3px solid var(--tampered)}
.flag.blind{border-left:3px solid var(--suspect)}
.flag.fp{border-left:3px solid var(--unknown)}
.flag h4{margin:0 0 6px}
dl.fields{margin:6px 0 0;display:grid;grid-template-columns:max-content 1fr;gap:6px 14px}
dl.fields dt{color:var(--on-surface-variant);font-size:12.5px}
dl.fields dd{margin:0;font-size:13px}
.kpi .hint{color:var(--on-surface-variant);font-size:11px;margin-top:6px;line-height:1.45}
section{margin:30px 0 0}
"""

# ---------------------------------------------------------------------------
# 文档模型：md 与 html 的共同底座
# ---------------------------------------------------------------------------
#
# 为什么要先建模型再渲染（而不是各写一套模板）：规范 §7 要求两种产物的**段落顺序与
# 小标题必须一致**。只要两边都从同一份 `build_document()` 出发，这个一致性就是
# 构造出来的，不靠人工维护；selftest 还能直接把两边的小标题抓出来比对。
#
# 文本一律用「markdown 行内语法」（**粗体**、`代码`）存放：
#   * md 渲染器原样输出；
#   * html 渲染器走 md_inline() 转标签，并顺手把「中文（VERDICT）」渲染成彩色徽章。
# 这样文案只有一份，也不可能两边跑偏。

SECTION_TITLES = [
    ("conclusion", "① 一句话结论"),
    ("numbers", "② 三个数字"),
    ("changed", "③ 这次改了什么"),
    ("categories", "④ 逐类判断"),
    ("confirmed", "⑤ 被坐实的问题"),
    ("blind", "⑥ 我们看不见的地方"),
    ("noise", "⑦ 环境噪声"),
    ("actions", "⑧ 怎么让分数上去"),
    ("appendix", "⑨ 附录"),
]

# 术语表：R3 的落地方式 —— 结论词永远带解释，第一次出现就在这里定义
GLOSSARY = (
    "术语：干净（CLEAN）、可疑（SUSPECT）、被坐实（TAMPERED）、测不了（UNKNOWN）、"
    "探针出错（ERROR）、结果不稳定（FLAKY）。后三种不计分，也**不算干净**。"
    "tier 是证据强度：A 级=不变量/密码学，B 级=交叉视图，C 级=特征匹配（只能出可疑）。"
)


def _sig_table(signals, limit=None, columns=None, evidence_len: int = 120) -> dict:
    """向量小表：④ 的逐类明细与 ⑨ 的完整表共用一份列定义，避免各写一遍。

    columns 决定列的顺序与子集（④ 里「类别」恒等于当前分类，所以省掉那一列）。
    evidence_len 分开传，④ 用短证据（60）保持表格可读，⑨ 用长证据（120）留全信息。
    """
    cols = columns or ["id", "category", "tier", "verdict", "confidence", "weight", "plane", "evidence"]
    # 列定义：key -> (表头, 对齐, 取值)
    defs = {
        "id": ("id", "left", lambda s: "`%s`" % s.get("id")),
        "category": ("类别", "left", lambda s: str(s.get("category") or "")),
        "tier": ("tier", "left", lambda s: str(s.get("tier") or "")),
        "verdict": ("结论", "left", lambda s: N.verdict_label(s.get("verdict"))),
        "confidence": ("置信度", "right", lambda s: "%.2f" % float(s.get("confidence") or 0.0)),
        "weight": ("权重", "right", lambda s: str(int(s.get("weight") or 0))),
        "plane": ("平面", "left", lambda s: str(s.get("plane") or "app")),
        "evidence": ("证据", "left", lambda s: N.short(s.get("evidence"), evidence_len)),
    }
    rows = []
    for s in signals or []:
        if limit is not None and len(rows) >= limit:
            break
        rows.append([defs[c][2](s) for c in cols])
    return {
        "type": "table",
        "head": [defs[c][0] for c in cols],
        "rows": rows,
        "align": [defs[c][1] for c in cols],
    }


def _non_clean(signals, category: str) -> list:
    out = []
    for s in signals or []:
        if s.get("category") != category:
            continue
        if str(s.get("verdict") or "").upper() in ("CLEAN", "UNKNOWN"):
            continue
        out.append(s)
    return out


def build_document(run_json: dict, docs=None, paths=None) -> list:
    """run.json → 九段结构（纯数据）。docs = litmus_narrative.docs_from_catalog(...)。"""
    run_json = run_json or {}
    paths = paths or {}
    sc = run_json.get("score") or {}
    cats = sc.get("categories") or []
    counts = sc.get("counts") or {}
    signals = run_json.get("signals") or []
    blind = run_json.get("blindSpots") or []
    fps = run_json.get("falsePositives") or []
    tampered = [s for s in signals if str(s.get("verdict") or "").upper() == "TAMPERED"]
    sections = []

    # ---- ① 一句话结论 ----
    sec = {"key": "conclusion", "blocks": []}
    for line in N.conclusion(run_json, docs).split("\n"):
        if line.strip():
            sec["blocks"].append({"type": "para", "text": line})
    sec["blocks"].append({"type": "note", "text": GLOSSARY})
    sections.append(sec)

    # ---- ② 三个数字 ----
    litmus = sc.get("litmus")
    kpis = [
        {
            "label": "Litmus 分",
            "value": N.fmt_score(litmus),
            "hint": "越高说明我们越看不出来（100 = 一条篡改都没抓到）",
            "color": score_color(litmus),
        },
        {
            "label": "盲区类别",
            "value": "%d 类" % len(blind),
            "hint": "包被改过却整类满分的类别，见 ⑥" if blind else "没有整类失明",
            "color": M3["suspect"] if blind else M3["clean"],
        },
        {
            "label": "误报向量",
            "value": "%d 条" % len(fps),
            "hint": "包没被改，红的都是设备脏，见 ⑦" if fps else "没有需要豁免的红叉",
            "color": M3["unknown"] if fps else M3["clean"],
        },
    ]
    sections.append({"key": "numbers", "blocks": [{"type": "kpis", "items": kpis}]})

    # ---- ③ 这次改了什么 ----
    wc = N.what_changed(run_json, docs)
    blocks = [
        {"type": "para", "text": wc["summary"]},
        {
            "type": "table",
            "head": ["检查项", "构建产物（期望）", "本次实测", "结论"],
            "rows": wc["rows"],
            "align": ["left", "right", "right", "left"],
        },
        {
            "type": "note",
            "text": "哈希/指纹/签名这三项里，只要有一项对不上，就说明装上去的这份包不是我们构建的那一份。"
                    "签名只能证明「谁签的」，证明不了「内容没动」，所以两者都要看。",
        },
    ]
    sections.append({"key": "changed", "blocks": blocks})

    # ---- ④ 逐类判断 ----
    blocks = []
    for cat in cats:
        cid = str(cat.get("id") or "")
        blocks.append({
            "type": "subhead",
            "text": "%s（%s）· %s 分"
                    % (cat.get("label") or cid, cid, N.fmt_score(cat.get("score"))),
        })
        # lead=False：标题已经写了类别和分数，正文从「怎么构成的」讲起，不重复
        blocks.append({
            "type": "para",
            "text": N.category_story(cat, signals, litmus, run=run_json, docs=docs, lead=False),
        })
        interesting = _non_clean(signals, cid)
        if interesting:
            blocks.append(_sig_table(
                interesting, limit=6, evidence_len=60,
                columns=["id", "tier", "verdict", "confidence", "weight", "plane", "evidence"],
            ))
    if not cats:
        blocks.append({"type": "para", "text": "这次没有任何类别数据（报告里没有 signals）。"})
    sections.append({"key": "categories", "blocks": blocks})

    # ---- ⑤ 被坐实的问题 ----
    blocks = []
    if tampered:
        blocks.append({
            "type": "para",
            "text": "%d 条向量拿到了 A/B 级证据，直接判定为被改。每条都按「判据 / 证据 / 意味着什么 / 怎么修」写清楚。"
                    % len(tampered),
        })
        for s in tampered:
            item = N.confirmed_item(s, docs)
            blocks.append({
                "type": "callout",
                "kind": "bad",
                "title": item["title"],
                "fields": item["fields"],
            })
    else:
        blocks.append({
            "type": "para",
            "text": "这次没有一条被坐实 —— 要么包确实没被改，要么改动只留下了「可疑」级别的痕迹（见 ④ 里的可疑项）。",
        })
    sections.append({"key": "confirmed", "blocks": blocks})

    # ---- ⑥ 我们看不见的地方 ----
    blocks = []
    if blind:
        blocks.append({
            "type": "para",
            "text": "盲区（blind spot）= 包**确实被改过**，但整类检测一条都没抓到。"
                    "这是我们要补的洞，不是用户的错。下面每一类都给出「为什么可能是洞」和「怎么验证是不是洞」。",
        })
        for b in blind:
            blocks.append({
                "type": "callout",
                "kind": "blind",
                "title": "⚠ %s（%s）· %s 分 · %d 条向量全干净"
                         % (b.get("label") or b.get("category"), b.get("category"),
                            N.fmt_score(b.get("score")), len(b.get("vectors") or [])),
                "paras": [p for p in N.blindspot_story(b, signals, docs, run_json).split("\n\n") if p.strip()],
            })
    elif (run_json.get("packageModified") or {}).get("modified"):
        blocks.append({"type": "para", "text": "这次包被改过，但六类都至少动了一下 —— 没有整类失明，这是好消息。"})
    else:
        blocks.append({
            "type": "para",
            "text": "这次包没被改，盲区判定不适用（盲区的前提是「包确实被改过」）。"
                    "要检查盲区，请先跑一次带修补的对照运行。",
        })
    sections.append({"key": "blind", "blocks": blocks})

    # ---- ⑦ 环境噪声 ----
    blocks = [{"type": "para", "text": p} for p in N.noise_story(run_json, docs).split("\n\n") if p.strip()]
    sections.append({"key": "noise", "blocks": blocks})

    # ---- ⑧ 怎么让分数上去 ----
    actions = N.action_list(run_json, docs)
    blocks = [{
        "type": "note",
        "text": "收益怎么算的：把某一类补到 100 分（或修掉一条红叉）后，按 profile 的类别权重折算成总分变化。"
                "**所有数字都是估算**，不含「改完之后检测能力是否真的变强」这层不确定性。",
    }]
    if actions:
        rows = []
        for a in actions:
            rows.append([
                a.get("title") or "",
                a.get("why") or "",
                "**%s**" % N.gain_label(a),
                a.get("cost") or "-",
                a.get("how") or "",
            ])
        blocks.append({
            "type": "table",
            "head": ["做什么", "为什么", "预计收益", "成本", "怎么做"],
            "rows": rows,
            "align": ["left", "left", "left", "left", "left"],
        })
    else:
        blocks.append({"type": "para", "text": "没有可执行的提分项：六类都满分，或者所有红叉都来自环境噪声。"})
    sections.append({"key": "actions", "blocks": blocks})

    # ---- ⑨ 附录 ----
    blocks = []
    blocks.append({"type": "subhead", "text": "完整向量表（%d 条，含干净项）" % len(signals)})
    blocks.append(_sig_table(signals))
    blocks.append({"type": "subhead", "text": "复现这条结果"})

    run_dir = paths.get("dir") or "<这次运行的目录>"
    raw_path = paths.get("raw") or (run_dir + "\\report.raw.json")
    expect_path = (run_json.get("run") or {}).get("expectPath") or "canary\\out\\build-info.json"
    baseline_path = (run_json.get("run") or {}).get("baselinePath")
    cmd = ["python cli\\litmus.py score --report %s --expect %s" % (raw_path, expect_path)]
    if baseline_path:
        cmd[0] += " --baseline %s" % baseline_path
    blocks.append({
        "type": "code",
        "text": cmd[0] + "\n# 输出到目录：\npython cli\\litmus.py score --report %s --expect %s --save %s"
                        % (raw_path, expect_path, run_dir),
    })
    coverage = run_json.get("coverage") or {}
    chk = run_json.get("appSummaryCheck") or {}
    bullets = [
        "本次运行：`%s`（%s）· profile `%s` · CLI %s"
        % ((run_json.get("run") or {}).get("label"), (run_json.get("run") or {}).get("framework"),
           (run_json.get("run") or {}).get("profile"), (run_json.get("run") or {}).get("cliVersion")),
        "报告来源：`%s` · App 侧运行 id `%s`"
        % ((run_json.get("run") or {}).get("reportSource"), (run_json.get("run") or {}).get("appRunId") or "-"),
        "构建产物：`%s` · %s · 构建于 %s"
        % ((run_json.get("expect") or {}).get("apk"), (run_json.get("expect") or {}).get("version"),
           (run_json.get("expect") or {}).get("builtAt") or "未知"),
        "原始数据：`%s`（全量记账）与 `%s`（App 原始报告）"
        % (paths.get("json") or (run_dir + "\\run.json"), raw_path),
    ]
    if coverage:
        bullets.append(
            "向量覆盖率：目录声明 %s 条，本次上报 %s 条；未上报 %d 条（%s）"
            % (coverage.get("declared"), coverage.get("present"), len(coverage.get("missing") or []),
               "、".join("`%s`" % v for v in (coverage.get("missing") or [])[:8]) or "无")
        )
    if chk.get("checked"):
        bullets.append(
            "评分一致性：App 自算 %s 分 vs CLI 重算 %s 分（差 %s）—— %s"
            % (N.fmt_score(chk.get("appScore")), N.fmt_score(chk.get("cliScore")),
               chk.get("scoreDelta"), "一致" if chk.get("match") else "**不一致，说明两侧公式漂了**")
        )
    problems = run_json.get("validation") or []
    if problems:
        bullets.append("契约告警 %d 条：%s" % (len(problems), "；".join(problems[:5])))
    blocks.append({"type": "bullets", "items": bullets})
    sections.append({"key": "appendix", "blocks": blocks})

    # 统一补上标题（顺序即 SECTION_TITLES 的顺序）
    by_key = {s["key"]: s for s in sections}
    ordered = []
    for key, title in SECTION_TITLES:
        sec = by_key.get(key) or {"key": key, "blocks": []}
        sec["title"] = title
        ordered.append(sec)
    return ordered


# ---------------------------------------------------------------------------
# md 渲染
# ---------------------------------------------------------------------------


def _md_cell(text) -> str:
    return N.gloss_verdicts(str(text or "")).replace("|", "\\|").replace("\n", " ")


def _render_md_blocks(blocks) -> list:
    out = []
    for b in blocks or []:
        t = b.get("type")
        if t == "para":
            out.append(N.gloss_verdicts(b.get("text")))
            out.append("")
        elif t == "note":
            out.append("> %s" % N.gloss_verdicts(b.get("text")))
            out.append("")
        elif t == "subhead":
            out.append("### %s" % N.gloss_verdicts(b.get("text")))
            out.append("")
        elif t == "bullets":
            for it in b.get("items") or []:
                out.append("- %s" % N.gloss_verdicts(it))
            out.append("")
        elif t == "kpis":
            items = b.get("items") or []
            out.append("| " + " | ".join(_md_cell(i.get("label")) for i in items) + " |")
            out.append("| " + " | ".join("---:" for _ in items) + " |")
            out.append("| " + " | ".join("**%s**" % _md_cell(i.get("value")) for i in items) + " |")
            out.append("| " + " | ".join(_md_cell(i.get("hint")) for i in items) + " |")
            out.append("")
        elif t == "table":
            head = b.get("head") or []
            rows = b.get("rows") or []
            if not rows:
                out.append("_（无内容）_")
                out.append("")
                continue
            out.append("| " + " | ".join(_md_cell(h) for h in head) + " |")
            out.append("| " + " | ".join(
                "---:" if (b.get("align") or [])[i:i + 1] == ["right"] else "---"
                for i in range(len(head))) + " |")
            for r in rows:
                out.append("| " + " | ".join(_md_cell(c) for c in r) + " |")
            out.append("")
        elif t == "callout":
            out.append("#### %s" % N.gloss_verdicts(b.get("title")))
            out.append("")
            for p in b.get("paras") or []:
                out.append(N.gloss_verdicts(p))
                out.append("")
            for k, v in b.get("fields") or []:
                out.append("- **%s**：%s" % (k, N.gloss_verdicts(v)))
            if b.get("fields"):
                out.append("")
        elif t == "code":
            out.append("```powershell")
            out.append(str(b.get("text") or ""))
            out.append("```")
            out.append("")
    return out


def render_markdown(run_json: dict, docs=None, paths=None) -> str:
    meta = _run_meta(run_json)
    sections = build_document(run_json, docs=docs, paths=paths)
    L = ["# Litmus 检测报告 · %s" % meta["label"], ""]
    L.append("> %s ｜ profile `%s` ｜ 框架 `%s` ｜ %s ｜ 报告来源 `%s`"
             % (_device_line(meta), meta["profile"], meta["framework"], meta["started"], meta["source"]))
    L.append("")
    for sec in sections:
        L.append("## %s" % sec["title"])
        L.append("")
        L.extend(_render_md_blocks(sec.get("blocks")))
    L.append("---")
    L.append("")
    L.append("由 Litmus CLI %s 生成 · schema litmus.run/1 · 评分口径与 canary/io/litmus/core/Score.java 一致。"
             % meta["cliVersion"])
    L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# html 渲染（单文件自包含：内联 CSS、无外链、无 <script>）
# ---------------------------------------------------------------------------

_MD_BOLD = re.compile(r"\*\*(.+?)\*\*")
_MD_CODE = re.compile(r"`([^`]+)`")
_BADGE = re.compile(r"(被坐实|干净|可疑|测不了|探针出错|结果不稳定)（(TAMPERED|CLEAN|SUSPECT|UNKNOWN|ERROR|FLAKY)）")


def md_inline(text) -> str:
    """markdown 行内语法 → html。同时把「中文（VERDICT）」变成彩色徽章。"""
    s = esc(N.gloss_verdicts(text))
    s = _BADGE.sub(lambda m: _badge_html(m.group(2), m.group(1) + "（" + m.group(2) + "）"), s)
    s = _MD_BOLD.sub(r"<strong>\1</strong>", s)
    s = _MD_CODE.sub(r"<code>\1</code>", s)
    return s


def _badge_html(verdict: str, label: str) -> str:
    v = str(verdict or "UNKNOWN").upper()
    color = VERDICT_COLOR.get(v, M3["unknown"])
    return '<span class="badge" style="color:%s;background:%s">%s</span>' % (color, _rgba(color, 0.16), esc(label))


def _render_html_blocks(blocks) -> str:
    out = []
    for b in blocks or []:
        t = b.get("type")
        if t == "para":
            out.append("<p>%s</p>" % md_inline(b.get("text")))
        elif t == "note":
            out.append('<p class="note">%s</p>' % md_inline(b.get("text")))
        elif t == "subhead":
            out.append('<h3 class="sub">%s</h3>' % md_inline(b.get("text")))
        elif t == "bullets":
            items = "".join("<li>%s</li>" % md_inline(it) for it in b.get("items") or [])
            out.append('<ul class="plain">%s</ul>' % items)
        elif t == "kpis":
            cells = []
            for i in b.get("items") or []:
                cells.append(
                    '<div class="kpi"><div class="n" style="color:%s">%s</div>'
                    '<div class="k">%s</div><div class="hint">%s</div></div>'
                    % (i.get("color") or M3["on-surface"], md_inline(i.get("value")),
                       md_inline(i.get("label")), md_inline(i.get("hint")))
                )
            out.append('<div class="kpis">%s</div>' % "".join(cells))
        elif t == "table":
            head = b.get("head") or []
            rows = b.get("rows") or []
            align = b.get("align") or []
            if not rows:
                out.append('<div class="card"><div class="empty">（无内容）</div></div>')
                continue
            th = "".join(
                '<th%s>%s</th>' % (' class="num"' if align[i:i + 1] == ["right"] else "", md_inline(h))
                for i, h in enumerate(head)
            )
            trs = []
            for r in rows:
                tds = "".join(
                    '<td%s>%s</td>' % (' class="num"' if align[i:i + 1] == ["right"] else "", md_inline(c))
                    for i, c in enumerate(r)
                )
                trs.append("<tr>%s</tr>" % tds)
            out.append('<div class="card"><table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>'
                       % (th, "".join(trs)))
        elif t == "callout":
            kind = b.get("kind") or "bad"
            parts = ['<div class="flag %s">' % kind, "<h4>%s</h4>" % md_inline(b.get("title"))]
            for p in b.get("paras") or []:
                parts.append("<p>%s</p>" % md_inline(p))
            fields = b.get("fields") or []
            if fields:
                parts.append('<dl class="fields">')
                for k, v in fields:
                    parts.append("<dt>%s</dt><dd>%s</dd>" % (md_inline(k), md_inline(v)))
                parts.append("</dl>")
            parts.append("</div>")
            out.append("".join(parts))
        elif t == "code":
            out.append('<div class="card"><pre class="facts">%s</pre></div>' % esc(b.get("text")))
    return "\n".join(out)


def render_html(run_json: dict, docs=None, paths=None) -> str:
    """单文件 report.html：Material 3 深色 token、内联 CSS、零外部依赖、零 JS。"""
    meta = _run_meta(run_json)
    sc = run_json.get("score") or {}
    counts = sc.get("counts") or {}
    pm = run_json.get("packageModified") or {}
    sections = build_document(run_json, docs=docs, paths=paths)
    litmus = sc.get("litmus")

    chips = ['<span class="chip primary">profile %s</span>' % esc(meta["profile"])]
    chips.append('<span class="chip %s">%s</span>'
                 % (("tampered", "包已改动") if pm.get("modified") else ("clean", "包未改动")))
    if sc.get("baseline"):
        chips.append('<span class="chip">基线 raw %s</span>' % esc(N.fmt_score((sc.get("baseline") or {}).get("raw"))))
    chips.append('<span class="chip">%s 条向量</span>' % esc(counts.get("total", 0)))

    body = []
    for sec in sections:
        body.append('<section id="%s"><h2>%s</h2>%s</section>'
                    % (sec["key"], esc(sec["title"]), _render_html_blocks(sec.get("blocks"))))

    parts = []
    parts.append('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    parts.append("<title>Litmus 检测报告 · %s</title>" % esc(meta["label"]))
    parts.append("<style>%s</style></head><body>" % _CSS)
    parts.append('<div class="wrap">')
    parts.append(
        '<div class="topbar"><div class="brand"><span class="dot"></span>'
        "<span>ARGUS</span><span>·</span><span>百眼检测</span>"
        '<span class="eyebrow">Tamper Detection Report</span></div>'
        "<h1>%s</h1>"
        '<div class="meta">%s ｜ 框架 %s ｜ %s ｜ 报告来源 <code>%s</code></div>'
        "</div>"
        % (esc(meta["label"]), esc(_device_line(meta)), esc(meta["framework"]),
           esc(meta["started"]), esc(meta["source"]))
    )
    parts.append('<div class="hero"><div class="hero-main">')
    parts.append(
        '<div><div class="scorebox"><div class="score-num" style="color:%s">%s</div>'
        '<div class="score-den">/ 100</div></div>'
        '<div class="score-cap">分值越高 = 我们越看不出来；满分不等于「没问题」，可能是「没抓到」。</div></div>'
        % (score_color(litmus), esc(N.fmt_score(litmus)))
    )
    parts.append('<div class="metagrid">')
    for k, v in (
        ("开始", meta["started"]),
        ("结束", meta["finished"]),
        ("raw 分", N.fmt_score(sc.get("raw"))),
        ("CLI 版本", meta["cliVersion"]),
    ):
        parts.append('<div><div class="meta-k">%s</div><div class="meta-v">%s</div></div>' % (esc(k), esc(v)))
    parts.append("</div></div>")
    parts.append('<div class="chips">%s</div>' % "".join(chips))
    parts.append("</div>")
    parts.append("".join(body))
    parts.append(
        "<footer>由 Litmus CLI %s 生成 · schema litmus.run/1 · 评分口径与 canary/io/litmus/core/Score.java 一致 · "
        "Material 3 · 单文件自包含，无外部依赖、无脚本。</footer>" % esc(meta["cliVersion"])
    )
    parts.append("</div></body></html>")
    return "".join(parts)


def to_markdown(run_json: dict, docs=None, paths=None) -> str:
    """对外入口（保持旧签名兼容）：给人看的 report.md。"""
    return render_markdown(run_json, docs=docs, paths=paths)


def to_html(run_json: dict, docs=None, paths=None) -> str:
    """对外入口（保持旧签名兼容）：单文件自包含的 report.html。"""
    return render_html(run_json, docs=docs, paths=paths)


# ---------------------------------------------------------------------------
# matrix：跨运行对比
# ---------------------------------------------------------------------------

_ABBR = {"CLEAN": "CLEAN", "SUSPECT": "SUSP", "TAMPERED": "TAMP", "UNKNOWN": "UNKN", "ERROR": "ERR", "FLAKY": "FLKY"}


def matrix_markdown(entries, all_clean=None, title: str = "runs", coverage=None) -> str:
    """entries: [{"label","path","run_json"}...]（按 label 排序后传入）。

    产出两张表：
      1. 类别分行 × label 列（分数）—— 看「这一次哪一类塌了」；
      2. 向量分行 × label 列（verdict 缩写）—— 看「哪条检测从来没动过」。
    末尾标记「所有运行都 CLEAN」的向量：一个对所有修补都无动于衷的向量，
    要么实现是假的，要么它检测的东西这次没人碰 —— 回归时必须点出来。
    """
    labels = [e["label"] for e in entries]
    L = []
    L.append("# Litmus 运行矩阵 · %s" % title)
    L.append("")
    L.append("共 %d 次运行：%s" % (len(entries), "、".join("`%s`" % x for x in labels)))
    L.append("")

    # ---- 总分 ----
    L.append("## 总分")
    L.append("")
    L.append("| 运行 | profile | Litmus | raw | 篡改 | 可疑 | 干净 | 盲区 | 误报 | 包状态 |")
    L.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
    for e in entries:
        rj = e["run_json"]
        sc = rj.get("score") or {}
        cnt = sc.get("counts") or {}
        pm = rj.get("packageModified") or {}
        L.append(
            "| `%s` | %s | **%s** | %s | %d | %d | %d | %d | %d | %s |"
            % (
                e["label"], esc_meta(rj.get("run", {}).get("profile")), fmt_score(sc.get("litmus")),
                fmt_score(sc.get("raw")), cnt.get("tampered", 0), cnt.get("suspect", 0), cnt.get("clean", 0),
                len(rj.get("blindSpots") or []), len(rj.get("falsePositives") or []),
                "改动" if pm.get("modified") else "未动",
            )
        )
    L.append("")

    # ---- 类别分 ----
    cat_ids = []
    for e in entries:
        for c in (e["run_json"].get("score") or {}).get("categories") or []:
            if c.get("id") not in cat_ids:
                cat_ids.append(c.get("id"))
    L.append("## 类别分")
    L.append("")
    L.append("| 类别 | %s |" % " | ".join(labels))
    L.append("| --- | %s |" % " | ".join("---:" for _ in labels))
    for cid in cat_ids:
        cells = []
        for e in entries:
            got = None
            for c in (e["run_json"].get("score") or {}).get("categories") or []:
                if c.get("id") == cid:
                    got = c.get("score")
                    break
            cells.append(fmt_score(got))
        L.append("| `%s` | %s |" % (cid, " | ".join(cells)))
    L.append("")

    # ---- 向量矩阵 ----
    vec_ids = []
    cat_of = {}
    for e in entries:
        for s in e["run_json"].get("signals") or []:
            sid = s.get("id")
            if sid not in vec_ids:
                vec_ids.append(sid)
            cat_of.setdefault(sid, s.get("category"))
    L.append("## 向量 verdict 矩阵")
    L.append("")
    L.append("缩写：CLEAN / SUSP 可疑 / TAMP 篡改 / UNKN 未测 / ERR 错误 / FLKY 不稳定 / — 本次报告没有该向量")
    L.append("")
    L.append("| 向量 | 类别 | %s | 备注 |" % " | ".join(labels))
    L.append("| --- | --- | %s | --- |" % " | ".join("---" for _ in labels))
    for vid in vec_ids:
        cells = []
        flags = set()
        for e in entries:
            hit = None
            for s in e["run_json"].get("signals") or []:
                if s.get("id") == vid:
                    hit = s
                    break
            if hit is None:
                cells.append("—")
            else:
                cells.append(_ABBR.get(str(hit.get("verdict")), str(hit.get("verdict"))))
                flags.add(str(hit.get("verdict")))
        note = ""
        if flags == {"CLEAN"}:
            note = "**全程 CLEAN**"
        elif "TAMPERED" in flags:
            note = "抓到篡改"
        elif flags == {"UNKNOWN"} or flags == {"UNKNOWN", "CLEAN"}:
            note = "未测（覆盖率缺口）"
        L.append("| `%s` | %s | %s | %s |" % (vid, cat_of.get(vid) or "", " | ".join(cells), note))
    L.append("")

    # ---- 全程 CLEAN 清单 ----
    if all_clean is None:
        all_clean = []
        for vid in vec_ids:
            clean_everywhere = True
            seen = False
            for e in entries:
                hit = None
                for s in e["run_json"].get("signals") or []:
                    if s.get("id") == vid:
                        hit = s
                        break
                if hit is not None:
                    seen = True
                    if str(hit.get("verdict")) != "CLEAN":
                        clean_everywhere = False
                        break
            if seen and clean_everywhere:
                all_clean.append(vid)

    L.append("## 所有运行都 CLEAN 的向量（%d）—— 疑似检测能力缺失" % len(all_clean))
    L.append("")
    if all_clean:
        L.append("> 这些向量在**每一次**运行里都是 CLEAN。要么实现没生效（永远返回 CLEAN），")
        L.append("> 要么本次矩阵覆盖的修补手段确实没碰它们（那就再补一个更强的修补样本）。")
        L.append("")
        for vid in all_clean:
            L.append("- `%s` · %s" % (vid, cat_of.get(vid) or ""))
    else:
        L.append("无。")
    L.append("")

    # ---- 目录覆盖率（声明了但一次都没出现过的向量）----
    if coverage:
        missing = coverage.get("missing") or []
        L.append("## 目录覆盖率：声明 %d / 出现 %d / 从未出现 %d" % (
            coverage.get("declared", 0), coverage.get("present", 0), len(missing)))
        L.append("")
        if missing:
            L.append("> 这些向量写在 `schema/vectors.json`（= 契约 §3）里，但**所有**运行都没有上报过它们。")
            L.append("> 说明探针还没实现 / 被 ProbeRegistry 漏掉 / 或者只在某些设备上才注册。")
            L.append("")
            for vid in missing:
                cid = None
                for c in ("runtime-integrity", "injection", "package-integrity", "privilege", "virtualization", "environment"):
                    if vid.startswith({"runtime-integrity": "rt.", "injection": "inj.", "package-integrity": "pkg.",
                                       "privilege": "priv.", "virtualization": "virt.", "environment": "env."}[c]):
                        cid = c
                        break
                L.append("- `%s` · %s" % (vid, cid or ""))
        else:
            L.append("全部声明向量都至少出现过一次。")
        L.append("")
    return "\n".join(L)


def esc_meta(value) -> str:
    v = str(value or "-")
    return v.replace("|", "\\|")
