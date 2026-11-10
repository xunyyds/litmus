#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
litmus_score.py —— Litmus 评分核心（CLI 权威实现）。

为什么这些决策长这样
--------------------
1. **公式必须与 `canary/src/io/litmus/core/Score.java` 逐位一致。**
   契约（docs/04-契约.md §0）写明「CLI 是权威」，但 App 也会给界面一个同样的数字；
   两边一旦有 1% 差异，用户就会认为工具本身不可信。因此这里刻意复刻 Java 的三处细节：
     * 类别权重顺序（Java 用 LinkedHashMap，输出顺序即声明顺序）；
     * `Math.round(v*10)/10` 的四舍五入语义（= floor(v*10+0.5)/10，正数域），
       不能用 Python 的 `round()`（银行家舍入，0.25 会舍成 0.2）；
     * **类别分不四舍五入就参与加权求和**，只有写进输出时才 round1。
       Java 里 `weightedSum += a * catScore` 用的是全精度 catScore，这里照做。
2. **不碰设备、不碰网络、不 import 第三方库。** 它是 `selftest` / `score` / `demo` 的共用底座，
   必须在「没有设备、没有 APK」的机器上也能算分。
3. **包完整性有两条信号只在 CLI 平面产生。** App 烘不进「自己的哈希」——
   改了包必然改哈希，自证没有意义（契约 §1.2 / §3 把 pkg.codepath.hash、pkg.zip.fingerprint
   标注为 "CLI 判"）。这两条由 `cli_plane_signals()` 生成，plane=cli，tier=A，weight=5。
4. **盲区/误报是本产品的卖点，不是附属统计。** 见 `blind_spots()` / `false_positives()` 的注释。
"""

from __future__ import annotations

import hashlib
import json
import math
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# schema 常量（契约 §4.1 / §4.2，构建产物见 build-info.json）
# ---------------------------------------------------------------------------

SCHEMA_REPORT = "litmus.report/1"
SCHEMA_RUN = "litmus.run/1"
SCHEMA_BUILD = "litmus.build/1"
SCHEMA_VECTORS = "litmus.vectors/1"

# ---------------------------------------------------------------------------
# 结论（契约 §1.1）
# ---------------------------------------------------------------------------

CLEAN = "CLEAN"
SUSPECT = "SUSPECT"
TAMPERED = "TAMPERED"
UNKNOWN = "UNKNOWN"
ERROR = "ERROR"
FLAKY = "FLAKY"

VERDICTS = (CLEAN, SUSPECT, TAMPERED, UNKNOWN, ERROR, FLAKY)

# 只有这三类进分母。UNKNOWN / ERROR / FLAKY 不计分母但计数（契约 §2 + 评分模型）。
COUNTABLE_VERDICTS = (CLEAN, SUSPECT, TAMPERED)

# 单条 signal 污染度 s
POLLUTION = {TAMPERED: 1.0, SUSPECT: 0.5, CLEAN: 0.0}

# ---------------------------------------------------------------------------
# 六类与权重（契约 §2.1）。顺序必须与 Score.java 的 CATEGORY_WEIGHT 声明顺序一致。
# ---------------------------------------------------------------------------

CATEGORY_ORDER = (
    "runtime-integrity",
    "injection",
    "package-integrity",
    "privilege",
    "virtualization",
    "environment",
)

CATEGORY_LABELS_ZH = {
    "runtime-integrity": "运行时完整性",
    "injection": "注入痕迹",
    "package-integrity": "包完整性",
    "privilege": "提权面",
    "virtualization": "虚拟化/多开",
    "environment": "环境面",
}

# id 前缀 ↔ category 一一对应（契约 §2.1），用于校验 App 上报自相矛盾的报告
CATEGORY_PREFIX = {
    "runtime-integrity": "rt.",
    "injection": "inj.",
    "package-integrity": "pkg.",
    "privilege": "priv.",
    "virtualization": "virt.",
    "environment": "env.",
}

DEFAULT_WEIGHTS = {
    "runtime-integrity": 0.24,
    "injection": 0.22,
    "package-integrity": 0.20,
    "privilege": 0.14,
    "virtualization": 0.10,
    "environment": 0.10,
}

# 三个 profile。权重为 0 的类别不参与总分聚合（但仍会出现在 categories 里，
# 这样报告能显示「这一类我看得清，只是这次不算分」）。
PROFILES = {
    "standard": dict(DEFAULT_WEIGHTS),
    "sig-only": {c: (1.0 if c == "package-integrity" else 0.0) for c in CATEGORY_ORDER},
    "runtime": {
        c: (0.5 if c in ("runtime-integrity", "injection") else 0.0)
        for c in CATEGORY_ORDER
    },
}

DEFAULT_PROFILE = "standard"

DEFAULT_TIER = "B"
DEFAULT_WEIGHT = 3

# CLI 平面信号参数（契约 §3 标注「CLI 判」的两条）
CLI_WEIGHT = 5
CLI_TIER = "A"
CLI_PLANE = "cli"
CLI_CATEGORY = "package-integrity"
CLI_HASH_ID = "pkg.codepath.hash"
CLI_ZIP_ID = "pkg.zip.fingerprint"

EVIDENCE_MAX = 300  # 契约 §1.1：evidence 不超过 300 字符

# 基线归一时 1-Pb 的数值保护（评分模型给的 1e-9），避免 baseline.raw=100 时除零
_EPS = 1e-9


class ScoreError(Exception):
    """评分层可预期的错误（给 CLI 直接打印人类可读信息）。"""


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------


def round1(value: float) -> float:
    """复刻 Java `Math.round(v*10d)/10d`。

    Java 的 Math.round 定义是 floor(x + 0.5)（正数域即四舍五入到最近，.5 向上），
    Python 内置 round() 是银行家舍入，两会在 .05 处产生 0.1 的差异 —— 必须显式实现。
    """
    return math.floor(float(value) * 10.0 + 0.5) / 10.0


def profile_weights(profile: str) -> dict:
    """取某个 profile 的类别权重，未知 profile 给出明确报错（不要静默回退 standard）。"""
    if profile is None:
        profile = DEFAULT_PROFILE
    key = str(profile).strip().lower()
    if key not in PROFILES:
        raise ScoreError(
            "未知 profile %r，可用：%s" % (profile, ", ".join(sorted(PROFILES)))
        )
    return dict(PROFILES[key])


def _as_weight(raw) -> int:
    """权重钳制到 1..5，与 Java `Math.max(1, Math.min(5, optInt("weight",3)))` 一致。"""
    if raw is None:
        return DEFAULT_WEIGHT
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_WEIGHT
    if v != v:  # NaN
        return DEFAULT_WEIGHT
    return max(1, min(5, int(v)))


def _as_confidence(raw) -> float:
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return 0.0
    if v != v:
        return 0.0
    return max(0.0, min(1.0, v))


def normalize_signal(sig: dict) -> dict:
    """把一条原始 signal 规范成评分用的内部结构（保持 field 名不变，只补默认值）。"""
    s = dict(sig) if isinstance(sig, dict) else {}
    verdict = str(s.get("verdict") or UNKNOWN).strip().upper()
    if verdict not in VERDICTS:
        # 契约外的取值一律视为 UNKNOWN（不扣分、单独计数），不能当成 CLEAN 放过。
        # 与 Score.java 的一处**有意差异**：Score.java 在类别内计数用 `else c.clean++`，
        # 会把契约外 verdict（如 "BOGUS"）当成 clean *并按权重进分母*，于是分数偏高。
        # CLI 更严格：非法 verdict 一律 UNKNOWN、不进分母。合法 verdict 下两侧逐字段一致
        # （见 cli 的 Java 对账脚本，Score.java 用真 org.json 跑）。
        verdict = UNKNOWN
    category = str(s.get("category") or "").strip()
    evidence = s.get("evidence")
    if not isinstance(evidence, str):
        evidence = "" if evidence is None else str(evidence)
    out = {
        "id": str(s.get("id") or "").strip(),
        "category": category,
        "verdict": verdict,
        "confidence": _as_confidence(s.get("confidence", 0.0)),
        "weight": _as_weight(s.get("weight", DEFAULT_WEIGHT)),
        "tier": str(s.get("tier") or DEFAULT_TIER).strip().upper() or DEFAULT_TIER,
        "evidence": evidence[:EVIDENCE_MAX],
        "ms": s.get("ms", 0),
        "plane": str(s.get("plane") or "").strip() or None,
    }
    return out


def normalize_signals(signals) -> list:
    if not signals:
        return []
    return [normalize_signal(s) for s in signals if isinstance(s, dict)]


# ---------------------------------------------------------------------------
# 评分
# ---------------------------------------------------------------------------


def summarize(signals, profile: str = DEFAULT_PROFILE) -> dict:
    """一次运行的分：类别分 + 总分（raw）。

    实现与 Score.java#summarize 对齐，另外多记了两件 CLI 需要、App 不需要的东西：
      * 每个类别的 UNKNOWN/ERROR/FLAKY 计数（盲区判定要看「是不是压根测不了」）；
      * 未四舍五入的 raw（基线归一必须用全精度，否则 --baseline 会漂 0.1）。
    """
    weights = profile_weights(profile)
    sigs = normalize_signals(signals)

    tally = {v: 0 for v in VERDICTS}
    acc = {c: {"polluted": 0.0, "counted": 0.0} for c in CATEGORY_ORDER}
    percat = {c: {v: 0 for v in VERDICTS} for c in CATEGORY_ORDER}

    for s in sigs:
        verdict = s["verdict"]
        tally[verdict] += 1
        cat = s["category"]
        if cat not in acc:
            # 契约外的 category：进总计数（total/clean/…），但不进任何类别分母
            continue
        percat[cat][verdict] += 1
        if verdict not in COUNTABLE_VERDICTS:
            continue
        acc[cat]["counted"] += s["weight"]
        acc[cat]["polluted"] += s["weight"] * POLLUTION[verdict]

    categories = []
    weighted_sum = 0.0
    weight_total = 0.0
    for cat in CATEGORY_ORDER:
        a = float(weights.get(cat, 0.0))
        counted = acc[cat]["counted"]
        cat_score = None if counted <= 0 else 100.0 * (1.0 - acc[cat]["polluted"] / counted)
        if cat_score is not None:
            # 注意：这里用全精度 cat_score，与 Java 一致；四舍五入只发生在输出层
            weighted_sum += a * cat_score
            weight_total += a
        counts = percat[cat]
        countable_n = counts[CLEAN] + counts[SUSPECT] + counts[TAMPERED]
        categories.append(
            {
                "id": cat,
                "label": CATEGORY_LABELS_ZH[cat],
                "score": None if cat_score is None else round1(cat_score),
                "scoreExact": cat_score,
                "weight": a,
                "counted": cat_score is not None,
                "tampered": counts[TAMPERED],
                "suspect": counts[SUSPECT],
                "clean": counts[CLEAN],
                "unknown": counts[UNKNOWN],
                "error": counts[ERROR],
                "flaky": counts[FLAKY],
                # total 是「该类别全部 signal」，countedTotal 是「进分母的那些」。
                # Java 的 categories[].total 只统计可计数的（它在 continue 之后才累加），
                # 与这里的 countedTotal 等价；对账时用 countedTotal，展示时可以两个都用。
                "total": sum(counts.values()),
                "countedTotal": countable_n,
                "countedWeight": counted,
                "pollutedWeight": acc[cat]["polluted"],
            }
        )

    raw = None if weight_total <= 0 else weighted_sum / weight_total

    return {
        "total": len(sigs),
        "clean": tally[CLEAN],
        "suspect": tally[SUSPECT],
        "tampered": tally[TAMPERED],
        "unknown": tally[UNKNOWN],
        "error": tally[ERROR],
        "flaky": tally[FLAKY],
        "score": None if raw is None else round1(raw),
        "raw": raw,
        "profile": str(profile),
        "weights": weights,
        "categories": categories,
        "counted": raw is not None,
        "signals": sigs,
    }


def raw_of(summary: dict) -> float:
    """取全精度 raw，同时兼容外部给的 run.json（可能只有四舍五入后的 score.raw）。"""
    if summary.get("raw") is not None:
        return float(summary["raw"])
    if summary.get("score") is not None:
        return float(summary["score"])
    raise ScoreError("这份报告没有任何可计数的 signal，无法给出分数（全部 UNKNOWN/ERROR/FLAKY）")


def adjust_with_baseline(raw: float, baseline_raw: float) -> float:
    """基线归一（评分模型）。

        P   = 1 - raw/100              # 本次污染度
        Pb  = 1 - baseline_raw/100     # 基线污染度
        adj = 100 * (1 - max(0, P-Pb) / max(1e-9, 1-Pb))

    直觉：以基线为「零点」。基线里本来就有的污染不再重复扣分 —— 那是环境的固有噪声，
    不是这次修补引入的增量。Pb=1（基线已经 0 分）时无意义，用 1e-9 兜底。
    """
    p = 1.0 - float(raw) / 100.0
    pb = 1.0 - float(baseline_raw) / 100.0
    denom = max(_EPS, 1.0 - pb)
    adj = 100.0 * (1.0 - max(0.0, p - pb) / denom)
    # 数值上应当落在 [0,100]；极端输入（raw 越界）时夹紧，避免报告出现 103.4 这种数字
    return round1(max(0.0, min(100.0, adj)))


def baseline_block(summary: dict, baseline_summary: dict | None, baseline_path: str | None = None):
    """组装 run.json 里的 score.baseline 与最终 litmus 分。"""
    raw = raw_of(summary)
    litmus = round1(raw)
    if baseline_summary is None:
        return litmus, None
    braw = raw_of(baseline_summary)
    litmus = adjust_with_baseline(raw, braw)
    return litmus, {
        "raw": round1(braw),
        "rawExact": braw,
        "litmus": litmus,
        "path": baseline_path,
    }


# ---------------------------------------------------------------------------
# CLI 平面信号：包完整性复核
# ---------------------------------------------------------------------------


def _pick(d, *keys) -> str:
    """从 dict 里按候选 key 取第一个非空字符串。

    为什么要多候选：契约 §4.1 的示例 facts 写的是 `zip.fingerprint`，
    而 LitmusRunner 实际写的是 `apk.zip.fingerprint`。两边都是「事实」，取到哪个都算数；
    有差异的地方是契约文档的口径不一致，CLI 必须都认。
    """
    if not isinstance(d, dict):
        return ""
    for k in keys:
        v = d.get(k)
        if isinstance(v, str):
            v = v.strip()
            if v:
                return v
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            return str(v)
    return ""


def _short(value: str, n: int = 16) -> str:
    v = value or ""
    return v if len(v) <= n else v[:n] + "…"


def _mismatch(verdict: str, conf: float, evidence: str, sid: str) -> dict:
    return {
        "id": sid,
        "category": CLI_CATEGORY,
        "verdict": verdict,
        "confidence": conf,
        "weight": CLI_WEIGHT,
        "tier": CLI_TIER,
        "evidence": evidence[:EVIDENCE_MAX],
        "ms": 0,
        "plane": CLI_PLANE,
    }


def cli_plane_signals(facts: dict, expect: dict) -> list:
    """生成两条只能在进程外判定的信号（契约 §3：pkg.codepath.hash / pkg.zip.fingerprint）。

    - 事实来自 App 上报（facts），期望值来自构建产物（build-info.json）；
    - 任一缺失一律 UNKNOWN（不扣分、但要看得见），**绝不**因为缺数据就判 TAMPERED；
    - 相等判 CLEAN：tier A 是密码学不变量，哈希对上就是没改过，不需要「保留怀疑」。
    """
    facts = facts if isinstance(facts, dict) else {}
    expect = expect if isinstance(expect, dict) else {}
    out = []

    # --- ① APK 全文件 SHA-256 -------------------------------------------------
    got = _pick(facts, "apk.sha256", "apkSha256", "sha256")
    want = _pick(expect, "apkSha256", "apk.sha256")
    if not got:
        out.append(
            _mismatch(
                UNKNOWN,
                0.0,
                "App 未上报 facts.apk.sha256（AppSnapshot 抓取失败或内核版本过旧，"
                "看 report.run.snapshotError）",
                CLI_HASH_ID,
            )
        )
    elif not want:
        out.append(
            _mismatch(
                UNKNOWN,
                0.0,
                "build-info.json 缺 apkSha256，无法复核包哈希（重跑 canary/build.ps1）",
                CLI_HASH_ID,
            )
        )
    elif got.lower() == want.lower():
        out.append(
            _mismatch(
                CLEAN,
                0.98,
                "facts.apk.sha256=%s == expect.apkSha256，安装的 base.apk 与构建产物逐字节一致"
                % _short(got),
                CLI_HASH_ID,
            )
        )
    else:
        out.append(
            _mismatch(
                TAMPERED,
                1.0,
                "facts.apk.sha256=%s ≠ expect.apkSha256=%s，装上去的 APK 不是构建产出的那个"
                % (_short(got), _short(want)),
                CLI_HASH_ID,
            )
        )

    # --- ② ZipEntry 指纹（契约 §4.4）-----------------------------------------
    got = _pick(facts, "apk.zip.fingerprint", "zip.fingerprint", "apkZipFingerprint")
    want = _pick(expect, "zipFingerprint", "apk.zip.fingerprint", "zip.fingerprint")
    if not got:
        out.append(
            _mismatch(
                UNKNOWN,
                0.0,
                "App 未上报 facts.apk.zip.fingerprint（ZipFile 枚举失败，见 report.run.snapshotError）",
                CLI_ZIP_ID,
            )
        )
    elif not want:
        out.append(
            _mismatch(
                UNKNOWN,
                0.0,
                "build-info.json 缺 zipFingerprint，无法复核重打包（重跑 canary/build.ps1）",
                CLI_ZIP_ID,
            )
        )
    elif got.lower() == want.lower():
        out.append(
            _mismatch(
                CLEAN,
                0.98,
                "facts.apk.zip.fingerprint=%s == expect.zipFingerprint，ZipEntry(CRC/size/method) 指纹一致"
                % _short(got),
                CLI_ZIP_ID,
            )
        )
    else:
        out.append(
            _mismatch(
                TAMPERED,
                1.0,
                "facts.apk.zip.fingerprint=%s ≠ expect.zipFingerprint=%s，"
                "ZipEntry 指纹变了 → 包被重打包/改过内容" % (_short(got), _short(want)),
                CLI_ZIP_ID,
            )
        )
    return out


def facts_mismatch(facts: dict, expect: dict, covered=()) -> list:
    """「靶包 facts 与 expect 不符」的兜底判定（评分模型里盲区触发的第二种条件）。

    CLI 两条信号之外，再交叉复核证书：重打包最常见的动作就是换签名。
    只比较双方都有的字段，缺一边不算不符（缺数据是 UNKNOWN，不是证据）。

    `covered` 是已经被 CLI 平面信号判过的 id 集合 —— 哈希/指纹不符不要在这里重复报，
    否则 packageModified.reasons 里同一件事会出现两次，报告看着像抓到了两个问题。
    """
    reasons = []
    if not isinstance(facts, dict) or not isinstance(expect, dict):
        return reasons
    covered = set(covered or ())

    if CLI_HASH_ID not in covered:
        got_sha = _pick(facts, "apk.sha256", "apkSha256")
        want_sha = _pick(expect, "apkSha256", "apk.sha256")
        if got_sha and want_sha and got_sha.lower() != want_sha.lower():
            reasons.append("facts.apk.sha256 != expect.apkSha256")

    if CLI_ZIP_ID not in covered:
        got_zip = _pick(facts, "apk.zip.fingerprint", "zip.fingerprint")
        want_zip = _pick(expect, "zipFingerprint", "apk.zip.fingerprint")
        if got_zip and want_zip and got_zip.lower() != want_zip.lower():
            reasons.append("facts.apk.zip.fingerprint != expect.zipFingerprint")

    certs = facts.get("cert.install")
    got_cert = str(certs[0] or "").strip() if isinstance(certs, list) and certs else ""
    want_cert = _pick(expect, "certSha256", "cert.sha256")
    if got_cert and want_cert and got_cert.lower() != want_cert.lower():
        reasons.append("facts.cert.install[0] != expect.certSha256")
    return reasons


def package_modified(signals, facts: dict, expect: dict) -> dict:
    """本次运行「包确实被改过」吗？盲区和误报都以它为前提。

    优先级：CLI 平面的 A 级信号 > facts 交叉复核。
    只要有一条成立就算改过 —— 宁可多报盲区（那是我们的洞），不要漏。
    """
    sigs = normalize_signals(signals)
    reasons = []
    judged = set()  # 已经由 CLI 信号给出结论（非 UNKNOWN）的事实项
    for s in sigs:
        if s["id"] not in (CLI_HASH_ID, CLI_ZIP_ID):
            continue
        if s["verdict"] == TAMPERED:
            reasons.append({"vector": s["id"], "why": "cli-expect-mismatch", "evidence": s["evidence"]})
            judged.add(s["id"])
        elif s["verdict"] != UNKNOWN:
            judged.add(s["id"])
    for r in facts_mismatch(facts, expect, covered=judged):
        reasons.append({"vector": "", "why": "facts-expect-mismatch", "evidence": r})
    return {"modified": bool(reasons), "reasons": reasons}


# ---------------------------------------------------------------------------
# 盲区：包改了，但整类一条都没抓到
# ---------------------------------------------------------------------------


def blind_spots(summary: dict, modified: dict) -> list:
    """盲区判定（产品卖点之一）。

    条件：① 包确实被改过；② 某类别有可计数 signal 且类别分 == 100；
         ③ 该类别里至少有 1 条 CLEAN 的向量（有东西可列，报告才有用）。

    「分数 100」说明这一类**所有**可计数向量都判了 CLEAN —— 那不是「这条检测没生效」，
    而是「这一整类对着一个明显被改过的包，一条都没抓到」。这正是我们需要补的地方。

    注意：category 分 == 100 时也包含「只有 UNKNOWN/ERROR」的情形吗？不含。
    没有可计数 signal 的类别 score 为 None，直接跳过 —— 那是「测不了」，要治的是覆盖率，
    不是盲区（报告里 categories[].counted=false 会体现）。
    """
    if not modified.get("modified"):
        return []
    out = []
    for cat in summary["categories"]:
        if not cat["counted"]:
            continue
        if cat["score"] is None or abs(float(cat["score"]) - 100.0) > 1e-9:
            continue
        clean_ids = [
            s["id"]
            for s in summary["signals"]
            if s["category"] == cat["id"]
            and s["verdict"] == CLEAN
            and s["id"]
        ]
        if not clean_ids:
            continue
        out.append(
            {
                "category": cat["id"],
                "label": cat["label"],
                "score": 100.0,
                "weight": cat["weight"],
                "counted": cat["weight"] > 0,
                "why": "pkg-modified-but-category-clean",
                "text": "包已改动，但 %s 一条都没抓到" % cat["label"],
                "vectors": clean_ids,
            }
        )
    return out


# ---------------------------------------------------------------------------
# 误报：基线里就判 TAMPERED，包没动，本轮还判 TAMPERED
# ---------------------------------------------------------------------------


def false_positives(summary: dict, baseline_summary: dict | None, modified: dict) -> dict:
    """误报判定（产品卖点之二）。

    条件：给了 --baseline；某向量在 baseline 里就是 TAMPERED，本轮仍是 TAMPERED，
    且**包没被改**（两条 CLI 信号都 CLEAN、facts 与 expect 也对得上）。

    → 这不可能归因于「用户改了包」，只能是该环境本身就让这条检测成立
      （自编译 ROM、模拟器、厂商魔改 /proc、老系统缺 API…）。
      结论：**不扣分、只标注**，并把它列进 noiseFromBaseline，供后续版本降级或改成 tier C。

    包的哈希/指纹为 UNKNOWN（缺数据）时也按「未被改」处理：没有证据说明包被动过，
    此时把 TAMPERED 归给环境是更保守（对用户更不误导）的解释。
    """
    if baseline_summary is None:
        return {"falsePositives": [], "noiseFromBaseline": []}
    if modified.get("modified"):
        # 包确实被改过 —— 那这些 TAMPERED 就可能是真的，不能叫误报
        return {"falsePositives": [], "noiseFromBaseline": []}

    base_map = {}
    for s in normalize_signals(baseline_summary.get("signals") or []):
        base_map[s["id"]] = s

    fps = []
    for s in summary["signals"]:
        if s["verdict"] != TAMPERED:
            continue
        b = base_map.get(s["id"])
        if b is None or b["verdict"] != TAMPERED:
            continue
        fps.append(
            {
                "vector": s["id"],
                "category": s["category"],
                "why": "baseline-clean-but-tampered",
                "tier": s["tier"],
                "weight": s["weight"],
                "evidence": s["evidence"],
                "baselineEvidence": b["evidence"],
                "text": "包没被改，%s 在基线里也是 TAMPERED → 该环境固有噪声，不扣分只标注" % s["id"],
            }
        )
    fps.sort(key=lambda x: (x["category"], x["vector"]))
    return {
        "falsePositives": fps,
        "noiseFromBaseline": [f["vector"] for f in fps],
    }


# ---------------------------------------------------------------------------
# 契约校验 & zip 指纹
# ---------------------------------------------------------------------------


def validate_report(report: dict) -> list:
    """轻量校验 App 上报的 report.json，返回问题列表（空=没问题）。

    不追求 JSON Schema 的完备性（那是 schema/*.json 的事），只抓会让 CLI 算错分的东西。
    """
    problems = []
    if not isinstance(report, dict):
        return ["report 不是 JSON 对象"]
    schema = report.get("schema")
    if schema != SCHEMA_REPORT:
        problems.append("schema=%r，期望 %r" % (schema, SCHEMA_REPORT))
    if not isinstance(report.get("signals"), list):
        problems.append("缺 signals 数组")
    for k in ("app", "device", "facts", "summary"):
        if k not in report:
            problems.append("缺字段 %s（App 端 LitmusRunner 版本过旧？）" % k)
    seen = {}
    for s in report.get("signals") or []:
        if not isinstance(s, dict):
            problems.append("signals 里有非对象元素")
            continue
        sid = str(s.get("id") or "")
        cat = str(s.get("category") or "")
        if not sid:
            problems.append("有 signal 缺 id")
        if sid in seen:
            problems.append("signal id 重复：%s（契约要求一 Probe 一条）" % sid)
        seen[sid] = True
        if cat not in CATEGORY_ORDER:
            problems.append("signal %s 的 category=%r 不在六类里" % (sid, cat))
        else:
            prefix = CATEGORY_PREFIX[cat]
            if sid and not sid.startswith(prefix):
                problems.append("signal %s 的 id 前缀与 category=%s 不符（应为 %s）" % (sid, cat, prefix))
        if str(s.get("verdict") or "").upper() not in VERDICTS:
            problems.append("signal %s 的 verdict=%r 非法" % (sid, s.get("verdict")))
    return problems


def zip_fingerprint(apk_path) -> str:
    """契约 §4.4 的 ZipEntry 指纹，必须与 Java 侧逐字节一致。

    行格式：`name|crc32(8位小写hex)|size|compressedSize|method` + '\\n'
    按 central directory 顺序（Java ZipFile#entries() / Python infolist() 同序）。
    用途：`litmus.py doctor` 用它反查 build-info.json 是否自洽 —— 这条能同时验证
    构建脚本和本实现，是「CLI 平面判包完整性」能不能信的前提。
    """
    lines = []
    with zipfile.ZipFile(str(apk_path)) as zf:
        for zi in zf.infolist():
            # Java 的 %08x 对 CRC 的 long 值与 Python 的 unsigned int 输出一致
            lines.append(
                "%s|%08x|%d|%d|%d\n"
                % (zi.filename, zi.CRC, zi.file_size, zi.compress_size, zi.compress_type)
            )
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def file_sha256(path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(str(path), "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# 向量目录（schema/vectors.json）交叉校验
# ---------------------------------------------------------------------------

_CATALOG_CACHE = {}


def load_catalog(path=None):
    """读 schema/vectors.json → {id: 目录条目}；读不到返回 None（不阻断评分）。

    有它才能做两件契约层面的事：
      ① 报告里出现「目录外的新 id」→ 提醒先登记（契约 §3 的流程是「先加目录再实现」）；
      ② C 级向量判 TAMPERED → 违反 §2.2 硬约束（C 级只能出 SUSPECT）。
    """
    key = str(path or "")
    if key in _CATALOG_CACHE:
        return _CATALOG_CACHE[key]
    p = Path(path) if path else (Path(__file__).resolve().parent.parent / "schema" / "vectors.json")
    cat = None
    if p.is_file():
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
            vecs = obj.get("vectors") if isinstance(obj, dict) else None
            if isinstance(vecs, list):
                cat = {v["id"]: v for v in vecs if isinstance(v, dict) and v.get("id")}
        except Exception:
            cat = None
    _CATALOG_CACHE[key] = cat
    return cat


def catalog_problems(signals, catalog) -> list:
    """按目录检查信号：未登记的 id / tier 与目录不符 / C 级越权判 TAMPERED。"""
    if not catalog:
        return []
    problems = []
    for s in normalize_signals(signals):
        sid = s["id"]
        if not sid:
            continue
        entry = catalog.get(sid)
        if entry is None:
            problems.append("向量 %s 不在 schema/vectors.json 目录里（新增向量请先登记到契约 §3）" % sid)
            continue
        cat = entry.get("category")
        if cat and s["category"] and cat != s["category"]:
            problems.append("向量 %s 报告的 category=%s 与目录里的 %s 不一致" % (sid, s["category"], cat))
        tier = str(entry.get("tier") or "").upper()
        if tier == "C" and s["verdict"] == TAMPERED:
            problems.append(
                "C 级向量 %s 判了 TAMPERED —— 契约 §2.2 规定 C 级（特征匹配）只能出 SUSPECT，"
                "要用 TAMPERED 必须另有 A/B 级佐证" % sid
            )
    return problems


def catalog_coverage(signals, catalog) -> dict:
    """目录覆盖率：声明了但本次报告里根本没出现的向量 = 实现缺口的硬指标。"""
    if not catalog:
        return {"declared": 0, "present": 0, "missing": []}
    present = {s["id"] for s in normalize_signals(signals) if s.get("id")}
    missing = [vid for vid in catalog if vid not in present]
    return {"declared": len(catalog), "present": len(present & set(catalog)), "missing": missing}


# ---------------------------------------------------------------------------
# 便捷入口：给 CLI 用的一次性分析（fail-fast 口径统一）
# ---------------------------------------------------------------------------


def analyze(report: dict, expect: dict, profile: str = DEFAULT_PROFILE,
            baseline_report: dict | None = None) -> dict:
    """App 报告 → 完整评分结论（含 CLI 平面信号、盲区、误报）。

    这是 `litmus.py run` / `score` / `demo` / `selftest` 共用的唯一分析入口，
    保证四条路径算出来的数一模一样（否则「回归」就失去意义）。
    """
    if not isinstance(report, dict):
        raise ScoreError("report 不是 JSON 对象")
    facts = report.get("facts") if isinstance(report.get("facts"), dict) else {}
    expect = expect if isinstance(expect, dict) else {}

    app_signals = normalize_signals(report.get("signals") or [])
    cli_signals = cli_plane_signals(facts, expect)
    all_signals = app_signals + cli_signals

    summary = summarize(all_signals, profile=profile)
    modified = package_modified(all_signals, facts, expect)

    base_summary = None
    if baseline_report is not None:
        base_summary = summarize(baseline_report.get("signals") or [], profile=profile)

    litmus, base_block = baseline_block(summary, base_summary, None)
    fps = false_positives(summary, base_summary, modified)

    return {
        "summary": summary,
        "signals": all_signals,
        "cliSignals": cli_signals,
        "litmus": litmus,
        "baseline": base_block,
        "blindSpots": blind_spots(summary, modified),
        "falsePositives": fps["falsePositives"],
        "noiseFromBaseline": fps["noiseFromBaseline"],
        "packageModified": modified,
        "profile": str(profile),
    }
