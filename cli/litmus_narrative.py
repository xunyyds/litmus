#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
litmus_narrative.py —— 把 run.json 翻译成**人能读懂的**中文。

职责边界（刻意划死）
------------------
* 只做「文字生成」：输入 run.json（dict）+ 向量文案（dict），输出 str / list[dict]。
* **不碰评分**（分数、权重、盲区判定全部来自 litmus_score.py），**不碰 IO**
  （不读文件、不写文件、不 import adb）。这样报告文案可以在 selftest 里被断言，
  也可以在 App 侧复用同一套说法。
* 文案按「类别 / tier / verdict / 计数」**组装**，不把长句硬编码在模板里 ——
  换一条向量、换一次运行，句子照样通顺（规范 §9 的硬要求）。

文风硬指标对应（docs/07 §8）
--------------------------
R1 结论先行      → conclusion() 三行内说清「改没改 + 哪类失守 + 哪类失明」
R2 数字带解释    → 每个分数后面都跟一句「这意味着什么」
R3 不出现裸词    → verdict_label() 统一输出「被坐实（TAMPERED）」这种带解释的形式；
                   外来文本（evidence / 向量文案）过一遍 gloss_verdicts() 兜底
R4 每条红都给解释 → confirmed_item() 固定四段：判据 / 证据 / 意味着什么 / 怎么修
R5 盲区给验证法  → blindspot_story() 必带「为什么可能是洞」+「怎么验证是不是洞」
R6 行动带收益    → action_list() 每条都有 gain（估算）与成本
R7 术语给英文    → 首次出现用「中文（English）」
R8 不编数字      → 收益一律标「估算」；没有实测的地方写「待实测」
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# 术语表（R3 / R7 的唯一出口）
# ---------------------------------------------------------------------------

VERDICT_ZH = {
    "CLEAN": "干净",
    "SUSPECT": "可疑",
    "TAMPERED": "被坐实",
    "UNKNOWN": "测不了",
    "ERROR": "探针出错",
    "FLAKY": "结果不稳定",
}

TIER_ZH = {
    "A": "A 级（不变量/密码学，改了就一定不成立）",
    "B": "B 级（交叉视图，同一事实多路径比对）",
    "C": "C 级（特征匹配，只能出可疑）",
}

CATEGORY_HINT = {
    "runtime-integrity": "看的是「运行起来的进程本身」有没有被动过：调试器附着、内存段被改、GOT 被劫持。",
    "injection": "看的是「有没有第三方在往你的进程里塞东西」：frida 端口/socket、inline hook 字节、异常加载的 so。",
    "package-integrity": "看的是「装上去的这份 APK 还是不是我们构建的那一份」：签名、文件哈希、打包指纹、dex 数量。",
    "privilege": "看的是「这台设备有没有给你留后门」：su、Magisk、KernelSU、可调试属性、异常挂载。",
    "virtualization": "看的是「这个 App 是不是跑在模拟器/多开容器里」：qemu 属性、虚拟设备文件、容器特征。",
    "environment": "看的是「周围环境有没有被摆布」：可调试位、开发者选项、代理、录屏/无障碍、悬浮窗。",
}

# 证据强度 → 一句话说明它在证据链里的份量
_TIER_WEIGHT_NOTE = {
    "A": "A 级结论本身就是不变量，出现就意味着改动一定发生过。",
    "B": "B 级是交叉视图，通常需要另一条证据佐证。",
    "C": "C 级只是特征匹配，单独出现只能说明「像」，不能说明「是」。",
}

# 补充：docs-spec 还没填 plain/bypass 时的兜底加固建议（按类别，不是长句模板）
_FIX_BY_CATEGORY = {
    "package-integrity": [
        "把「构建产物哈希」接进 CI：每次出包都落一份 build-info，安装后立刻比对",
        "别只比签名 —— 换签名容易看见，改 dex 但沿用签名的二次打包只能靠哈希/指纹抓",
    ],
    "runtime-integrity": [
        "内存段比对要拿「映射区字节 vs 磁盘文件字节」，只比大小/时间戳会被轻易绕过",
        "关键读取走裸 syscall 再和 libc 结果交叉比对，防止 libc 被替换后自证清白",
    ],
    "injection": [
        "端口/socket/线程名这类特征改个名就没了，至少要配一条字节级不变量（trampoline 扫描或 so 路径校验）",
        "扫到的 so 路径要和安装目录/系统目录做白名单比对，避免被塞进可写目录",
    ],
    "privilege": [
        "su/Magisk 这类只看文件名的检测对「无文件 root」无效，要补内核面与挂载面的交叉证据",
        "读取系统属性时同时用两条通道（Java API + 直接读 /proc 或 /system/build.prop）比对",
    ],
    "virtualization": [
        "属性/文件特征都是「可伪造项」，至少要有一条硬件面不变量（传感器清单、GPU/CPU 指纹、启动耗时分布）",
        "把「多开容器」和「模拟器」拆成两条独立判定，混在一条里会让两者互相稀释",
    ],
    "environment": [
        "环境项天生与包无关：它们只说明设备脏，不说明包被改，报告里应与「包完整性」分开解读",
        "建议补一条「环境快照 vs 上次环境快照」的差分，用来把设备噪声从分数里扣掉（--baseline 就是这个思路）",
    ],
}

# 盲区的验证配方（R5）：每条都是可执行动作，不是形容词
_VERIFY_BY_CATEGORY = {
    "virtualization": [
        "换一台真机（非模拟器、非多开）跑同一个包：该类仍然满分 → 说明它检测的是「环境像不像模拟器」，与「包被改」本来就无关，不算洞",
        "造一份「真的动了这一面」的样板包（改 ro 属性 / 塞进 VirtualApp），如果它还是满分 → 真洞",
        "补一条硬件面不变量（传感器清单 / GPU 指纹）再跑，若新向量也是干净，基本可以确诊",
    ],
    "environment": [
        "把同一个包在原设备上跑两次，看这一类是否波动 → 会波动说明测的是环境噪声，不是篡改",
        "手工把设备「弄脏」（打开开发者选项、挂代理），该类应掉分；不掉分 → 真洞",
        "检查这些向量的 tier：如果全是 C 级特征匹配，它们本来就抓不到「包被改」这件事",
    ],
    "package-integrity": [
        "用 `keytool -printcert` / `apksigner verify` 独立取一次签名，与报告里的值比对",
        "对同一个包重算 `sha256sum`，确认 CLI 平面两条信号不是误判",
        "把包解压后逐文件比对构建产物，定位到底是哪个 entry 变了",
    ],
    "runtime-integrity": [
        "用 frida/gdb 附着一个调试版，看这些向量是否会亮 → 不亮说明探针没真正接上运行时",
        "跑一份「已知被 inline hook」的样板包，若仍全干净 → 真洞",
        "检查 native 探针是否加载成功（producer.hasNative / run.snapshotError）",
    ],
    "injection": [
        "手动起一个 frida-server 再跑一次，若 `inj.frida.*` 仍全干净 → 真洞",
        "检查 /proc/self/maps 在本机是否可读（不可读会让整类退化成「测不了」）",
        "用一份带明文 trampoline 的 so 做对照，验证字节扫描确实在工作",
    ],
    "privilege": [
        "在一台已 root 的真机上跑同一份包，该类应掉分；不掉分 → 真洞",
        "手工检查 su 路径 / Magisk 目录 / ro.debuggable 是否真的存在，与报告比对",
        "确认这些检测有没有被 SELinux 挡住而退化成「测不了」",
    ],
}

_GENERIC_VERIFY = [
    "先确认这一类里的向量有没有真正跑起来（看「测不了」的条数），全都没跑就别谈抓到",
    "用一份「确实动了这一类」的样板包做对照：对照包也满分，就是真洞",
    "给它补一条 A 级不变量（密码学/字节比对），再跑同一个包",
]


# ---------------------------------------------------------------------------
# 基础格式化（全部带解释，R2/R3/R7）
# ---------------------------------------------------------------------------


def verdict_label(verdict) -> str:
    """「被坐实（TAMPERED）」这种带解释的形式 —— 全文唯一的结论词出口（R3）。"""
    v = str(verdict or "").strip().upper()
    return "%s（%s）" % (VERDICT_ZH.get(v, "未知结论"), v) if v else "未知结论"


def tier_label(tier) -> str:
    t = str(tier or "").strip().upper()
    return "%s 级" % t if t in ("A", "B", "C") else "未分级"


def fmt_score(value, digits: int = 1) -> str:
    if value is None:
        return "—"
    try:
        return ("%." + str(digits) + "f") % float(value)
    except (TypeError, ValueError):
        return "—"


def pct(part, whole) -> str:
    try:
        part, whole = float(part), float(whole)
    except (TypeError, ValueError):
        return "—"
    if whole <= 0:
        return "—"
    return "%.0f%%" % (100.0 * part / whole)


def short(text, n: int = 90) -> str:
    t = " ".join(str(text or "").split())
    return t if len(t) <= n else t[: n - 1] + "…"


def _join(items) -> str:
    items = [x for x in items if x]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return "、".join(items[:-1]) + "和" + items[-1]


_VERDICT_WORDS = ("TAMPERED", "SUSPECT", "CLEAN", "UNKNOWN", "ERROR", "FLAKY")


def gloss_verdicts(text) -> str:
    """把外来文本里「裸的」结论词改写成带解释的形式（R3 兜底）。

    只改独立出现的词（前后是中文/空白/标点），已经处在「（TAMPERED）」里的不再动。
    这样即使 schema/vectors.json 的文案由别人维护、里面写了 CLEAN，报告也不会出现裸词。
    """
    s = str(text or "")
    for v in _VERDICT_WORDS:
        pattern = re.compile(r"(?<![（(A-Za-z_])" + v + r"(?![）)A-Za-z_])")

        def repl(m, _v=v):
            return VERDICT_ZH.get(_v, _v) + "（" + _v + "）"

        s = pattern.sub(repl, s)
    return s


# ---------------------------------------------------------------------------
# 向量文案（schema/vectors.json 的 zh / plain / bypass / fix）
# ---------------------------------------------------------------------------


def docs_from_catalog(catalog) -> dict:
    """把 litmus_score.load_catalog() 的结果转成 {id: 文案}。

    plain / bypass 由 docs-spec 并行填；**读不到就回落 zh**（不阻塞报告），
    bypass / fix 都缺时用 _FIX_BY_CATEGORY 里的加固建议。
    """
    if not isinstance(catalog, dict):
        return {}
    out = {}
    for sid, entry in catalog.items():
        if not isinstance(entry, dict):
            continue
        zh = str(entry.get("zh") or "").strip()
        plain = str(entry.get("plain") or "").strip() or zh
        bypass = str(entry.get("bypass") or "").strip()
        fix = str(entry.get("fix") or "").strip()
        out[sid] = {
            "id": sid,
            "zh": zh,
            "plain": plain,
            "bypass": bypass,
            "fix": fix,
            "tier": str(entry.get("tier") or "").upper(),
            "category": entry.get("category") or "",
            "weight": entry.get("weight"),
        }
    return out


def docs_entry(docs, sid: str) -> dict:
    """取一条向量的文案；没有就返回空壳（调用方负责回落）。"""
    if isinstance(docs, dict):
        e = docs.get(sid)
        if isinstance(e, dict):
            return e
    return {}


def judge_text(sig: dict, docs) -> str:
    """「判据」：优先 docs.zh（人写的判据），没有就退回证据本身。"""
    e = docs_entry(docs, str(sig.get("id") or ""))
    return gloss_verdicts(e.get("zh") or "（这条向量还没登记判据，见 schema/vectors.json）")


def meaning_text(sig: dict, docs) -> str:
    """「意味着什么」：plain（docs-spec 在填）→ 回落 zh → 再回落类别提示。"""
    e = docs_entry(docs, str(sig.get("id") or ""))
    text = e.get("plain") or e.get("zh") or ""
    if not text:
        cat = str(sig.get("category") or "")
        return gloss_verdicts(CATEGORY_HINT.get(cat) or "这条向量还没有人写「意味着什么」。")
    return gloss_verdicts(text)


def fix_text(sig: dict, docs) -> str:
    """「怎么修」：fix → bypass（并说明这是对手的路径）→ 按类别兜底（R4）。

    注意 bypass 是「对手怎么绕过」，读者要的是「我们怎么补」，所以这里把它翻成防守语气；
    另外要吃掉原文末尾的句号，否则会拼出「…兜着。。加固方向…」这种双句号。
    """
    e = docs_entry(docs, str(sig.get("id") or ""))
    if e.get("fix"):
        return gloss_verdicts(e["fix"].strip().rstrip("。"))
    if e.get("bypass"):
        return gloss_verdicts(
            "对手的绕过路径是「%s」；加固方向就是堵死这条路。" % e["bypass"].strip().rstrip("。")
        )
    cat = str(sig.get("category") or "")
    tips = _FIX_BY_CATEGORY.get(cat) or []
    if tips:
        return gloss_verdicts("；".join(tips))
    return "这一类还没有写加固建议（待补）。"


# ---------------------------------------------------------------------------
# ① 一句话结论（R1：三行内说清「改没改 + 哪类失守 + 哪类失明」）
# ---------------------------------------------------------------------------


def _counted_categories(run) -> list:
    cats = ((run or {}).get("score") or {}).get("categories") or []
    return [c for c in cats if c.get("score") is not None]


def worst_category(run):
    cats = _counted_categories(run)
    if not cats:
        return None
    return min(cats, key=lambda c: float(c["score"]))


def best_category(run):
    cats = _counted_categories(run)
    if not cats:
        return None
    return max(cats, key=lambda c: float(c["score"]))


def reason_phrase(pkg: dict) -> str:
    """把 packageModified.reasons 翻译成人话（①/③ 共用）。

    输出形如「内容哈希、打包指纹和签名都与构建产物对不上」——
    不再逐项重复「不符」，读起来才像一句话。
    """
    nouns = []
    for r in (pkg or {}).get("reasons") or []:
        vec = str(r.get("vector") or "")
        why = str(r.get("why") or "")
        ev = str(r.get("evidence") or "")
        if vec == "pkg.codepath.hash":
            noun = "内容哈希"
        elif vec == "pkg.zip.fingerprint":
            noun = "打包指纹"
        elif why == "facts-expect-mismatch":
            noun = "签名" if "cert" in ev else "观测值"
        else:
            noun = ""
        if noun and noun not in nouns:
            nouns.append(noun)
    if not nouns:
        return "和构建产物对不上"
    return "%s都与构建产物对不上" % _join(nouns)


def score_sentence(run) -> str:
    """分数的口径必须每次都解释，否则 88.1 就是天书（R2）。"""
    sc = (run or {}).get("score") or {}
    litmus = sc.get("litmus")
    if litmus is None:
        return "这份报告算不出分：所有向量都停在「测不了」，不能当作「干净」。"
    sem = "这个分是「我们看着它有多干净」，越高说明越看不出来（100 = 一条篡改都没抓到，0 = 全被抓住）。"
    base = sc.get("baseline")
    if base:
        head = "Litmus 分 %s/100。" % fmt_score(litmus)
        note = "这次带基线跑：扣分只算「比基线多出来的脏」，基线里本来就有的噪声不再重复扣。"
        if float(litmus or 0) >= 99.95:
            note += "本次没有比基线更脏，所以归一后到了 100 分。"
        return head + note + sem
    return "Litmus 分 %s/100。" % fmt_score(litmus) + sem


def conclusion(run, docs=None) -> str:
    """一句话结论：最多三行。第一行包状态+失守类别，第二行盲区，第三行分数口径。"""
    run = run or {}
    sc = run.get("score") or {}
    counts = sc.get("counts") or {}
    pkg = run.get("packageModified") or {}
    blind = run.get("blindSpots") or []
    tampered = int(counts.get("tampered") or 0)
    suspect = int(counts.get("suspect") or 0)
    lines = []

    if pkg.get("modified"):
        worst = worst_category(run)
        tail = ""
        if tampered:
            tail = "，其中「%s」掉得最狠（%s 分，%d 条被坐实）" % (
                worst["label"] if worst else "未知类别",
                fmt_score(worst["score"]) if worst else "—",
                tampered,
            )
        elif suspect:
            tail = "，但没有一条被坐实，%d 条停在可疑" % suspect
        lines.append("这个包**被改过**（%s）%s。" % (reason_phrase(pkg), tail))
    else:
        if tampered:
            lines.append(
                "包本身没被改（哈希、打包指纹、签名都对得上），但有 %d 条检测被坐实 —— "
                "说明改动发生在**运行时**，不在 APK 里。" % tampered
            )
        else:
            lines.append("这个包没被改：哈希、打包指纹、签名都与构建产物一致，六类里没有一条被坐实。")

    if blind:
        labels = _join([str(b.get("label") or b.get("category")) for b in blind])
        lines.append("但「%s」一条都没抓到 —— 这几类对本次修补是失明的，见 ⑥。" % labels)
    elif pkg.get("modified"):
        lines.append("六类都至少动了一下，没有整类失明。")
    elif suspect:
        lines.append("有 %d 条停在可疑，但它们都还够不上「被坐实」，多半是设备噪声，见 ⑦。" % suspect)

    lines.append(score_sentence(run))
    return "\n".join(lines)


def advice_line(run) -> str:
    """终端「建议」那一行（规范 §10），也给 ⑧ 当引导语。"""
    run = run or {}
    blind = run.get("blindSpots") or []
    counts = (run.get("score") or {}).get("counts") or {}
    fps = run.get("falsePositives") or []
    if blind and counts.get("tampered"):
        return "先看 ⑥ 盲区（那是我们的洞），再看 ⑤ 被坐实的问题；能不能提分看 ⑧。"
    if counts.get("tampered"):
        return "先看 ⑤ 被坐实的问题（每条都给了怎么修），再按 ⑧ 的行动清单排序。"
    if blind:
        return "先看 ⑥ 盲区（包被改过却整类满分），⑤ 这次是空的。"
    if fps:
        return "先看 ⑦ 环境噪声：这些红叉不是包的问题，是设备脏。"
    return "这次没有硬伤：⑤⑥ 都是空的，可以只看 ② 的三个数字。"


# ---------------------------------------------------------------------------
# ④ 逐类判断
# ---------------------------------------------------------------------------


def _signals_in(run_or_signals, category: str) -> list:
    signals = run_or_signals
    if isinstance(run_or_signals, dict):
        signals = run_or_signals.get("signals") or []
    return [s for s in (signals or []) if s.get("category") == category]


def _rank_sentence(run, cat) -> str:
    cats = _counted_categories(run or {})
    if len(cats) < 2 or cat.get("score") is None:
        return ""
    ordered = sorted(cats, key=lambda c: float(c["score"]))  # 从最差到最好
    idx = [c.get("id") for c in ordered].index(cat.get("id")) + 1
    if idx == 1:
        return "六类里最差的一类。"
    if idx == len(ordered):
        return "六类里最好的一类。"
    return "六类里排第 %d（从最差数起）。" % idx


def category_story(cat, signals, score=None, run=None, docs=None, lead: bool = True) -> str:
    """每一类 2–4 句人话：分数+排名 / 计数 / 关键向量 / 例外说明。

    签名按 lead 要求保持 (cat, signals, score)，run/docs 可选：
    有 run 就能给排名和「盲区」「包被改」这类上下文，没有也能读通。
    `lead=False` 用于「外面已经用标题写了类别和分数」的场合（报告 ④），避免重复。
    """
    cat = cat or {}
    cid = str(cat.get("id") or "")
    label = str(cat.get("label") or cid or "未知类别")
    sigs = _signals_in(signals, cid)
    parts = []

    if cat.get("score") is None:
        parts.append(
            "**%s（%s）这次没有分**：%d 条向量全是「测不了」，这既不是干净也不是有问题，"
            "而是这一类在这台设备上没法判定。" % (label, cid, len(sigs))
        )
    elif lead:
        s = float(cat["score"])
        if s >= 95:
            mood = "几乎全干净"
        elif s >= 80:
            mood = "大体干净，但有零星可疑"
        elif s >= 50:
            mood = "差不多一半被判为可疑或被坐实"
        else:
            mood = "被坐实的条数已经压过了干净的条数"
        rank_txt = _rank_sentence(run, cat).rstrip("。")
        # 排名本身已经说了「最差/最好」时就不必再重复 mood（避免「最差 + 掉得最狠」同义反复）
        if rank_txt.startswith("六类里最差") or rank_txt.startswith("六类里最好"):
            head = rank_txt
        else:
            head = mood + ("，" + rank_txt if rank_txt else "")
        parts.append("**%s（%s）%s 分**：%s。" % (label, cid, fmt_score(s), head))

    counted = int(cat.get("countedTotal") or 0)
    total = int(cat.get("total") or counted)
    n_clean = int(cat.get("clean") or 0)
    n_sus = int(cat.get("suspect") or 0)
    n_tam = int(cat.get("tampered") or 0)
    n_un = int(cat.get("unknown") or 0) + int(cat.get("error") or 0) + int(cat.get("flaky") or 0)
    bits = []
    if counted:
        bits.append("可判定 %d 条里 %d 条干净" % (counted, n_clean))
        if n_sus:
            bits.append("%d 条可疑" % n_sus)
        if n_tam:
            bits.append("%d 条被坐实" % n_tam)
    if n_un:
        bits.append("另有 %d 条测不了（不计分）" % n_un)
    if total and total != counted + n_un:
        bits.append("共 %d 条向量" % total)
    if bits:
        parts.append("，".join(bits) + "。")

    key = key_vectors(sigs)
    if key:
        v = key[0]
        ev = short(v.get("evidence"), 80)
        parts.append(
            "最需要看的是 **%s**：%s，置信度 %.2f。%s"
            % (
                v.get("id"),
                verdict_label(v.get("verdict")),
                float(v.get("confidence") or 0.0),
                ("证据是 `%s`。" % ev) if ev else "这条没给证据串。",
            )
        )
    elif cat.get("score") is not None and float(cat["score"]) >= 99.99:
        parts.append("这一类没有任何一条被判为可疑或被坐实。")

    # 例外说明：满分但包被改过 → 盲区；或包没改但整类红 → 噪声
    if run:
        blind_ids = {b.get("category") for b in (run.get("blindSpots") or [])}
        if cid in blind_ids:
            parts.append("**注意**：包确实被改过，这一类却拿了满分 —— 也就是说它对着这次修补完全瞎了，见 ⑥。")
        elif (run.get("packageModified") or {}).get("modified") is False and n_tam:
            parts.append("包没被改而这一类出现被坐实，通常说明是设备环境让它成立的，见 ⑦。")

    return "".join(parts)


def key_vectors(signals, limit: int = 3) -> list:
    """挑「最该看的」几条：先按结论严重度，再按 tier 强度，再按权重。"""
    order = {"TAMPERED": 0, "ERROR": 1, "FLAKY": 2, "SUSPECT": 3, "CLEAN": 4, "UNKNOWN": 5}
    tier_rank = {"A": 0, "B": 1, "C": 2}
    interesting = [s for s in (signals or []) if str(s.get("verdict") or "").upper() not in ("CLEAN", "UNKNOWN")]
    if not interesting:
        return []
    interesting.sort(
        key=lambda s: (
            order.get(str(s.get("verdict") or "").upper(), 9),
            tier_rank.get(str(s.get("tier") or "").upper(), 3),
            -int(s.get("weight") or 0),
        )
    )
    return interesting[:limit]


# ---------------------------------------------------------------------------
# ③ 这次改了什么（expect vs actual，加一句推断）
# ---------------------------------------------------------------------------


def what_changed(run, docs=None) -> dict:
    """返回 {rows: [[检查项, 期望, 实测, 结论]], summary: str}。

    「结论」列是自动推断的：只换内容不换签名、整包重签、只动签名块……三种故事要分开讲，
    否则读者只知道「不一致」却不知道发生了什么。
    """
    run = run or {}
    expect = run.get("expect") or {}
    facts = run.get("facts") or {}
    pkg = run.get("packageModified") or {}

    got_sha = str(facts.get("apk.sha256") or "").strip()
    got_zip = str(facts.get("apk.zip.fingerprint") or facts.get("zip.fingerprint") or "").strip()
    certs = facts.get("cert.install")
    got_cert = str(certs[0]).strip() if isinstance(certs, list) and certs else ""
    want_sha = str(expect.get("apkSha256") or "").strip()
    want_zip = str(expect.get("zipFingerprint") or "").strip()
    want_cert = str(expect.get("certSha256") or "").strip()

    def cmp_row(name, want, got, unit=""):
        if not got:
            return [name, _short_hash(want), "App 没上报", "无法复核"]
        if not want:
            return [name, "构建信息里没有", _short_hash(got), "无法复核"]
        same = got.lower() == want.lower()
        return [name, _short_hash(want), _short_hash(got), "一致" if same else "**不一致**"]

    rows = [
        cmp_row("APK 全文件哈希（sha256）", want_sha, got_sha),
        cmp_row("打包指纹（ZipEntry CRC/大小/压缩方式）", want_zip, got_zip),
        cmp_row("签名证书（sha256）", want_cert, got_cert),
    ]

    reasons = {str(r.get("vector") or "") for r in (pkg.get("reasons") or [])}
    cert_mismatch = any("cert" in str(r.get("evidence") or "") for r in (pkg.get("reasons") or [])
                        if r.get("why") == "facts-expect-mismatch")
    if not pkg.get("modified"):
        if got_sha and want_sha:
            summary = "三项都能对上：装上去的这份 APK 就是我们构建的那一份，没有被动过。"
        else:
            summary = "缺少可比对的观测值，**这次没法确认包有没有被改**（见 ⑨ 原始 JSON 的 facts）。"
    elif "pkg.codepath.hash" in reasons and "pkg.zip.fingerprint" in reasons and not cert_mismatch:
        summary = (
            "签名没变、内容和打包指纹都变了 —— 典型的**二次打包**：改完 dex/资源后沿用原签名，"
            "或者绕过了签名校验。"
        )
    elif cert_mismatch:
        summary = (
            "签名变了，内容和打包指纹也跟着变 —— 整包被**重新签名并重打包**，"
            "这是最常见的「换个证书再装一遍」。"
        )
    elif "pkg.zip.fingerprint" in reasons and want_sha and got_sha and got_sha.lower() != want_sha.lower():
        summary = (
            "全文件字节变了、但签名和打包指纹未必都变 —— 常见于只替换签名块（v2/v3）"
            "或对 zip 做了重新对齐。"
        )
    else:
        summary = "至少一项与构建产物对不上，具体见上表。"
    return {"rows": rows, "summary": summary}


def _short_hash(value, n: int = 16) -> str:
    v = str(value or "").strip()
    if not v:
        return "—"
    return v if len(v) <= n else v[:n] + "…"


# ---------------------------------------------------------------------------
# ⑤ 被坐实的问题 / ⑥ 盲区 / ⑦ 环境噪声
# ---------------------------------------------------------------------------


def confirmed_item(sig, docs=None) -> dict:
    """一条被坐实的向量 → 四段固定结构（R4），外加 tier 的份量说明。"""
    sig = sig or {}
    tier = str(sig.get("tier") or "").upper()
    title = "%s · %s · %s" % (sig.get("id"), sig.get("category"), tier_label(tier))
    tier_note = _TIER_WEIGHT_NOTE.get(tier, "")
    return {
        "id": sig.get("id"),
        "title": title,
        "verdict": verdict_label(sig.get("verdict")),
        "fields": [
            ["判据", judge_text(sig, docs)],
            ["证据", ("`" + short(sig.get("evidence"), 200) + "`") if sig.get("evidence") else "（这条没给证据串）"],
            ["意味着什么", (meaning_text(sig, docs) + (" " + tier_note if tier_note else ""))],
            ["怎么修", fix_text(sig, docs)],
        ],
    }


def blindspot_story(bs, signals, docs=None, run=None) -> str:
    """盲区要说清「为什么可能是洞」+「怎么验证是不是洞」（R5）。返回多段文本。"""
    bs = bs or {}
    cid = str(bs.get("category") or "")
    label = str(bs.get("label") or cid)
    vectors = list(bs.get("vectors") or [])
    sigs = [s for s in (signals or []) if s.get("id") in set(vectors)]
    tiers = [str((docs_entry(docs, sid).get("tier") or (next((x.get("tier") for x in sigs if x.get("id") == sid), "")))).upper()
             for sid in vectors]
    tiers = [t for t in tiers if t]
    dist = {}
    for t in tiers:
        dist[t] = dist.get(t, 0) + 1

    paras = []
    paras.append(
        "**%s（%s）** %d 条向量全部是「干净」的，可这个包**确实被改过**："
        "也就是说整类检测对这次修补一条都没抓到。" % (label, cid, len(vectors) or len(sigs))
    )

    strength = ""
    if dist:
        strength = "，".join("%d 条 %s 级" % (n, t) for t, n in sorted(dist.items()))
    if dist and all(t == "C" for t in tiers):
        why = (
            "为什么可能是洞：这一类的构成是 %s，一条 A/B 级的不变量都没有。"
            "C 级是「特征匹配」（包名/属性/文件/端口/线程名），它只认**见过的痕迹**；"
            "这次修补恰好没留下它们，但下一次的修补只要多花一步就能绕开 —— "
            "整类没有不变量，等于这一类只能靠对手犯错。"
            % (strength or "全是 C 级")
        )
    elif dist:
        why = (
            "为什么可能是洞：这一类的构成是 %s。里面确实有更强的证据级别，但它们对这次修补没反应 —— "
            "要么探针没覆盖到真正的改动点，要么这些不变量的观测面选错了。"
            % (strength or "未登记")
        )
    else:
        why = "为什么可能是洞：这一类没有登记过 tier，无法判断证据强度，需要先补目录（schema/vectors.json）。"
    paras.append(why)

    steps = _VERIFY_BY_CATEGORY.get(cid) or _GENERIC_VERIFY
    paras.append("怎么验证是不是洞：" + "；".join("%d）%s" % (i + 1, s) for i, s in enumerate(steps)) + "。")
    return "\n\n".join(paras)


def noise_story(run, docs=None) -> str:
    """⑦ 环境噪声：与基线对比，讲清「这是设备脏，不是你的锅」。"""
    run = run or {}
    sc = run.get("score") or {}
    counts = sc.get("counts") or {}
    base = sc.get("baseline")
    fps = run.get("falsePositives") or []
    noise = run.get("noiseFromBaseline") or []
    blind = run.get("blindSpots") or []
    n_un = int(counts.get("unknown") or 0) + int(counts.get("error") or 0) + int(counts.get("flaky") or 0)
    n_sus = int(counts.get("suspect") or 0)
    paras = []

    if base:
        # raw 越高越干净：delta = 本次 raw − 基线 raw，负值意味着「比基线更脏」
        delta = None
        try:
            delta = float(sc.get("raw") or 0) - float(base.get("raw") or 0)
        except (TypeError, ValueError):
            delta = None
        line = "这次带基线跑：本次 raw %s 分，基线 raw %s 分" % (fmt_score(sc.get("raw")), fmt_score(base.get("raw")))
        if delta is not None:
            if delta >= 1:
                line += "，比基线**干净** %s 分（这次没把环境弄得更脏）" % fmt_score(abs(delta))
            elif delta <= -1:
                line += (
                    "，比基线**脏** %s 分 —— 只有这多出来的 %s 分才算在这次修补头上，"
                    "基线里那份噪声已经扣掉了" % (fmt_score(abs(delta)), fmt_score(abs(delta)))
                )
            else:
                line += "，与基线基本持平（差 %s 分，在噪声范围内）" % fmt_score(abs(delta))
        paras.append(line + "。")
        if noise:
            paras.append(
                "**被判为环境固有噪声的有 %d 条**：%s。它们在基线里就已经是红叉，这次也没变化，"
                "所以**没有扣分，只标注**。" % (len(noise), "、".join("`%s`" % v for v in noise))
            )
        else:
            paras.append("基线里没有「两次都红」的向量，所以这次没有环境固有噪声需要豁免。")
    else:
        paras.append(
            "这次**没带基线**跑（`--baseline` 未给），所以无法区分「设备本来就脏」和「这次修补引入的问题」："
            "下面的分数是绝对分，不是相对某台干净设备的增量。"
        )

    bits = []
    if n_sus:
        bits.append("%d 条停在可疑（有痕迹但证据不足）" % n_sus)
    if n_un:
        bits.append("%d 条完全测不了（这类不计分，但也不是「干净」）" % n_un)
    if blind:
        bits.append("%d 类整体失明（见 ⑥）" % len(blind))
    if bits:
        paras.append("另外要留意：" + "；".join(bits) + "。")
    if fps:
        paras.append(
            "本次有 %d 条被判为**误报（false positive）**：%s —— 包没被改，它们在基线里就是红的，"
            "属于这台设备的毛病。" % (len(fps), "、".join("`%s`" % f.get("vector") for f in fps))
        )
    paras.append(
        "建议：在同一台设备上用 `--baseline` 再跑一次干净包，把这次的红叉逐条对照；"
        "同一份包重复跑如果分数抖动，抖动幅度本身就是噪声底（待实测）。"
    )
    return "\n\n".join(paras)


# ---------------------------------------------------------------------------
# ⑧ 行动清单（R6：每条都带「预计 +x 分（估算）」）
# ---------------------------------------------------------------------------


def _category_gain(cat, denom_weight: float) -> float:
    """把某一类补到 100 能拿回多少总分。

    推导：raw = Σ(a_k·C_k)/Σa_k，某一类的 C_k 提高 ΔC 时 Δraw = a_k·ΔC/Σa_k。
    所以「这一类从 C_k 补到 100」的收益 = a_k·(100−C_k)/Σa_k。
    全部类别的收益之和恰好等于 100−raw，说明这个折算是自洽的（selftest 会验）。
    """
    if not denom_weight or cat.get("score") is None:
        return 0.0
    a = float(cat.get("weight") or 0.0)
    return a * (100.0 - float(cat["score"])) / float(denom_weight)


def _vector_gain(cat, weight, denom_weight: float) -> float:
    """类内修掉一条权重 w 的红叉能拿回多少总分。

    单条红叉 → 该类 C_k 提升 100·w/Σw_k（分母只算可计数向量），
    换算到总分同样乘 a_k/Σa_k。
    """
    if not denom_weight or cat.get("score") is None:
        return 0.0
    counted_w = float(cat.get("countedWeight") or 0.0)
    if counted_w <= 0:
        return 0.0
    a = float(cat.get("weight") or 0.0)
    delta_c = 100.0 * float(weight) / counted_w
    return a * delta_c / float(denom_weight)


def action_list(run, docs=None) -> list:
    """按性价比排序的行动清单。gain 全部标「估算」，没有实测的地方写「待实测」（R8）。"""
    run = run or {}
    sc = run.get("score") or {}
    cats = sc.get("categories") or []
    counted = [c for c in cats if c.get("score") is not None]
    denom = sum(float(c.get("weight") or 0.0) for c in counted)
    signals = run.get("signals") or []
    actions = []

    # 1) 修红叉：单条权重最大的先修（同分时成本更低）
    for c in counted:
        reds = [s for s in signals
                if s.get("category") == c.get("id") and str(s.get("verdict") or "").upper() == "TAMPERED"]
        reds.sort(key=lambda s: -int(s.get("weight") or 0))
        for s in reds[:2]:
            gain = _vector_gain(c, int(s.get("weight") or 3), denom)
            if gain <= 0.05:
                continue
            actions.append({
                "kind": "fix",
                "title": "处理 %s（%s）" % (s.get("id"), c.get("label")),
                "why": "它是可判定项里权重 %d 的红叉，「%s」的分数主要被它拉着。"
                       % (int(s.get("weight") or 3), c.get("label")),
                "how": fix_text(s, docs),
                "gain": round(gain, 1),
                "gain_note": "估算",
                "cost": "小" if int(s.get("weight") or 3) >= 5 else "中",
            })

    # 2) 消除可疑：整类可疑 > 0 且没有红叉时，可疑就是唯一可提分的地方
    for c in counted:
        if float(c.get("score") or 100.0) >= 99.99:
            continue
        if int(c.get("tampered") or 0):
            continue
        gain = _category_gain(c, denom)
        if gain <= 0.05:
            continue
        actions.append({
            "kind": "suspect",
            "title": "把 %s 的可疑项判成干净（或改成「测不了」）" % c.get("label"),
            "why": "该类 %d 条可疑把分数压在 %s 分；可疑项要么补证据升级成结论，要么承认测不了。"
                   % (int(c.get("suspect") or 0), fmt_score(c.get("score"))),
            "how": "逐条看 ④ 里列出的可疑向量：能补 A/B 级证据的就升级；补不了的承认「测不了」，从分母里拿掉比留在可疑里更诚实。",
            "gain": round(gain, 1),
            "gain_note": "估算",
            "cost": "中",
        })

    # 3) 盲区：现在不加分，但决定下次能不能抓到（诚实标注收益为 0）
    for b in run.get("blindSpots") or []:
        actions.append({
            "kind": "blind",
            "title": "给 %s 补一条 A 级不变量" % b.get("label"),
            "why": "包被改过，这一类 %d 条全干净 —— 现在它不加分，但下次真被改到这一面时，只有它能救。"
                   % len(b.get("vectors") or []),
            "how": "先按 ⑥ 的「怎么验证是不是洞」确认是真洞，再给这一类加一条 tier A 的判据（字节比对/密码学校验，而不是特征匹配）。",
            "gain": 0.0,
            "gain_note": "估算",
            "note": "这一类现在已满分，真正的收益要等下次修补才知道（待实测）",
            "cost": "大",
        })

    # 4) 误报：删掉/降级噪声向量，也能提分
    for f in run.get("falsePositives") or []:
        cat = next((c for c in cats if c.get("id") == f.get("category")), None)
        if not cat:
            continue
        gain = _vector_gain(cat, int(f.get("weight") or 3), denom)
        actions.append({
            "kind": "noise",
            "title": "把 %s 标成环境噪声（或降级为 tier C）" % f.get("vector"),
            "why": "包没被改，它在基线里就是红的 —— 继续算它会一直冤枉这台设备。",
            "how": "在基线白名单里登记它，或把它降级成只出「可疑」；也可以先修环境再复测。",
            "gain": round(max(gain, 0.0), 1),
            "gain_note": "估算",
            "cost": "小",
        })

    actions.sort(key=lambda a: (-float(a.get("gain") or 0.0), {"小": 0, "中": 1, "大": 2}.get(a.get("cost"), 9)))
    return actions


def gain_label(action: dict) -> str:
    """统一给行动清单写收益文案（R6 + R8）：数字一律标「估算」。"""
    g = float(action.get("gain") or 0.0)
    if abs(g) < 0.05:
        base = "预计 +0 分（%s）" % (action.get("gain_note") or "估算")
    else:
        base = "预计 +%.1f 分（%s）" % (g, action.get("gain_note") or "估算")
    if action.get("note"):
        base += "，" + action["note"]
    return base
