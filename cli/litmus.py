#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
litmus.py —— Litmus CLI 主入口。

    litmus.py doctor    环境自检（adb / 设备 / build-info / APK / schema）
    litmus.py run       adb 跑一次检测 → 拉报告 → 打分 → 写 runs/<label>-<ts>/
    litmus.py score     离线重算（不碰设备，用于回归）
    litmus.py matrix    扫 runs/ 下所有 run.json，出跨运行对比表
    litmus.py selftest  纯构造 fixture 自检（没有设备、没有 APK 也能跑）
    litmus.py demo      用内置 fixture 生成一份完整 run（给人看 report.html）

设计要点
--------
* 只用标准库。adb 之外没有任何网络行为，不做任何 root 操作。
* Windows 路径一律 pathlib；相对路径按**仓库根**解析（不按 cwd），
  这样在哪个目录下敲命令结果都一样。
* 所有磁盘 IO 都是 UTF-8 + ensure_ascii=False（中文 evidence 必须肉眼可读）。
* 拉报告三级回退：① 设备文件 ② logcat（单行 / CHUNK 分片）③ 明确报错。
  绝不静默返回「没有信号 = 满分」—— 那会把「拉不到报告」伪装成「检测通过」。
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import traceback
import zlib
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import litmus_report as R  # noqa: E402  （同目录模块，必须在 sys.path 处理之后导入）
import litmus_narrative as N  # noqa: E402
import litmus_score as S  # noqa: E402

CLI_VERSION = R.VERSION
REPO_ROOT = Path(os.environ.get("LITMUS_ROOT") or _HERE.parent).resolve()

PKG = "io.litmus.canary"
ACTIVITY = "%s/.MainActivity" % PKG
LOG_TAG = "LitmusReport"
REMOTE_DIR = "/sdcard/Android/data/%s/files/litmus" % PKG

DEFAULT_ADB_CANDIDATES = (
    r"D:\dev\android-sdk\platform-tools\adb.exe",
    r"C:\android-sdk\platform-tools\adb.exe",
)

BUILD_INFO_REL = Path("canary") / "out" / "build-info.json"


class CliError(Exception):
    """可预期的操作失败：直接给用户一句人话，不要 traceback。"""


# ---------------------------------------------------------------------------
# 终端初始化：让中文在 PowerShell / cmd 里都能显示
# ---------------------------------------------------------------------------


def init_stdio() -> None:
    """把 stdout/stderr 切成 UTF-8。

    Windows 上 Python 默认按 ANSI 代码页（简中机器是 GBK/936）编码标准输出，
    直接 print('✓') 会 UnicodeEncodeError 或乱码。两件事都要做：
      1. stream.reconfigure(encoding='utf-8')  ← 改 Python 侧
      2. SetConsoleOutputCP(65001)             ← 改控制台侧，否则字节是 UTF-8、控制台按 GBK 解
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass


def use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("LITMUS_COLOR") == "0":
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 路径 / JSON 工具
# ---------------------------------------------------------------------------


def rp(path) -> Path:
    """把命令行给的路径解析到绝对路径：绝对路径原样，相对路径按仓库根解析。"""
    p = Path(str(path)).expanduser()
    return p.resolve() if p.is_absolute() else (REPO_ROOT / p).resolve()


def rel(path) -> str:
    """给用户看路径时优先用相对仓库根的短形式。"""
    try:
        return str(Path(path).resolve().relative_to(REPO_ROOT))
    except Exception:
        return str(path)


def read_json(path) -> dict:
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise CliError("文件不存在：%s" % rel(p))
    except UnicodeDecodeError as e:
        raise CliError("%s 不是 UTF-8 文本：%s" % (rel(p), e))
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise CliError("%s 不是合法 JSON（第 %d 行第 %d 列：%s）" % (rel(p), e.lineno, e.colno, e.msg))
    if not isinstance(obj, dict):
        raise CliError("%s 顶层不是 JSON 对象" % rel(p))
    return obj


def write_json(path, obj) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return p


def write_text(path, text: str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def now_iso() -> str:
    """UTC + Z，与 App 侧 LitmusRunner.iso8601() 同格式（便于排序/对账）。"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


@contextlib.contextmanager
def scratch_dir(prefix: str = "selftest-"):
    """临时工作目录，放在仓库内 `cli/.tmp/`。

    两个坑，都踩过：
      1. 受限沙箱/CI 里系统 %TEMP% 往往不可写（实测 WinError 5），而仓库目录一定可写；
      2. **不能用 tempfile.mkdtemp()**：它在 Windows 上按 0o700 建目录，
         Python 3.13+ 会把该 mode 落成受限 DACL，结果连自己都写不进去（PermissionError）。
         所以这里自己起名 + 默认 mode 建目录。
    用完即删，`.tmp/` 已进 cli/.gitignore。
    """
    base = REPO_ROOT / "cli" / ".tmp"
    base.mkdir(parents=True, exist_ok=True)
    d = base / (prefix + secrets.token_hex(6))
    d.mkdir(parents=True, exist_ok=True)
    try:
        yield d
    finally:
        shutil.rmtree(str(d), ignore_errors=True)


def load_expect(path) -> tuple[dict, Path]:
    p = rp(path)
    obj = read_json(p)
    schema = obj.get("schema")
    if schema and schema != S.SCHEMA_BUILD:
        print("[warn] build-info.json 的 schema=%r，期望 %r（继续按字段读取）" % (schema, S.SCHEMA_BUILD), file=sys.stderr)
    return obj, p


def default_build_info() -> Path:
    return rp(BUILD_INFO_REL)


def expect_summary(expect: dict) -> dict:
    """run.json 里只放对账需要的字段（其余留在 report.raw 与 build-info.json）。

    builtAt/sizeBytes 也抄一份：构建产物会在开发期反复重出，事后回看得知道
    「这次比的是哪一次的包」，否则分数突然变了却查不出来。
    """
    return {
        "apkSha256": expect.get("apkSha256"),
        "certSha256": expect.get("certSha256"),
        "zipFingerprint": expect.get("zipFingerprint"),
        "version": expect.get("version"),
        "flavor": expect.get("flavor"),
        "builtAt": expect.get("builtAt"),
        "sizeBytes": expect.get("sizeBytes"),
        "apk": expect.get("apk"),
    }


# ---------------------------------------------------------------------------
# adb
# ---------------------------------------------------------------------------


def find_adb(explicit=None) -> str:
    """定位 adb：显式参数 > LITMUS_ADB > 常见安装路径 > PATH。"""
    if explicit:
        p = Path(str(explicit))
        if p.is_file():
            return str(p)
        raise CliError("--adb 指定的文件不存在：%s" % explicit)
    env = os.environ.get("LITMUS_ADB")
    if env:
        p = Path(env)
        if p.is_file():
            return str(p)
    for cand in DEFAULT_ADB_CANDIDATES:
        if Path(cand).is_file():
            return cand
    found = shutil.which("adb")
    if found:
        return found
    raise CliError(
        "找不到 adb。三种修法任选：① 装 Android platform-tools 并加入 PATH "
        "② 设环境变量 LITMUS_ADB=<adb.exe 全路径> ③ 命令加 --adb <路径>"
    )


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "gbk"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


class Adb:
    """adb 薄封装。

    为什么所有调用都走 bytes + 自己解码：Windows 上 adb 输出是按系统代码页编码的，
    subprocess(text=True) 会用 locale 编码去解，中文设备名会直接抛 UnicodeDecodeError。
    """

    def __init__(self, serial=None, adb_path=None, echo=False):
        self.adb = find_adb(adb_path)
        self.serial = serial
        self.echo = echo

    def _base(self) -> list:
        cmd = [self.adb]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd

    def run(self, args, timeout=60) -> tuple[int, bytes, bytes]:
        cmd = self._base() + [str(a) for a in args]
        if self.echo:
            print("[adb] " + " ".join(cmd), file=sys.stderr)
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        except FileNotFoundError:
            raise CliError("adb 不存在：%s" % self.adb)
        except subprocess.TimeoutExpired:
            raise CliError("adb 命令超时（%.0fs）：%s" % (timeout, " ".join(cmd[1:])))
        return p.returncode, p.stdout, p.stderr

    def text(self, args, timeout=60) -> str:
        rc, out, err = self.run(args, timeout=timeout)
        blob = out + (b"\n" + err if err and rc != 0 else b"")
        return _decode(blob)

    def shell(self, *args, timeout=60) -> str:
        return self.text(["shell"] + list(args), timeout=timeout)

    def devices(self) -> list:
        rc, out, err = self.run(["devices"], timeout=30)
        text = _decode(out) + _decode(err)
        result = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices") or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                result.append((parts[0], parts[1]))
        return result


def pick_serial(adb: Adb, want: str | None) -> str:
    devs = adb.devices()
    if not devs:
        raise CliError("没有检测到任何设备。检查：USB 调试是否打开 / 模拟器是否启动 / adb kill-server 后重试")
    if want:
        for serial, state in devs:
            if serial == want:
                if state != "device":
                    raise CliError("设备 %s 状态是 %r（需要 device；unauthorized 时请在手机上点「允许调试」）" % (serial, state))
                adb.serial = serial
                return serial
        raise CliError("找不到序列号 %r 的设备；当前：%s" % (want, ", ".join("%s(%s)" % d for d in devs)))
    online = [s for s, st in devs if st == "device"]
    if not online:
        raise CliError("设备在线但状态异常：%s" % ", ".join("%s(%s)" % d for d in devs))
    adb.serial = online[0]
    if len(online) > 1:
        print("[warn] 有多台设备，默认用 %s；要换请加 --serial" % online[0], file=sys.stderr)
    return online[0]


# ---------------------------------------------------------------------------
# logcat 协议解析（契约 §4.3）
# ---------------------------------------------------------------------------

P_SINGLE = "LITMUS_REPORT "
P_CHUNK = "LITMUS_REPORT_CHUNK "
P_PATH = "LITMUS_REPORT_PATH "


def _try_json(text: str):
    text = text.strip()
    if not text:
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def parse_logcat(text: str):
    """从 logcat 文本里还原 App 报告。

    返回 (report|None, how, path|None)。
    协议：单行 `LITMUS_REPORT {json}`；超长走 `LITMUS_REPORT_CHUNK i/n <b64>`；
    另外 App 落盘后会打一行 `LITMUS_REPORT_PATH <绝对路径>`，用它可以把
    「文件回退」从盲猜目录升级成精确路径（顺便规避 Android 11+ 的 scoped storage 限制）。
    """
    single = None
    path = None
    groups = []  # 每次出现 idx==1 开一个新组，避免把两轮运行的分片拼在一起
    cur = None

    for line in text.splitlines():
        ip = line.find(P_PATH)
        if ip >= 0:
            cand = line[ip + len(P_PATH):].strip()
            if cand:
                path = cand
            continue
        ic = line.find(P_CHUNK)
        if ic >= 0:
            body = line[ic + len(P_CHUNK):].strip()
            parts = body.split(" ", 1)
            if len(parts) != 2 or "/" not in parts[0]:
                continue
            try:
                idx_s, total_s = parts[0].split("/", 1)
                idx, total = int(idx_s), int(total_s)
            except ValueError:
                continue
            if idx == 1 or cur is None or cur.get("total") != total:
                cur = {"total": total, "parts": {}}
                groups.append(cur)
            cur["parts"][idx] = parts[1].strip()
            continue
        isng = line.find(P_SINGLE)
        if isng >= 0:
            obj = _try_json(line[isng + len(P_SINGLE):])
            if obj is not None:
                single = obj
            continue

    # 单行优先取最后一条（一轮运行可能有多次 publish）
    if single is not None:
        return single, "logcat:single", path

    # 分片：取最后一个完整组
    for g in reversed(groups):
        total = g["total"]
        parts = g["parts"]
        if total <= 0 or len(parts) < total or any(i not in parts for i in range(1, total + 1)):
            continue
        b64 = "".join(parts[i] for i in range(1, total + 1))
        try:
            raw = base64.b64decode(b64, validate=False)
            obj = _try_json(raw.decode("utf-8", errors="replace"))
        except (binascii.Error, ValueError):
            continue
        if obj is not None:
            return obj, "logcat:chunk(%d)" % total, path
    return None, "", path


def logcat_dump(adb: Adb, since_seconds: int | None = None) -> str:
    """抓当前 logcat 缓冲里 tag=LitmusReport 的行。

    用 `-s LitmusReport:I` 过滤，避免把整机日志拉回来（4000 行 × 几十 KB 很慢）。
    `-v brief` 去掉时间戳前缀，减少误匹配面。
    """
    return adb.text(["logcat", "-d", "-v", "brief", "-s", "%s:I" % LOG_TAG], timeout=25)


# ---------------------------------------------------------------------------
# 拉报告：三级回退
# ---------------------------------------------------------------------------


def _remote_list(adb: Adb) -> list:
    """列出设备上的报告文件（新→旧）。

    两条路径都试：
      a) 直接 `ls -t /sdcard/Android/data/<pkg>/files/litmus/` —— shell 用户能读就行；
      b) `run-as <pkg> ls ...` —— Android 11+ scoped storage 把 shell 用户挡在外面，
         但以应用自身 uid 执行时可以读自己的外部目录；仅 debuggable 包能用。
    """
    out_paths = []
    for args in (
        ["shell", "ls", "-t", REMOTE_DIR],
        ["shell", "run-as", PKG, "ls", "-t", REMOTE_DIR],
    ):
        text = adb.text(args, timeout=20)
        for line in text.splitlines():
            name = line.strip()
            if not name or name.startswith("ls:") or "Permission denied" in name or name.startswith("run-as:"):
                continue
            if "/" in name:  # `ls` 有时回全路径
                out_paths.append(name if name.startswith("/") else REMOTE_DIR + "/" + name.split("/")[-1])
            else:
                out_paths.append(REMOTE_DIR + "/" + name)
        if out_paths:
            return out_paths
    return out_paths


def _cat_remote(adb: Adb, remote_path: str):
    """读远端文件。

    用 `exec-out` 而不是 `shell`：`adb shell` 会把 \n 转成 \r\n（Windows 客户端上更糟），
    而报告里可能有 base64/中文，宁可拿原始字节。
    """
    rc, out, err = adb.run(["exec-out", "cat", remote_path], timeout=30)
    if rc != 0 or not out.strip():
        return None
    return _try_json(_decode(out))


def pull_report_from_device(adb: Adb, hinted_path: str | None = None):
    """① 设备文件。返回 (report|None, 说明)。"""
    candidates = []
    if hinted_path:
        candidates.append(hinted_path)
    candidates.extend(_remote_list(adb))
    if not candidates:
        return None, "① 设备文件：%s 不存在或不可读" % REMOTE_DIR
    for path in candidates:
        obj = _cat_remote(adb, path)
        if obj is not None:
            return obj, "① 设备文件：%s" % path
    return None, "① 设备文件：读到了 %d 个文件但都解不出 JSON" % len(candidates)


def pull_report(adb: Adb, prefer_logcat: bool = True):
    """两路都试，返回 (report|None, source, notes)。

    logcat 优先是有原因的：它一条命令就能同时给出「报告本体」和「落盘路径」，
    比先 ls 再 cat 少一半 round-trip；设备文件则作为 logcat 被 -c 清掉 / 被别的
    进程刷掉时的兜底。两路都失败才算失败（③）。
    """
    notes = []
    if prefer_logcat:
        rep, how, path = parse_logcat(logcat_dump(adb))
        if rep is not None:
            return rep, how, notes
        notes.append("② logcat：没有 LITMUS_REPORT / LITMUS_REPORT_CHUNK 记录")
        rep, note = pull_report_from_device(adb, path)
    else:
        rep, note = pull_report_from_device(adb)
        if rep is not None:
            return rep, "sdcard", notes
        notes.append(note)
        lg, how, _p = parse_logcat(logcat_dump(adb))
        return lg, how, notes
    notes.append(note)
    return rep, ("sdcard" if rep is not None else ""), notes


# ---------------------------------------------------------------------------
# 组装 run.json（run / score / demo 共用同一条路径）
# ---------------------------------------------------------------------------


def app_summary_check(report: dict) -> dict:
    """拿 App 自算的 summary 和 CLI 用**同一公式**重算的结果对账。

    这是「与 Score.java 一致性」的可执行证据：App 的 summary 是 Score.java 算的，
    CLI 用 litmus_score.summarize() 对同一批 signal 再算一遍（profile=standard，
    且**不带** CLI 平面信号，因为 App 看不见它们）。两个 score 必须相等，
    否则说明两侧公式/四舍五入/权重有一处漂了。回归时先看这个字段。
    """
    app = report.get("summary") if isinstance(report.get("summary"), dict) else None
    if not app:
        return {"checked": False, "reason": "report.summary 缺失（App 端版本过旧）"}
    cli = S.summarize(report.get("signals") or [], profile="standard")
    deltas = {}
    for k in ("total", "clean", "suspect", "tampered", "unknown", "error", "flaky"):
        if k in app:
            deltas[k] = int(app.get(k) or 0) - int(cli.get(k) or 0)
    sd = None
    if app.get("score") is not None and cli.get("score") is not None:
        sd = round(float(app["score"]) - float(cli["score"]), 3)
    ok = (sd is None or abs(sd) < 1e-9) and not any(v for v in deltas.values())
    return {
        "checked": True,
        "match": ok,
        "appScore": app.get("score"),
        "cliScore": cli.get("score"),
        "scoreDelta": sd,
        "countDeltas": deltas,
    }


def analyze_report(report: dict, expect: dict, profile: str, baseline_report: dict | None):
    analysis = S.analyze(report, expect, profile=profile, baseline_report=baseline_report)
    return analysis


def assemble_run_json(
    *,
    report: dict,
    expect: dict,
    expect_path=None,
    analysis: dict,
    label: str,
    framework: str,
    serial: str,
    started_at: str,
    finished_at: str,
    mode: str,
    report_source: str,
    baseline_path=None,
    app_run_id: str = "",
) -> dict:
    """把 App 报告 + 评分结论拼成稳定的 run.json（契约 §4.2 litmus.run/1）。"""
    summary = analysis["summary"]
    dev = report.get("device") or {}
    app = report.get("app") or {}
    producer = report.get("producer") or {}
    counts = {k: summary[k] for k in ("total", "clean", "suspect", "tampered", "unknown", "error", "flaky")}

    score = {
        "litmus": analysis["litmus"],
        "raw": summary["score"],
        "rawExact": summary["raw"],
        "profile": analysis["profile"],
        "baseline": analysis["baseline"],
        "counts": counts,
        "categories": summary["categories"],
    }

    run_block = {
        "id": "%s-%s" % (label, (started_at or now_iso()).replace(":", "").replace("-", "")),
        "appRunId": app_run_id,
        "startedAt": started_at,
        "finishedAt": finished_at,
        "label": label,
        "framework": framework,
        "profile": analysis["profile"],
        "mode": mode,
        "reportSource": report_source,
        "cliVersion": CLI_VERSION,
        "expectPath": rel(expect_path) if expect_path else None,
        "baselinePath": rel(baseline_path) if baseline_path else None,
        "device": {
            "serial": serial or "",
            "manufacturer": dev.get("manufacturer") or "",
            "model": dev.get("model") or "",
            "brand": dev.get("brand") or "",
            "sdk": dev.get("sdk"),
            "release": dev.get("release") or "",
            "fingerprint": dev.get("fingerprint") or "",
        },
        "app": {
            "package": app.get("package") or "",
            "pid": app.get("pid"),
            "codePath": app.get("codePath") or "",
        },
    }

    return {
        "schema": S.SCHEMA_RUN,
        "run": run_block,
        "expect": expect_summary(expect),
        "app": app,
        "device": dev,
        "producer": producer,
        "facts": report.get("facts") or {},
        "signals": analysis["signals"],
        "score": score,
        "blindSpots": analysis["blindSpots"],
        "falsePositives": analysis["falsePositives"],
        "noiseFromBaseline": analysis["noiseFromBaseline"],
        "packageModified": analysis["packageModified"],
        "appSummaryCheck": app_summary_check(report),
        # 契约告警 = 报告自身的问题 + 与向量目录对不上的问题（不阻断出分，但要看得见）
        "validation": S.validate_report(report) + S.catalog_problems(report.get("signals") or [], S.load_catalog()),
        "coverage": S.catalog_coverage(analysis["signals"], S.load_catalog()),
    }


_DOCS_CACHE = {}


def load_docs(catalog=None) -> dict:
    """向量文案（zh/plain/bypass）——报告里「判据/意味着/怎么修」的唯一来源。

    读不到 schema/vectors.json 也不报错：litmus_narrative 会回落到 zh 与按类别的加固建议。
    """
    key = "default"
    if key in _DOCS_CACHE:
        return _DOCS_CACHE[key]
    docs = N.docs_from_catalog(catalog if catalog is not None else S.load_catalog())
    _DOCS_CACHE[key] = docs
    return docs


def write_run_bundle(out_dir: Path, report: dict, run_json: dict, docs=None) -> dict:
    """写四件套：report.raw.json（App 原样）/ run.json（全量记账）/ report.md / report.html。

    paths 传给渲染层是为了在 ⑨ 附录里写出**能直接复制执行**的复现命令，
    而不是让人自己猜这次跑的是哪个目录。
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    docs = docs if docs is not None else load_docs()
    paths = {
        "dir": rel(out_dir),
        "raw": rel(out_dir / "report.raw.json"),
        "json": rel(out_dir / "run.json"),
    }
    out = {
        "raw": write_json(out_dir / "report.raw.json", report),
        "json": write_json(out_dir / "run.json", run_json),
        "md": write_text(out_dir / "report.md", R.to_markdown(run_json, docs=docs, paths=paths)),
        "html": write_text(out_dir / "report.html", R.to_html(run_json, docs=docs, paths=paths)),
    }
    return out


# ---------------------------------------------------------------------------
# 内置 fixture（selftest / demo 共用；纯构造，不依赖设备或 APK）
# ---------------------------------------------------------------------------

_F64 = "0123456789abcdef" * 4          # 64 位十六进制占位（看似真哈希）


def _sig(sid, cat, verdict, conf, weight, tier, evidence):
    return {
        "id": sid,
        "category": cat,
        "verdict": verdict,
        "confidence": conf,
        "weight": weight,
        "tier": tier,
        "evidence": evidence,
        "ms": 1,
    }


def _envelope(signals, summary, facts, run_id="fixture", device=None):
    return {
        "schema": S.SCHEMA_REPORT,
        "producer": {
            "name": PKG,
            "version": "0.1.0",
            "flavor": "release",
            "buildUtc": "2026-11-10T08:00:00Z",
            "buildInfo": "fixture",
            "hasNative": True,
        },
        "run": {
            "id": run_id,
            "collectedAt": "2026-11-10T08:01:02Z",
            "durationMs": 412,
            "passes": 1,
            "probeCount": len(signals),
            "snapshotError": "",
        },
        "app": {
            "package": PKG,
            "pid": 12345,
            "uid": 10123,
            "process": PKG,
            "codePath": "/data/app/~~x/base.apk",
            "debuggable": False,
            "targetSdk": 32,
        },
        "device": device
        or {
            "manufacturer": "Google",
            "model": "sdk_gphone64_arm64",
            "brand": "google",
            "fingerprint": "google/sdk_gphone64_arm64/emu64a:12/SE1A.220203.002/1:userdebug/dev-keys",
            "sdk": 32,
            "release": "12",
            "abis": ["arm64-v8a"],
            "emulatorHint": True,
        },
        "facts": facts,
        "signals": signals,
        "summary": summary,
    }


def fixture_a() -> tuple[dict, dict]:
    """A：包**未**被改，frida 痕迹明显。用来验证「不误报盲区」与多类别混合计分。

    手算过程（也是 selftest 的期望值来源）：
      runtime-integrity: Σw=4+4+4+2=14, Σ(w·s)=4+4=8 → C=100(1-8/14)=42.857142857…
      injection:         Σw=6, Σ=1.5+1.5=3        → C=50.0
      package-integrity: 只有 pkg.signature(CLEAN,w5) → 100；CLI 补两条 CLEAN(w5,w5) → 仍 100
      privilege:         priv.su CLEAN(w4)；priv.props UNKNOWN 不进分母 → 100
      virtualization:    virt.emulator.props CLEAN → 100
      environment:       只有 env.debuggable ERROR → 无可用分母，类别分 = null（不参与总分）
      raw = (0.24·42.857142857 + 0.22·50 + 0.20·100 + 0.14·100 + 0.10·100) / 0.90
          = 65.2857142857 / 0.90 = 72.5396825397 → 72.5
    App 侧（不含 CLI 两条）的 raw 恰好也是 72.5（pkg 本来就是 100）。
    """
    expect = {"apkSha256": _F64, "zipFingerprint": _F64[::-1], "certSha256": _F64}
    facts = {
        "apk.sha256": _F64,
        "apk.zip.fingerprint": _F64[::-1],
        "cert.install": [_F64],
        "apk.codePath": "/data/app/~~x/base.apk",
        "apk.dex.count": 1,
    }
    sigs = [
        _sig("rt.tracerpid", "runtime-integrity", S.TAMPERED, 1.0, 4, "A", "TracerPid=1234（libc）vs 裸 syscall 1234，进程被 ptrace 附着"),
        _sig("rt.maps.anon_exec", "runtime-integrity", S.TAMPERED, 0.92, 4, "B", "maps 中 3 段 r-xp 匿名映射，共 81920 字节（frida gum trampoline 池）"),
        _sig("rt.got.integrity", "runtime-integrity", S.CLEAN, 0.95, 4, "A", "扫描 214 个 GOT 落点，全部落在已映射段内"),
        _sig("rt.maps.deleted", "runtime-integrity", S.CLEAN, 0.9, 2, "B", "maps 中无 (deleted) file-backed 段"),
        _sig("inj.frida.port", "injection", S.SUSPECT, 0.7, 3, "B", "/proc/net/tcp 命中 27042 (0x69A2) 监听"),
        _sig("inj.frida.socket", "injection", S.SUSPECT, 0.65, 3, "C", "unix socket 名含 gmain/gum-js-loop 前缀"),
        _sig("pkg.signature", "package-integrity", S.CLEAN, 0.99, 5, "A", "签名与 built-in 期望值一致（sha256=0123…）"),
        _sig("priv.su", "privilege", S.CLEAN, 0.9, 4, "B", "PATH 与常见 12 个 su 路径均不可执行"),
        _sig("priv.props", "privilege", S.UNKNOWN, 0.0, 3, "B", "ro.debuggable 读取被 SELinux 拒绝（本机型不可测）"),
        _sig("virt.emulator.props", "virtualization", S.CLEAN, 0.85, 3, "B", "qemu/goldfish/ranchu 属性均为空"),
        _sig("env.debuggable", "environment", S.ERROR, 0.0, 3, "C", "ActivityManager.getPackageInfo 抛 NameNotFoundException"),
    ]
    summary = {
        "total": 11, "clean": 5, "suspect": 2, "tampered": 2,
        "unknown": 1, "error": 1, "flaky": 0, "score": 72.5,
    }
    return _envelope(sigs, summary, facts, run_id="fa1"), expect


def fixture_b() -> tuple[dict, dict]:
    """B：包**被**改（哈希不符），多类满分 → 制造 5 个盲区。

    App 侧 raw = 100.0（App 看不见自己的哈希，所以它认为完美）；
    CLI 补上 pkg.codepath.hash TAMPERED(w5) 后：
      package-integrity: Σw=5(signature)+5(hash)+5(zip)=15, Σ(w·s)=5 → C=66.666…→66.7
      其余五类均 100
      raw = (0.24·100 + 0.22·100 + 0.20·66.6666667 + 0.14·100 + 0.10·100 + 0.10·100)/1.0 = 93.3333 → 93.3
    包已改 + 5 类满分 → 5 个盲区。这正是产品的核心叙事。
    """
    expect = {"apkSha256": _F64, "zipFingerprint": _F64[::-1], "certSha256": _F64}
    facts = {
        "apk.sha256": ("deadbeef" * 8),          # ≠ expect.apkSha256 → TAMPERED
        "apk.zip.fingerprint": _F64[::-1],       # = expect → CLEAN
        "cert.install": [_F64],                  # = expect → 证书没换（只改了 dex）
        "apk.dex.count": 1,
    }
    sigs = [
        _sig("pkg.signature", "package-integrity", S.CLEAN, 0.99, 5, "A", "签名一致（改的是 dex，不是签名块）"),
        _sig("rt.tracerpid", "runtime-integrity", S.CLEAN, 0.95, 4, "A", "TracerPid=0"),
        _sig("rt.maps.file_integrity", "runtime-integrity", S.CLEAN, 0.9, 4, "A", "liblitmus.so r-x 段字节与磁盘一致"),
        _sig("inj.frida.port", "injection", S.CLEAN, 0.9, 3, "B", "27042/27043 均未监听"),
        _sig("priv.su", "privilege", S.CLEAN, 0.9, 4, "B", "无 su"),
        _sig("priv.mounts", "privilege", S.CLEAN, 0.8, 3, "B", "/proc/mounts 无异常挂载"),
        _sig("virt.emulator.props", "virtualization", S.CLEAN, 0.85, 3, "B", "无模拟器属性"),
        _sig("env.debuggable", "environment", S.CLEAN, 0.95, 3, "C", "FLAG_DEBUGGABLE=0"),
        _sig("env.proxy", "environment", S.CLEAN, 0.7, 3, "C", "无 VPN/代理"),
    ]
    summary = {
        "total": 9, "clean": 9, "suspect": 0, "tampered": 0,
        "unknown": 0, "error": 0, "flaky": 0, "score": 100.0,
    }
    return _envelope(sigs, summary, facts, run_id="fb2"), expect


def fixture_c() -> tuple[dict, dict, dict]:
    """C：包未改 + 给了基线 → 验证误报（FP）与基线归一。

    本轮（App 侧）：rt.tracerpid CLEAN(w4)=100 / priv.mounts TAMPERED(w3)+priv.su CLEAN(w4)=57.142857
                    / env.proxy CLEAN(w3)=100；App raw = (0.24·100+0.14·57.142857+0.10·100)/0.48 = 87.5
    本轮（CLI 侧）：再加 pkg 两条 CLEAN(各 w5) → pkg=100
                    raw = (0.24·100+0.20·100+0.14·57.142857+0.10·100)/0.68 = 91.176470588 → 91.2
    基线：priv.mounts TAMPERED、priv.su CLEAN、rt.tracerpid TAMPERED、env.proxy CLEAN
                    raw = (0.24·0+0.14·57.142857+0.10·100)/0.48 = 37.5
    基线归一：P=0.0882 < Pb=0.625 → adj = 100.0（基线更脏，本次没有新增污染）
    误报：priv.mounts 在基线里 TAMPERED、本轮仍 TAMPERED、包未改 → 环境固有噪声
          rt.tracerpid 基线 TAMPERED 但本轮 CLEAN → **不算**误报（条件：本轮仍 TAMPERED）
    """
    expect = {"apkSha256": _F64, "zipFingerprint": _F64[::-1], "certSha256": _F64}
    facts = {"apk.sha256": _F64, "apk.zip.fingerprint": _F64[::-1], "cert.install": [_F64]}
    cur = [
        _sig("rt.tracerpid", "runtime-integrity", S.CLEAN, 0.95, 4, "A", "TracerPid=0"),
        _sig("priv.mounts", "privilege", S.TAMPERED, 0.8, 3, "B", "/proc/mounts 出现 overlay 于 /system"),
        _sig("priv.su", "privilege", S.CLEAN, 0.9, 4, "B", "无 su"),
        _sig("env.proxy", "environment", S.CLEAN, 0.7, 3, "C", "无 VPN/代理"),
    ]
    summary = {
        "total": 4, "clean": 3, "suspect": 0, "tampered": 1,
        "unknown": 0, "error": 0, "flaky": 0, "score": 87.5,
    }
    base = [
        _sig("rt.tracerpid", "runtime-integrity", S.TAMPERED, 1.0, 4, "A", "TracerPid=99（基线环境有调试器）"),
        _sig("priv.mounts", "privilege", S.TAMPERED, 0.8, 3, "B", "/proc/mounts 出现 overlay 于 /system"),
        _sig("priv.su", "privilege", S.CLEAN, 0.9, 4, "B", "无 su"),
        _sig("env.proxy", "environment", S.CLEAN, 0.7, 3, "C", "无 VPN/代理"),
    ]
    base_summary = {
        "total": 4, "clean": 2, "suspect": 0, "tampered": 2,
        "unknown": 0, "error": 0, "flaky": 0, "score": 37.5,
    }
    return _envelope(cur, summary, facts, run_id="fc3"), _envelope(base, base_summary, facts, run_id="fb0"), expect


def fixture_named(name: str):
    n = (name or "b").strip().lower()
    if n in ("a", "clean-pkg", "frida"):
        rep, exp = fixture_a()
        return rep, exp, None
    if n in ("b", "tampered", "blind"):
        rep, exp = fixture_b()
        return rep, exp, None
    if n in ("c", "baseline", "fp"):
        cur, base, exp = fixture_c()
        return cur, exp, base
    raise CliError("未知 fixture %r，可选 a / b / c" % name)


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# selftest 用的小工具（纯文本检查，不需要设备）
# ---------------------------------------------------------------------------

_VERDICT_WORDS = ("TAMPERED", "SUSPECT", "CLEAN", "UNKNOWN", "ERROR", "FLAKY")


def bare_verdicts(text: str) -> list:
    """找出「裸的」结论词（R3）。

    只允许「中文（VERDICT）」这种带解释的形式；其它位置出现大写结论词就算违规。
    返回 [(词, 上下文)]，空列表 = 合规。
    """
    bad = []
    for v in _VERDICT_WORDS:
        for m in re.finditer(re.escape(v), text):
            before = text[max(0, m.start() - 1):m.start()]
            after = text[m.end():m.end() + 1]
            if before == "（" and after == "）":
                continue
            bad.append((v, text[max(0, m.start() - 18):m.end() + 4]))
    return bad


def strip_tags(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text or "")


def md_section_titles(text: str) -> list:
    return [ln[3:].strip() for ln in (text or "").splitlines() if ln.startswith("## ")]


def html_section_titles(text: str) -> list:
    return [m.group(1).strip() for m in re.finditer(r"<h2>(.*?)</h2>", text or "")]


class Checker:
    """极简断言器：不抛异常、跑完全部再汇报，方便一次看全。"""

    def __init__(self, verbose: bool = False):
        self.ok = 0
        self.fail = []
        self.verbose = verbose
        self.section = ""

    def head(self, title: str) -> None:
        self.section = title
        print("\n── %s" % title)

    def check(self, name: str, cond: bool, detail: str = "") -> bool:
        if cond:
            self.ok += 1
            if self.verbose:
                print("  ✓ %s" % name)
            return True
        self.fail.append("%s%s" % (self.section + " / " if self.section else "", name + (" — " + detail if detail else "")))
        print("  ✗ %s%s" % (name, "  (" + detail + ")" if detail else ""))
        return False

    def eq(self, name: str, got, want) -> bool:
        return self.check(name, got == want, "got=%r want=%r" % (got, want))

    def close(self, name: str, got, want, tol: float = 0.05) -> bool:
        try:
            ok = got is not None and abs(float(got) - float(want)) <= tol
        except (TypeError, ValueError):
            ok = False
        return self.check(name, ok, "got=%r want=%r±%s" % (got, want, tol))

    def done(self) -> bool:
        total = self.ok + len(self.fail)
        print("")
        if self.fail:
            print("FAIL：%d/%d 项断言未通过" % (len(self.fail), total))
            for f in self.fail:
                print("  - %s" % f)
            return False
        print("全部 %d 项断言通过" % total)
        print("OK")
        return True


def cmd_selftest(args) -> int:
    ck = Checker(verbose=getattr(args, "verbose", False))
    print("Litmus CLI selftest · cli %s · Python %s" % (CLI_VERSION, sys.version.split()[0]))
    print("（纯构造 fixture，不需要设备 / APK / adb）")

    # ---------------- 1. 四舍五入语义 & 权重表 ----------------
    ck.head("1. 数值语义（必须与 Score.java 逐位一致）")
    ck.close("round1(42.857142857) == 42.9（Java Math.round 语义）", S.round1(42.85714285714286), 42.9, 1e-9)
    ck.close("round1(0.25) == 0.3（不是 Python round 的 0.2）", S.round1(0.25), 0.3, 1e-9)
    ck.close("round1(66.666666) == 66.7", S.round1(66.66666666666667), 66.7, 1e-9)
    ck.eq("standard 权重和 == 1.0", round(sum(S.PROFILES["standard"].values()), 10), 1.0)
    ck.eq("sig-only 只有 package-integrity 计权", S.PROFILES["sig-only"]["package-integrity"], 1.0)
    ck.eq("runtime 只有 rt+inj 各 0.5",
          (S.PROFILES["runtime"]["runtime-integrity"], S.PROFILES["runtime"]["injection"],
           S.PROFILES["runtime"]["privilege"]), (0.5, 0.5, 0.0))
    try:
        S.profile_weights("nope")
        ck.check("未知 profile 必须报错", False)
    except S.ScoreError:
        ck.check("未知 profile 必须报错", True)

    # ---------------- 2. zip 指纹（契约 §4.4）----------------
    ck.head("2. Zip 指纹算法（契约 §4.4，与 Java 逐字节一致）")
    import zipfile

    with scratch_dir("zip-") as td:
        zp = Path(td) / "t.zip"
        with zipfile.ZipFile(zp, "w", zipfile.ZIP_STORED) as zf:
            zi = zipfile.ZipInfo("f.txt", date_time=(2020, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_STORED
            zf.writestr(zi, b"abc")
        ck.eq("zlib.crc32(b'abc') == 0x352441c2（独立于本实现）", zlib.crc32(b"abc"), 0x352441C2)
        expect_line = "f.txt|352441c2|3|3|0\n"
        import hashlib

        ck.eq("zip_fingerprint 与契约行格式一致",
              S.zip_fingerprint(zp), hashlib.sha256(expect_line.encode("utf-8")).hexdigest())

    # ---------------- 3. fixture A：混合计分 ----------------
    ck.head("3. fixture A —— 包未改 + frida 痕迹 + UNKNOWN/ERROR 不进分母")
    rep_a, exp_a = fixture_a()
    an_a = S.analyze(rep_a, exp_a, profile="standard")
    ck.eq("向量总数 = 11 应用 + 2 CLI", an_a["summary"]["total"], 13)
    ck.eq("CLI 平面信号恰好 2 条", len(an_a["cliSignals"]), 2)
    ck.check("CLI 信号 plane=cli / tier=A / weight=5 / category=package-integrity",
             all(s["plane"] == "cli" and s["tier"] == "A" and s["weight"] == 5
                 and s["category"] == "package-integrity" for s in an_a["cliSignals"]))
    ck.check("hash 与 zip 两条 CLI 信号都判 CLEAN（facts 与 expect 一致）",
             [s["verdict"] for s in an_a["cliSignals"]] == [S.CLEAN, S.CLEAN])
    cats_a = {c["id"]: c for c in an_a["summary"]["categories"]}
    ck.close("runtime-integrity = 42.9", cats_a["runtime-integrity"]["score"], 42.9)
    ck.close("injection = 50.0", cats_a["injection"]["score"], 50.0)
    ck.close("package-integrity = 100.0", cats_a["package-integrity"]["score"], 100.0)
    ck.close("privilege = 100.0（UNKNOWN 不计入分母）", cats_a["privilege"]["score"], 100.0)
    ck.eq("privilege 的 UNKNOWN 计数 = 1", cats_a["privilege"]["unknown"], 1)
    ck.eq("environment 无可用分母 → counted=False, score=None",
          (cats_a["environment"]["counted"], cats_a["environment"]["score"]), (False, None))
    ck.close("raw = 72.5（手算：65.2857142857/0.90）", an_a["summary"]["score"], 72.5)
    ck.close("raw 全精度 = 72.5396825397", an_a["summary"]["raw"], 72.53968253968254, 1e-6)
    ck.eq("包未被改动 → packageModified=false", an_a["packageModified"]["modified"], False)
    ck.eq("包未改 → 盲区为空", an_a["blindSpots"], [])
    ck.eq("无 baseline → 误报为空", an_a["falsePositives"], [])
    ck.eq("验证器对 fixture A 无告警（fixture 本身合规）", S.validate_report(rep_a), [])

    # profile 变体
    an_sig = S.analyze(rep_a, exp_a, profile="sig-only")
    ck.close("sig-only：raw = package-integrity = 100.0", an_sig["summary"]["score"], 100.0)
    an_rt = S.analyze(rep_a, exp_a, profile="runtime")
    ck.close("runtime profile：raw = (42.857142+50)/2 = 46.4", an_rt["summary"]["score"], 46.4)

    # ---------------- 4. fixture B：盲区 ----------------
    ck.head("4. fixture B —— 包被改 + 多类满分 → 盲区判定")
    rep_b, exp_b = fixture_b()
    an_b = S.analyze(rep_b, exp_b)
    vb = {s["id"]: s["verdict"] for s in an_b["cliSignals"]}
    ck.eq("pkg.codepath.hash = TAMPERED（APK 哈希不符）", vb.get("pkg.codepath.hash"), S.TAMPERED)
    ck.eq("pkg.zip.fingerprint = CLEAN（ZipEntry 未被改）", vb.get("pkg.zip.fingerprint"), S.CLEAN)
    ck.eq("packageModified.modified = true", an_b["packageModified"]["modified"], True)
    ck.eq("盲区触发原因 = cli-expect-mismatch",
          sorted({r["why"] for r in an_b["packageModified"]["reasons"]}), ["cli-expect-mismatch"])
    bs = {b["category"]: b for b in an_b["blindSpots"]}
    ck.eq("盲区类别数 = 5", len(an_b["blindSpots"]), 5)
    ck.eq("盲区集合 = rt/inj/priv/virt/env（pkg 因 66.7 不算）",
          sorted(bs), ["environment", "injection", "privilege", "runtime-integrity", "virtualization"])
    ck.check("盲区文案含「包已改动，但 … 一条都没抓到」",
             bs["privilege"]["text"].startswith("包已改动，但") and "一条都没抓到" in bs["privilege"]["text"])
    ck.check("盲区里列出了该类别 CLEAN 的向量 id",
             set(bs["privilege"]["vectors"]) == {"priv.su", "priv.mounts"})
    ck.close("package-integrity = 66.7（100·(1-5/15)）",
             {c["id"]: c for c in an_b["summary"]["categories"]}["package-integrity"]["score"], 66.7)
    ck.close("raw = 93.3", an_b["summary"]["score"], 93.3)
    ck.check("CLI 权威性：App 自算 100.0 > CLI 93.3（App 看不见自己的哈希）",
             float(rep_b["summary"]["score"]) == 100.0 and float(an_b["summary"]["score"]) < 100.0)

    # ---------------- 5. fixture C：误报 + 基线归一 ----------------
    ck.head("5. fixture C —— 基线误报 + 基线归一")
    rep_c, base_c, exp_c = fixture_c()
    an_c = S.analyze(rep_c, exp_c, baseline_report=base_c)
    ck.close("raw = 91.2（含 CLI 的 pkg=100）", an_c["summary"]["score"], 91.2)
    ck.eq("包未被改动", an_c["packageModified"]["modified"], False)
    ck.eq("误报条数 = 1", len(an_c["falsePositives"]), 1)
    ck.eq("误报向量 = priv.mounts（基线 TAMPERED 且本轮仍 TAMPERED）",
          [f["vector"] for f in an_c["falsePositives"]], ["priv.mounts"])
    ck.eq("rt.tracerpid 基线 TAMPERED 但本轮 CLEAN → 不算误报",
          "rt.tracerpid" in an_c["noiseFromBaseline"], False)
    ck.eq("noiseFromBaseline = ['priv.mounts']", an_c["noiseFromBaseline"], ["priv.mounts"])
    ck.close("基线归一 adj = 100.0（本次污染 < 基线污染，无新增扣分）", an_c["litmus"], 100.0)
    ck.close("baseline.raw = 37.5", (an_c["baseline"] or {}).get("raw"), 37.5)
    ck.close("反例：raw=72.5396825 对 baseline=80 → 90.7",
             S.adjust_with_baseline(72.53968253968254, 80.0), 90.7)

    # 包被改时不许叫误报
    an_bc = S.analyze(rep_c, exp_c, baseline_report=base_c)
    rep_bad = json.loads(json.dumps(rep_c))
    rep_bad["facts"]["apk.sha256"] = "0" * 64
    an_bad = S.analyze(rep_bad, exp_c, baseline_report=base_c)
    ck.eq("包被改后同一条不再算误报", an_bad["falsePositives"], [])
    ck.eq("（对照）包未改时算误报", len(an_bc["falsePositives"]), 1)

    # ---------------- 6. CLI 平面信号缺失的场景 ----------------
    ck.head("6. 缺数据必须判 UNKNOWN（不能当 CLEAN 放过）")
    rep_missing = json.loads(json.dumps(rep_a))
    rep_missing["facts"].pop("apk.sha256")
    an_missing = S.analyze(rep_missing, exp_a)
    v = {s["id"]: s["verdict"] for s in an_missing["cliSignals"]}
    ck.eq("facts 缺 apk.sha256 → pkg.codepath.hash = UNKNOWN", v.get("pkg.codepath.hash"), S.UNKNOWN)
    ck.eq("缺 expect 的 zipFingerprint → UNKNOWN",
          {s["id"]: s["verdict"] for s in S.analyze(rep_a, {})["cliSignals"]}["pkg.zip.fingerprint"], S.UNKNOWN)
    ck.eq("UNKNOWN 不计分母，因此不改变 raw", an_missing["summary"]["score"], 72.5)

    # ---------------- 7. 契约校验能抓错 ----------------
    ck.head("7. 契约校验（validate_report）")
    bad = json.loads(json.dumps(rep_a))
    bad["schema"] = "litmus.report/0"
    bad["signals"][0]["category"] = "bogus-category"
    bad["signals"][1]["verdict"] = "MAYBE"
    probs = S.validate_report(bad)
    ck.check("抓到 schema 不符", any("schema" in p for p in probs), str(probs))
    ck.check("抓到非法 category", any("不在六类" in p for p in probs), str(probs))
    ck.check("抓到非法 verdict", any("verdict" in p for p in probs), str(probs))
    bad2 = json.loads(json.dumps(rep_a))
    bad2["signals"].append(dict(bad2["signals"][0]))
    ck.check("抓到重复 id", any("重复" in p for p in S.validate_report(bad2)))

    # 向量目录交叉校验（schema/vectors.json = 契约 §3 的可机读投影）
    cat = S.load_catalog()
    ck.check("向量目录可加载（schema/vectors.json，≥38 条）", cat is not None and len(cat) >= 38,
             "catalog=%r" % (None if cat is None else len(cat)))
    ck.eq("fixture A 的信号全部能在目录里对上", S.catalog_problems(rep_a["signals"], cat), [])
    ck.check("C 级向量判 TAMPERED 会被拦下（契约 §2.2）",
             any("C 级" in p for p in S.catalog_problems(
                 [_sig("env.proxy", "environment", S.TAMPERED, 0.5, 3, "C", "x")], cat)))
    ck.check("目录外的新 id 会被提示先登记",
             any("不在" in p for p in S.catalog_problems(
                 [_sig("rt.brand.new", "runtime-integrity", S.CLEAN, 0.9, 3, "A", "x")], cat)))
    cov = S.catalog_coverage(rep_b["signals"], cat)
    ck.check("覆盖率统计正确（fixture B 只上报 9 条，缺 31 条）",
             cov["declared"] == len(cat) and cov["present"] == 9 and len(cov["missing"]) == len(cat) - 9,
             str({k: (v if k != "missing" else len(v)) for k, v in cov.items()}))

    # ---------------- 8. logcat 协议解析（契约 §4.3）----------------
    ck.head("8. logcat 协议解析（单行 / CHUNK 分片 / PATH）")
    small = {"schema": S.SCHEMA_REPORT, "signals": []}
    line_small = "I/LitmusReport( 1234): " + P_SINGLE + json.dumps(small)
    got, how, _p = parse_logcat(line_small)
    ck.eq("单行 LITMUS_REPORT 可解析", got, small)
    ck.eq("来源标注 logcat:single", how, "logcat:single")

    big = _envelope([_sig("rt.tracerpid", "runtime-integrity", S.CLEAN, 0.9, 4, "A", "x" * 200)],
                    {"total": 1, "score": 100.0}, {"apk.sha256": _F64}, run_id="big")
    raw = json.dumps(big, ensure_ascii=False).encode("utf-8")
    b64 = base64.b64encode(raw).decode("ascii")
    chunk = 500
    total = (len(b64) + chunk - 1) // chunk
    lines = ["I/LitmusReport( 1234): " + P_CHUNK + "%d/%d %s" % (i + 1, total, b64[i * chunk:(i + 1) * chunk])
             for i in range(total)]
    lines.insert(2, "I/LitmusReport( 1234): " + P_PATH + REMOTE_DIR + "/report-big.json")
    got2, how2, path2 = parse_logcat("\n".join(lines))
    ck.eq("CHUNK 分片可拼回完整 JSON", got2, big)
    ck.eq("CHUNK 组数标记正确", how2, "logcat:chunk(%d)" % total)
    ck.eq("LITMUS_REPORT_PATH 可解析", path2, REMOTE_DIR + "/report-big.json")
    # 分片乱序也要能拼
    shuffled = lines[:2] + list(reversed(lines[2:]))
    got3, _h3, _p3 = parse_logcat("\n".join(shuffled))
    ck.eq("CHUNK 乱序仍可拼回", got3, big)
    # 缺片必须失败（不能拼出半个 JSON 当成功）
    got4, _h4, _p4 = parse_logcat("\n".join(lines[:-1]))
    ck.eq("CHUNK 缺片 → 不返回半成品", got4, None)
    # 两轮运行的分片不能互相污染
    lines_twice = lines + [l.replace("%d/%d" % (1, total), "1/%d" % total) for l in lines[:1]] + lines[1:]
    got5, _h5, _p5 = parse_logcat("\n".join(lines_twice))
    ck.check("两轮 CHUNK 叠加时取最后完整的一轮", got5 is not None)

    # ---------------- 9. 报告渲染（md / html 单文件无外链）----------------
    ck.head("9. 报告渲染（report.md / report.html 单文件自包含）")
    with scratch_dir("render-") as td:
        out_dir = Path(td) / "runs" / "T-blind"
        run_json = assemble_run_json(
            report=rep_b, expect=exp_b, expect_path=Path("canary/out/build-info.json"),
            analysis=an_b, label="T-blind", framework="frida", serial="emulator-5554",
            started_at="2026-11-10T08:00:00Z", finished_at="2026-11-10T08:00:03Z",
            mode="fixture", report_source="fixture", baseline_path=None,
            app_run_id=rep_b["run"]["id"],
        )
        paths = write_run_bundle(out_dir, rep_b, run_json, docs=load_docs())
        ck.check("四件套都写出来了",
                 all(Path(p).is_file() and Path(p).stat().st_size > 0 for p in paths.values()),
                 str({k: rel(v) for k, v in paths.items()}))
        html_text = Path(paths["html"]).read_text(encoding="utf-8")
        md_text = Path(paths["md"]).read_text(encoding="utf-8")
        ck.check("html 以 <!doctype html> 开头", html_text.lstrip().lower().startswith("<!doctype html>"))
        ck.check("html 无外部依赖（无 http/https 链接、无 cdn、无 <script src>）",
                 ("http://" not in html_text and "https://" not in html_text
                  and "cdn" not in html_text.lower() and "<script" not in html_text.lower()))
        ck.check("html 内联了 CSS（Material 3 token）",
                 "<style>" in html_text and "--surface:#141218" in html_text)
        ck.check("html 含 label、profile、设备、分数",
                 all(k in html_text for k in ("T-blind", "standard", "emulator-5554"))
                 and ("93.3" in html_text), """""")
        ck.check("html 有两个高亮区块（⑥ 盲区 / ⑦ 环境噪声）",
                 "⑥ 我们看不见的地方" in html_text and "⑦ 环境噪声" in html_text)
        ck.check("html 里 5 个盲区都渲染出来了", html_text.count('class="flag blind"') >= 5)
        ck.check("html 中文未转义成 \\uXXXX", "包已改动" in html_text)
        ck.check("md 含九段结构与向量表", "## ④ 逐类判断" in md_text and "## ⑥ 我们看不见的地方" in md_text
                 and "| id |" in md_text)
        ck.check("md 的向量表包含 pkg.codepath.hash", "pkg.codepath.hash" in md_text)
        rj = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        ck.eq("run.json schema = litmus.run/1", rj["schema"], S.SCHEMA_RUN)
        ck.close("run.json 的 score.litmus 落盘正确", rj["score"]["litmus"], 93.3)
        ck.eq("run.json 的 run.device.serial 落盘正确", rj["run"]["device"]["serial"], "emulator-5554")
        ck.check("run.json 的 appSummaryCheck 抓到了 App/CLI 分差",
                 rj["appSummaryCheck"]["checked"] and rj["appSummaryCheck"]["match"] is True)
        ck.check("run.json 带上了目录覆盖率", (rj.get("coverage") or {}).get("declared", 0) >= 38)

        # ---------------- 10. matrix ----------------
        ck.head("10. matrix 跨运行对比")
        entries = []
        for label, a_x in (("T-clean", an_a), ("T-blind", an_b)):
            rep_x, exp_x = (rep_a, exp_a) if a_x is an_a else (rep_b, exp_b)
            rjx = assemble_run_json(
                report=rep_x, expect=exp_x, expect_path=None, analysis=a_x, label=label,
                framework="-", serial="s", started_at="2026-11-10T08:00:00Z",
                finished_at="2026-11-10T08:00:01Z", mode="fixture", report_source="fixture",
            )
            entries.append({"label": label, "path": str(out_dir / label), "run_json": rjx})
        mx = R.matrix_markdown(entries, title="selftest")
        ck.check("matrix 里有总分表与类别分表", "## 总分" in mx and "## 类别分" in mx)
        ck.check("matrix 列名是 label", "T-clean" in mx and "T-blind" in mx)
        ck.check("matrix 标出了「所有运行都 CLEAN」的向量",
                 "所有运行都 CLEAN" in mx and "全程 CLEAN" in mx)
        ck.check("matrix 标出了被抓到的篡改（TAMP）", "TAMP" in mx)

    # ---------------- 11. 命令层 smoke ----------------
    ck.head("11. 命令层 smoke（不碰设备）")
    ck.check("doctor 在无 adb 参数下能给出结论（异常被兜住）",
             _doctor_smoke_ok(), "doctor 抛出未捕获异常")
    ck.check("init_stdio 幂等", _init_smoke_ok())

    # ---------------- 12. 基线口径 + CLI 端到端 ----------------
    ck.head("12. 基线两种形态口径一致 + CLI 端到端（真文件、不碰设备）")
    rep_c2, base_c2, exp_c2 = fixture_c()
    with scratch_dir("cli-") as td:
        td = Path(td)
        bi = {
            "schema": S.SCHEMA_BUILD,
            "apk": "canary/out/litmus-canary-0.1.0.apk",
            "apkSha256": exp_c2["apkSha256"],
            "certSha256": exp_c2["certSha256"],
            "zipFingerprint": exp_c2["zipFingerprint"],
            "version": "0.1.0",
            "flavor": "release",
            "builtAt": "2026-11-10T08:00:00Z",
        }
        bi_path = write_json(td / "build-info.json", bi)
        cur_path = write_json(td / "report.raw.json", rep_c2)
        base_raw_path = write_json(td / "baseline.raw.json", base_c2)

        # 基线是 App 原始报告时，必须补上 CLI 平面信号再算 Pb，否则基线污染度偏小
        _br, bsum, _bp = load_baseline(base_raw_path, exp_c2, "standard")
        ck.close("基线（raw 报告）补 CLI 平面后 raw = 55.9", bsum["raw"], 55.88235294117648, 1e-6)
        ck.check("（对照）若漏掉 CLI 平面会算成 37.5，两者不同",
                 abs(float(bsum["raw"]) - 37.5) > 1.0)

        argv = ["score", "--report", str(cur_path), "--expect", str(bi_path),
                "--baseline", str(base_raw_path), "--json", "--label", "T-cli"]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(argv)
        ck.eq("score 子命令退出码 0", rc, 0)
        out = json.loads(buf.getvalue())
        ck.eq("score --json 输出合法 run.json", out["schema"], S.SCHEMA_RUN)
        ck.close("score 端到端 litmus = 100.0（基线归一生效）", out["score"]["litmus"], 100.0)
        ck.close("score 端到端 raw = 91.2", out["score"]["raw"], 91.2)
        ck.eq("--label 覆盖生效", out["run"]["label"], "T-cli")
        ck.eq("误报在端到端路径上也识别出 priv.mounts",
              [f["vector"] for f in out["falsePositives"]], ["priv.mounts"])

        save_dir = td / "runs" / "T-cli"
        with contextlib.redirect_stdout(io.StringIO()):
            main(["score", "--report", str(cur_path), "--expect", str(bi_path), "--save", str(save_dir)])
        ck.check("score --save 写出四件套",
                 all((save_dir / n).is_file() for n in
                     ("report.raw.json", "run.json", "report.md", "report.html")))

        # 基线是 run.json 时直接吃 rawExact（不能重算，重算会把 CLI 平面再叠一次）
        saved = json.loads((save_dir / "run.json").read_text(encoding="utf-8"))
        _br2, bsum2, _bp2 = load_baseline(save_dir / "run.json", exp_c2, "standard")
        ck.close("run.json 形态的基线直接用 rawExact", bsum2["raw"], saved["score"]["rawExact"], 1e-6)

        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            rc2 = main(["matrix", "--runs", str(td / "runs")])
        ck.eq("matrix 子命令退出码 0", rc2, 0)
        ck.check("matrix 写出 matrix.md", (td / "runs" / "matrix.md").is_file())
        ck.check("matrix 控制台点名了「所有运行都 CLEAN」", "所有运行都 CLEAN" in buf2.getvalue())

        # 未提供 --baseline 时行尾不能出现伪「误报 0 条」
        buf3 = io.StringIO()
        with contextlib.redirect_stdout(buf3):
            main(["score", "--report", str(cur_path), "--expect", str(bi_path)])
        ck.check("无 --baseline 时不显示误报结论", "误报 0 条" not in buf3.getvalue())

    # ---------------- 13. 报告文风（docs/07 §7–§8 的 R1–R8）----------------
    ck.head("13. 报告文风（九段结构 + R1–R8 硬指标）")
    rep_n, exp_n = fixture_b()          # 包被改 + 2 类盲区，正好覆盖 ①⑤⑥
    an_n = S.analyze(rep_n, exp_n)
    docs = load_docs()
    with scratch_dir("narrative-") as td:
        td = Path(td)
        out_dir = td / "runs" / "T-narrative"
        rjn = assemble_run_json(
            report=rep_n, expect=exp_n, expect_path=Path("canary/out/build-info.json"),
            analysis=an_n, label="T-narrative", framework="repack", serial="emulator-5554",
            started_at="2026-11-10T08:00:00Z", finished_at="2026-11-10T08:00:03Z",
            mode="fixture", report_source="fixture", baseline_path=None,
            app_run_id=rep_n["run"]["id"],
        )
        paths = write_run_bundle(out_dir, rep_n, rjn, docs=docs)
        md = Path(paths["md"]).read_text(encoding="utf-8")
        html_text = Path(paths["html"]).read_text(encoding="utf-8")

        # R1：结论先行，且就是一句话结论（3 行内）
        concl = N.conclusion(rjn, docs)
        ck.eq("R1 结论正好 3 行", len(concl.split("\n")), 3)
        ck.check("R1 结论说清「被改过」", "被改过" in concl, concl[:80])
        ck.check("R1 结论点名失守类别", "包完整性" in concl, concl[:120])
        ck.check("R1 结论点名失明类别（盲区）", "虚拟化" in concl and "⑥" in concl, concl[:160])
        ck.check("R1 md 前 12 行内出现「① 一句话结论」（不是先甩表格）",
                 md.splitlines()[:12] and any("①" in ln for ln in md.splitlines()[:12]),
                 str(md.splitlines()[:6]))

        # 干净包要能给出相反的结论（不能只会说「被改过」）
        rep_clean, exp_clean = fixture_a()
        an_clean = S.analyze(rep_clean, exp_clean)
        rjc = assemble_run_json(
            report=rep_clean, expect=exp_clean, expect_path=None, analysis=an_clean,
            label="T-clean", framework="-", serial="s", started_at="2026-11-10T08:00:00Z",
            finished_at="2026-11-10T08:00:01Z", mode="fixture", report_source="fixture",
        )
        ck.check("R1 干净包的结论是「没被改」", "没被改" in N.conclusion(rjc, docs))
        # 全干净的报告要能走「⑤ 空段」的分支（I8：空态也要有一句人话，不能是空白）
        clean_sigs = [dict(x, verdict="CLEAN") for x in rep_clean["signals"]]
        rep_all_clean = dict(rep_clean, signals=clean_sigs)
        an_all = S.analyze(rep_all_clean, exp_clean)
        rj_all = assemble_run_json(
            report=rep_all_clean, expect=exp_clean, expect_path=None, analysis=an_all,
            label="T-all-clean", framework="-", serial="s", started_at="2026-11-10T08:00:00Z",
            finished_at="2026-11-10T08:00:01Z", mode="fixture", report_source="fixture",
        )
        md_all = R.to_markdown(rj_all, docs=docs, paths=paths)
        ck.check("⑤ 全干净时有空态人话（不是一片空白）",
                 "没有一条被坐实" in md_all, md_all[md_all.find("⑤"):][:80])
        ck.check("⑥ 包没被改时说明「盲区判定不适用」而不是报 0 个洞",
                 "盲区判定不适用" in md_all)

        # R2：每个数字都带解释 —— 每类都给 2–6 句，且含计数与关键向量
        def sentences(t):
            return [s for s in t.replace("！", "。").replace("？", "。").split("。") if s.strip()]

        stories_ok = True
        for c in an_n["summary"]["categories"]:
            st = N.category_story(c, an_n["signals"], an_n["litmus"], run=rjn, docs=docs)
            n = len(sentences(st))
            if not (2 <= n <= 6):
                stories_ok = False
                print("     句数异常 %s = %d" % (c["id"], n))
        ck.check("R2 六类各 2–6 句人话", stories_ok)
        pkg_story = N.category_story(
            [c for c in an_n["summary"]["categories"] if c["id"] == "package-integrity"][0],
            an_n["signals"], an_n["litmus"], run=rjn, docs=docs)
        ck.check("R2 分数后面紧跟一句解释（含「可判定 N 条里…」）",
                 "可判定" in pkg_story and "条干净" in pkg_story, pkg_story[:120])
        pkg_red_ids = [x["id"] for x in an_n["signals"]
                       if x["category"] == "package-integrity" and x["verdict"] == "TAMPERED"]
        ck.check("R4 关键向量给了解释（点名某条红叉 + 置信度）",
                 bool(pkg_red_ids) and any(i in pkg_story for i in pkg_red_ids) and "置信度" in pkg_story,
                 pkg_story[:160])

        # R3：不出现裸结论词（md 与 html 都查）
        ck.eq("R3 md 无裸 TAMPERED/CLEAN 等（只允许「中文（VERDICT）」形式）",
              bare_verdicts(md), [])
        ck.eq("R3 html 无裸结论词", bare_verdicts(strip_tags(html_text)), [])
        ck.check("R3 术语表存在（干净（CLEAN）… 被坐实（TAMPERED）…）",
                 "术语：" in md and "被坐实（TAMPERED）" in md)

        # R5：盲区必须给「为什么」+「怎么验证」
        ck.check("R5 盲区段有「为什么可能是洞」", "为什么可能是洞" in md)
        ck.check("R5 盲区段有「怎么验证是不是洞」且给出 ≥2 个具体步骤",
                 "怎么验证是不是洞" in md and md.count("）换") + md.count("）造") +
                 md.count("）补") + md.count("）把") + md.count("）手工") + md.count("）检查") +
                 md.count("）先") + md.count("）用") + md.count("）给它") >= 2, "")

        # R6 + R8：行动清单每条带预估收益，且标注估算 / 待实测
        actions = N.action_list(rjn, docs)
        ck.check("R6 行动清单非空", len(actions) > 0, "actions=%d" % len(actions))
        ck.check("R6 每条都有预计收益且标「估算」",
                 all("估算" in N.gain_label(a) for a in actions),
                 str([N.gain_label(a) for a in actions[:3]]))
        ck.check("R6 每条都写了成本", all(a.get("cost") for a in actions))
        ck.check("R8 没有编造的精确收益（每条都带「估算」或「待实测」）",
                 all(("估算" in N.gain_label(a)) or ("待实测" in N.gain_label(a)) for a in actions))
        ck.check("⑧ 章节里有「预计 +」字样", "预计 +" in md)

        # 收益折算的自洽性：把每类都补到 100 的收益之和 == 100 - raw
        cats_n = [c for c in an_n["summary"]["categories"] if c["score"] is not None]
        denom = sum(float(c["weight"]) for c in cats_n)
        total_gain = sum(N._category_gain(c, denom) for c in cats_n)
        ck.close("收益折算自洽（各类收益之和 = 100 - raw）",
                 total_gain, 100.0 - float(an_n["summary"]["raw"]), 0.05)

        # 九段结构：md 与 html 的标题必须完全一致，且顺序就是规范 §7 的 ①②③…
        expected_titles = [t for _k, t in R.SECTION_TITLES]
        ck.eq("九段标题 = 规范 §7 的 ①..⑨", expected_titles,
              ["① 一句话结论", "② 三个数字", "③ 这次改了什么", "④ 逐类判断",
               "⑤ 被坐实的问题", "⑥ 我们看不见的地方", "⑦ 环境噪声",
               "⑧ 怎么让分数上去", "⑨ 附录"])
        ck.eq("md 的九段标题与顺序完全正确", md_section_titles(md), expected_titles)
        ck.eq("html 的九段标题与 md 完全一致（顺序也一样）",
              html_section_titles(html_text), md_section_titles(md))

        # html 仍必须是单文件自包含
        ck.check("html 仍是单文件自包含（无 http/https/script/cdn/@import/box-shadow）",
                 not any(k in html_text.lower()
                         for k in ("http://", "https://", "<script", "cdn.", "@import", "box-shadow")))
        ck.check("html 沿用 M3 token（--surface:#141218 等）",
                 "--surface:#141218" in html_text and "--clean:#B6F09C" in html_text)

        # ⑨ 附录：完整向量表 + 可复现命令
        table_rows = sum(1 for ln in md.splitlines()
                         if ln.startswith("| `") and "package-integrity" in ln or ln.startswith("| `rt.")
                         or ln.startswith("| `inj.") or ln.startswith("| `priv.")
                         or ln.startswith("| `virt.") or ln.startswith("| `env.")
                         or ln.startswith("| `pkg."))
        ck.check("⑨ 附录的完整向量表覆盖全部 signal", table_rows >= len(an_n["signals"]),
                 "rows=%d signals=%d" % (table_rows, len(an_n["signals"])))
        ck.check("⑨ 附录给了可直接执行的复现命令",
                 "python cli\\litmus.py score --report" in md and "--expect" in md)
        ck.check("⑨ 附录写了原始 JSON 路径", "run.json" in md and "report.raw.json" in md)

        # §10：终端也要先给结论/建议，且在表格上方
        term = R.to_terminal(rjn, color=False, docs=docs)
        ck.check("§10 终端有「结论：」与「建议：」", "结论：" in term and "建议：" in term)
        ck.check("§10 结论/建议出现在类别表上方",
                 term.find("结论：") < term.find("类别") and term.find("建议：") < term.find("类别"),
                 "concl=%d advice=%d table=%d" % (term.find("结论："), term.find("建议："), term.find("类别")))
        ck.check("§10 终端不再直接甩内部枚举（包状态用人话）",
                 "cli-expect-mismatch" not in term, term[term.find("包状态"):term.find("包状态") + 60])

    return 0 if ck.done() else 2


def _doctor_smoke_ok() -> bool:
    """doctor 在「没有设备」的机器上也必须能跑完（只是多几行 ✗），不能崩。"""
    try:
        _ = collect_doctor_items(serial=None, adb_arg="__nonexistent__", expect_path=None, apk_path=None)
        return True
    except CliError:
        return True
    except Exception:
        traceback.print_exc()
        return False


def _init_smoke_ok() -> bool:
    try:
        init_stdio()
        init_stdio()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


class DoctorItem:
    def __init__(self, name: str):
        self.name = name
        self.ok = None          # True/False/None(=warn)
        self.detail = ""
        self.hints = []

    def good(self, detail=""):
        self.ok = True
        self.detail = detail
        return self

    def bad(self, detail="", *hints):
        self.ok = False
        self.detail = detail
        self.hints.extend(hints)
        return self

    def warn(self, detail="", *hints):
        self.ok = None
        self.detail = detail
        self.hints.extend(hints)
        return self


def collect_doctor_items(serial=None, adb_arg=None, expect_path=None, apk_path=None) -> list:
    items = []

    # 1. Python
    it = DoctorItem("Python 运行时")
    ver = sys.version_info
    if ver >= (3, 10):
        it.good("%d.%d.%d" % ver[:3])
    else:
        it.bad("%d.%d.%d（需要 ≥ 3.10）" % ver[:3], "升级 Python 到 3.10+")
    items.append(it)

    # 2. 标准库依赖
    it = DoctorItem("依赖检查（只用标准库）")
    missing = []
    for mod in ("json", "zipfile", "hashlib", "subprocess", "argparse", "base64"):
        try:
            __import__(mod)
        except Exception:
            missing.append(mod)
    if missing:
        it.bad("缺 " + ", ".join(missing), "标准库缺失说明 Python 安装不完整，重装 Python")
    else:
        it.good("json/zipfile/hashlib/subprocess/argparse 齐全")
    items.append(it)

    # 3. adb
    it = DoctorItem("adb 可执行文件")
    adb = None
    try:
        adb = Adb(serial=serial, adb_path=adb_arg)
        it.good(adb.adb)
    except CliError as e:
        it.bad("未找到", str(e))
    items.append(it)

    # 4. 设备
    it = DoctorItem("adb 设备")
    if adb is None:
        it.warn("跳过（没有 adb）", "先解决上一条")
    else:
        try:
            devs = adb.devices()
            online = [s for s, st in devs if st == "device"]
            if not devs:
                it.bad("一台设备都没有", "启动模拟器（MuMu / AVD）或插上手机并打开 USB 调试",
                       "adb kill-server 然后 adb devices 复查")
            elif not online:
                it.bad("设备状态异常：%s" % ", ".join("%s(%s)" % d for d in devs),
                       "unauthorized → 手机上点「允许 USB 调试」", "offline → 重插线 / adb reconnect")
            else:
                detail = "、".join("%s(%s)" % (s, st) for s, st in devs)
                if serial and serial not in online:
                    it.bad("指定了 --serial %s，但它在不在线列表里（%s）" % (serial, detail), "换 --serial 或不指定（自动选第一台）")
                else:
                    it.good(detail)
                    adb.serial = serial or online[0]
        except CliError as e:
            it.bad("查询失败", str(e))
    items.append(it)

    # 5. 靶包是否安装
    it = DoctorItem("靶包安装状态（%s）" % PKG)
    if adb is None or not adb.serial:
        it.warn("跳过（没有可用设备）")
    else:
        try:
            out = adb.shell("pm", "list", "packages", PKG, timeout=20)
            if "package:%s" % PKG in out:
                it.good("已安装")
            else:
                it.warn("未安装", "litmus.py run 会自动 adb install -r；也可手动安装 %s" % (apk_path or "canary/out/*.apk"))
        except CliError as e:
            it.warn("查询失败", str(e))
    items.append(it)

    # 6. build-info.json
    it = DoctorItem("build-info.json")
    expect = None
    p = rp(expect_path) if expect_path else default_build_info()
    if not p.is_file():
        it.bad("不存在：%s" % rel(p), "在仓库根跑 powershell -ExecutionPolicy Bypass -File canary/build.ps1",
               "或换机器时用 --expect <path> 指定一份构建产物清单")
    else:
        try:
            expect = read_json(p)
            schema = expect.get("schema")
            lack = [k for k in ("apkSha256", "zipFingerprint") if not expect.get(k)]
            if schema != S.SCHEMA_BUILD:
                it.warn("schema=%r（期望 %r）" % (schema, S.SCHEMA_BUILD), "重跑 canary/build.ps1 生成新格式")
            elif lack:
                it.bad("缺关键字段：%s" % ", ".join(lack), "重跑 canary/build.ps1")
            else:
                it.good("v%s / %s / zip=%s" % (expect.get("version"), expect.get("flavor"), (expect.get("zipFingerprint") or "")[:12] + "…"))
        except CliError as e:
            it.bad("读取失败", str(e))
    items.append(it)

    # 7. APK 文件 + 自洽性（用 CLI 自己重算哈希/指纹反查构建脚本）
    it = DoctorItem("靶包 APK")
    apk = rp(apk_path) if apk_path else None
    if apk is None and expect:
        cand = expect.get("apk")
        if cand:
            apk = rp(cand)
    if apk is None:
        apk = rp("canary/out/litmus-canary-0.1.0.apk")
    if not apk.is_file():
        it.bad("不存在：%s" % rel(apk), "跑 canary/build.ps1 产出 APK", "或用 --apk 指定一个已构建的 APK")
    elif expect is None:
        it.good("%s（无 build-info 可对账）" % rel(apk))
    else:
        try:
            sha = S.file_sha256(apk)
            zf = S.zip_fingerprint(apk)
            bad = []
            if expect.get("apkSha256") and sha.lower() != str(expect["apkSha256"]).lower():
                bad.append("apkSha256 不符（build-info=%s… / 实测=%s…）" % (str(expect["apkSha256"])[:12], sha[:12]))
            if expect.get("zipFingerprint") and zf.lower() != str(expect["zipFingerprint"]).lower():
                bad.append("zipFingerprint 不符（build-info=%s… / 实测=%s…）" % (str(expect["zipFingerprint"])[:12], zf[:12]))
            if bad:
                it.bad("build-info 与 APK 不自洽", *bad,
                       "说明构建脚本算指纹的口径与契约 §4.4 不一致，或 APK 被替换过")
            else:
                it.good("%s · sha256=%s… · zip=%s… 与 build-info 自洽" % (rel(apk), sha[:12], zf[:12]))
        except Exception as e:
            it.bad("计算失败：%s" % e, "APK 可能是下载中断的残包，重新构建")
    items.append(it)

    # 8. schema 目录
    it = DoctorItem("schema/ 契约文件")
    need = ["app-report.schema.json", "run.schema.json", "vectors.json"]
    miss = []
    broken = []
    for name in need:
        sp = REPO_ROOT / "schema" / name
        if not sp.is_file():
            miss.append(name)
            continue
        try:
            json.loads(sp.read_text(encoding="utf-8"))
        except Exception as e:
            broken.append("%s(%s)" % (name, e))
    if miss or broken:
        it.bad("缺 %s%s" % (", ".join(miss) or "-", ("；损坏 " + ", ".join(broken)) if broken else ""),
               "schema/ 是契约的一部分，请随代码一起提交")
    else:
        it.good("app-report.schema.json / run.schema.json / vectors.json 就位")
    items.append(it)

    # 9. 运行目录可写
    it = DoctorItem("runs/ 可写")
    try:
        d = REPO_ROOT / "runs"
        d.mkdir(parents=True, exist_ok=True)
        probe = d / ".doctor-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        existing = len(list(d.glob("*")))
        it.good("%s（已有 %d 项）" % (rel(d), existing))
    except Exception as e:
        it.bad("不可写：%s" % e, "检查目录权限 / 是否在只读介质上")
    items.append(it)

    return items


def cmd_doctor(args) -> int:
    items = collect_doctor_items(
        serial=getattr(args, "serial", None),
        adb_arg=getattr(args, "adb", None),
        expect_path=getattr(args, "expect", None),
        apk_path=getattr(args, "apk", None),
    )
    color = use_color()
    print("")
    print(R.paint("Litmus doctor", "bold", color) + R.paint("  · cli %s · Python %s · 仓库 %s"
                                                          % (CLI_VERSION, sys.version.split()[0], REPO_ROOT), "dim", color))
    print("")
    fails = 0
    warns = 0
    for it in items:
        if it.ok is True:
            mark = R.paint("✓", "green", color)
        elif it.ok is False:
            mark = R.paint("✗", "red", color)
            fails += 1
        else:
            mark = R.paint("•", "yellow", color)
            warns += 1
        name = R.pad(it.name, 26)
        print(" [%s] %s %s" % (mark, name, it.detail))
        for h in it.hints:
            print("        " + R.paint("→ " + h, "dim", color))
    print("")
    if fails:
        print(R.paint("结论：%d 项失败 / %d 项提醒 —— 按上面的 → 修" % (fails, warns), "red", color))
        return 1
    print(R.paint("结论：全部通过%s" % ("（%d 项提醒）" % warns if warns else ""), "green", color))
    print(R.paint("下一步：python cli/litmus.py run --label C1-baseline --framework none", "dim", color))
    return 0


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def resolve_apk(args, expect: dict) -> Path:
    if getattr(args, "apk", None):
        return rp(args.apk)
    cand = expect.get("apk")
    if cand:
        p = rp(cand)
        if p.is_file():
            return p
    ver = expect.get("version") or "0.1.0"
    return rp("canary/out/litmus-canary-%s.apk" % ver)


def adb_install(adb: Adb, apk: Path, allow_uninstall: bool = True) -> float:
    """装包。返回耗时秒数。

    三次尝试，全是这个产品绕不开的：
      1. `install -r`（-d 允许降级，否则自家版本号一改就装不上）；
      2. INSTALL_FAILED_TEST_ONLY → 加 `-t`（有些构建脚本会打 testOnly）；
      3. INSTALL_FAILED_UPDATE_INCOMPATIBLE（**签名不同**）→ 这恰恰是「用户修补了靶包」
         最常见的样子，不卸载永远装不上。自动 uninstall + install，并明确警告：
         设备上的旧报告会被一起清掉。
    """
    if not apk.is_file():
        raise CliError("APK 不存在：%s（先构建：powershell -File canary/build.ps1）" % rel(apk))
    t0 = time.time()

    def attempt(extra=()):
        rc, out, err = adb.run(["install", "-r", "-d", *extra, str(apk)], timeout=240)
        return rc, _decode(out) + _decode(err)

    rc, text = attempt()
    if "Success" not in text and "INSTALL_FAILED_TEST_ONLY" in text:
        rc, text = attempt(("-t",))
    if "Success" not in text and (
        "INSTALL_FAILED_UPDATE_INCOMPATIBLE" in text or "signatures do not match" in text
    ):
        if not allow_uninstall:
            raise CliError(
                "签名与设备上已装的 %s 不一致，装不上（这正是重打包包的典型症状）。\n"
                "  加 --no-uninstall 时 CLI 不会替你卸载。手动处理：adb uninstall %s" % (PKG, PKG)
            )
        print(
            "[warn] 设备上已装包的签名与 %s 不同（重打包/换签名很常见）→ 自动卸载重装；\n"
            "       注意：/sdcard/Android/data/%s 下的旧报告会被一并清掉" % (rel(apk), PKG),
            file=sys.stderr,
        )
        adb.run(["uninstall", PKG], timeout=180)
        rc, text = attempt()
    if "Success" not in text:
        raise CliError("安装失败（%s）：\n%s" % (rel(apk), short_adb_out(text)))
    return time.time() - t0


def short_adb_out(text: str, n: int = 1200) -> str:
    t = text.strip()
    return t if len(t) <= n else t[:n] + "\n…（截断）"


def trigger_run(adb: Adb, custom: str | None) -> str:
    """把检测拉起来。返回一句人类可读的触发方式描述。

    顺序是有讲究的：App 在 Application.onCreate 里就已经起线程跑了，
    所以 `am start` 是主路径；广播 / force_run 只是「主路径没效果」时的兜底，
    它们都在同一个进程内被幂等忽略，多打几次不会产生两份互相覆盖的报告。
    """
    if custom:
        out = adb.shell(*custom.split(), timeout=60)
        return "custom: %s" % custom
    rc, out, err = adb.run(["shell", "am", "start", "-W", "-n", ACTIVITY], timeout=90)
    text = _decode(out) + _decode(err)
    if "Error:" in text or "does not exist" in text:
        if "does not exist" in text or "Unable to find explicit activity" in text:
            raise CliError("%s 未安装或入口不对（%s）。先去掉 --no-install 让 CLI 装包。" % (PKG, short_adb_out(text, 400)))
        raise CliError("am start 失败：%s" % short_adb_out(text, 400))
    return "am start -W"


def wait_for_report(adb: Adb, timeout: float, label: str, verbose: bool = False):
    """轮询直到拿到报告 / 超时。返回 (report, source, notes)。

    为什么 logcat 优先、设备文件降频：
      logcat 一次 exec 就能拿到报告本体 + 落盘路径，是最便宜的路径；
      `ls` 走的 shell 在 Android 11+ 还会被 scoped storage 挡住。
      所以每拍查 logcat，设备文件每 4 拍查一次（再加上有 LITMUS_REPORT_PATH 提示时立刻查）。
    """
    t0 = time.time()
    deadline = t0 + float(timeout)
    notes = []
    hinted = None
    triggers_done = set()
    tick = 0
    last_noise = 0.0
    log_lines = 0

    while True:
        tick += 1
        text = logcat_dump(adb)
        log_lines = max(log_lines, len([ln for ln in text.splitlines() if ln.strip()]))
        rep, how, path = parse_logcat(text)
        if path:
            hinted = path
        if rep is not None:
            return rep, how, notes

        # 设备文件：第一拍就试（App 可能已经把文件落好了），之后降频
        if tick == 1 or tick % 4 == 1 or (hinted and tick % 2 == 0):
            file_rep, note = pull_report_from_device(adb, hinted)
            if file_rep is not None:
                return file_rep, "sdcard", notes
            if note and note not in notes:
                notes.append(note)

        elapsed = time.time() - t0
        # 兜底触发：5 秒没动静就广播一次；12 秒还没动静就 force_run 一次
        if elapsed > 5 and "broadcast" not in triggers_done:
            triggers_done.add("broadcast")
            adb.shell("am", "broadcast", "-a", "%s.RUN" % PKG, "-p", PKG, timeout=30)
            if verbose:
                print("[..] 5s 无报告 → 已广播 %s.RUN" % PKG, file=sys.stderr)
        if elapsed > 12 and "force_run" not in triggers_done:
            triggers_done.add("force_run")
            adb.run(["shell", "am", "start", "-W", "-n", ACTIVITY, "--ez", "force_run", "true"], timeout=60)
            if verbose:
                print("[..] 12s 无报告 → 已用 --ez force_run true 重启", file=sys.stderr)

        if verbose and time.time() - last_noise > 4:
            last_noise = time.time()
            print("[..] 等待报告 %ds/%ss" % (int(elapsed), int(timeout)), file=sys.stderr)

        if time.time() >= deadline:
            break
        time.sleep(0.6)

    # 最后再抢救一次（有时报告刚好在超时那一拍落盘）
    rep, how, _path = parse_logcat(logcat_dump(adb))
    if rep is not None:
        return rep, how, notes
    file_rep, note = pull_report_from_device(adb, hinted)
    if file_rep is not None:
        return file_rep, "sdcard", notes
    if note and note not in notes:
        notes.append(note)

    # ③ 失败：把「试过什么」全列出来，绝不静默
    tried = list(notes)
    tried.append(
        "② logcat：tag=%s 一共 %d 行，但没有成套的 LITMUS_REPORT / LITMUS_REPORT_CHUNK"
        % (LOG_TAG, log_lines)
    )
    raise CliError(
        "等了 %ss 还是没拿到报告（label=%s）。已经试过：\n  %s\n"
        "排查顺序：\n"
        "  1) adb -s %s logcat -d -s %s  有没有任何输出？（没有=App 根本没跑，看 2）\n"
        "  2) adb -s %s shell am force-stop %s; adb -s %s shell am start -W -n %s  然后手动看 logcat\n"
        "  3) App 崩溃：adb -s %s logcat -d -s AndroidRuntime\n"
        "  4) 报告太大被 logcat 截断时走 LITMUS_REPORT_CHUNK，检查 chunk 是否成套（i/n）\n"
        "  5) Android 11+ 上 shell 用户读不了 /sdcard/Android/data，此路径靠 logcat\n"
        "  6) 单条 log 行超过约 4000 字节会被 logd 截断；超长报告必须走 CHUNK"
        % (
            timeout,
            label,
            "\n  ".join(tried),
            adb.serial, LOG_TAG, adb.serial, PKG, adb.serial, ACTIVITY, adb.serial,
        )
    )


def load_baseline(path, expect: dict, profile: str):
    """读基线并算出它的 raw。返回 (baseline_report, baseline_summary, path)。

    基线的两种形态都要支持，而且必须**口径一致**：
      * `run.json`（CLI 产物）：里面 `score.rawExact` 就是当时算出来的 raw，
        它已经包含 CLI 平面两条信号 —— 直接拿来用最忠实。
      * `report.raw.json`（App 原始报告）：里面没有 CLI 平面信号（App 看不见自己的哈希）。
        如果就这么算 Pb，基线的污染度会偏小 → 归一后分数偏低，看起来「改了包」。
        所以这里把**同一份 expect** 喂进去重算一遍，让基线和本轮用同一套信号集。
        前提：基线是同一个 target APK 的干净运行（C1-baseline 场景），否则基线本来就该判 TAMPERED。
    """
    rep = read_json(path)
    if rep.get("schema") == S.SCHEMA_RUN:
        bscore = rep.get("score") or {}
        if bscore.get("rawExact") is not None or bscore.get("raw") is not None:
            summary = {
                "raw": bscore.get("rawExact", bscore.get("raw")),
                "score": bscore.get("raw"),
                "signals": rep.get("signals") or [],
                "categories": bscore.get("categories") or [],
            }
            return rep, summary, path
    # App 原始报告：补上 CLI 平面信号后再算
    summary = S.analyze(rep, expect, profile=profile)["summary"]
    return rep, summary, path


def cmd_run(args) -> int:
    color = use_color()
    docs = load_docs()
    expect_path = rp(args.expect) if getattr(args, "expect", None) else default_build_info()
    try:
        expect, expect_path = load_expect(expect_path)
    except CliError as e:
        # 没有 build-info.json 就没有期望哈希 → CLI 平面两条信号只能判 UNKNOWN，
        # 那等于把「包完整性」这条最硬的 A 级证据关掉。与其降级跑，不如直接告诉用户去构建。
        raise CliError(
            "%s\n  修法：① 在仓库根构建靶包：powershell -ExecutionPolicy Bypass -File canary/build.ps1\n"
            "        ② 已经有构建产物时用 --expect <path> 指定 build-info.json\n"
            "        ③ 只想验证评分逻辑、不想碰设备：python cli/litmus.py selftest / demo" % e
        )
    profile = args.profile
    S.profile_weights(profile)  # 早失败：profile 拼错时不要等到跑了设备才报

    baseline_report = None
    baseline_path = None
    baseline_summary = None
    if getattr(args, "baseline", None):
        baseline_path = rp(args.baseline)
        baseline_report, baseline_summary, _p = load_baseline(baseline_path, expect, profile)

    adb = Adb(serial=getattr(args, "serial", None), adb_path=getattr(args, "adb", None), echo=args.verbose)
    serial = pick_serial(adb, getattr(args, "serial", None))
    print(R.paint("[1/6] 设备 %s · profile=%s · label=%s" % (serial, profile, args.label), "cyan", color))

    apk = resolve_apk(args, expect)
    if args.no_install:
        print(R.paint("[2/6] 跳过安装（--no-install），用设备上已装的包", "dim", color))
    else:
        print(R.paint("[2/6] 安装 %s …" % rel(apk), "cyan", color))
        secs = adb_install(adb, apk, allow_uninstall=not getattr(args, "no_uninstall", False))
        print("      ok（%.1fs）" % secs)

    # 清 logcat 缓冲：不清的话上一轮的报告会被当成这一轮（这是最难查的假失败）
    adb.run(["logcat", "-c"], timeout=30)
    adb.shell("am", "force-stop", PKG, timeout=30)
    print(R.paint("[3/6] 触发检测 …", "cyan", color))
    how_start = trigger_run(adb, args.trigger)
    started_at = now_iso()
    print("      %s（窗口起点 %s）" % (how_start, started_at))

    print(R.paint("[4/6] 等报告（最多 %ss）…" % args.timeout, "cyan", color))
    report, source, _notes = wait_for_report(adb, args.timeout, args.label, verbose=args.verbose)
    finished_at = now_iso()
    app_run_id = ((report.get("run") or {}).get("id") or "")
    print("      ok（来源 %s · appRunId %s）" % (source, app_run_id or "-"))

    n_sig = len(report.get("signals") or [])
    print(R.paint("[5/6] 收到 %d 条应用侧信号，补 2 条 CLI 平面信号并打分 …" % n_sig, "cyan", color))
    analysis = S.analyze(report, expect, profile=profile, baseline_report=baseline_report)
    if baseline_summary is not None:
        # 用「喂进来的 baseline 摘要」参与归一，保持与 score 子命令同一口径
        analysis["litmus"], analysis["baseline"] = S.baseline_block(
            analysis["summary"], baseline_summary, rel(baseline_path)
        )

    run_json = assemble_run_json(
        report=report, expect=expect, expect_path=expect_path, analysis=analysis,
        label=args.label, framework=args.framework, serial=serial,
        started_at=started_at, finished_at=finished_at, mode="live",
        report_source=source, baseline_path=baseline_path, app_run_id=app_run_id,
    )

    out_dir = rp(args.out) / ("%s-%s" % (args.label, now_stamp()))
    paths = write_run_bundle(out_dir, report, run_json, docs=docs)
    print(R.paint("[6/6] 产物：%s" % rel(out_dir), "cyan", color))
    for k in ("raw", "json", "md", "html"):
        print("      %-18s %s" % (k, rel(paths[k])))

    print(R.to_terminal(run_json, color=color, docs=docs))

    chk = run_json.get("appSummaryCheck") or {}
    if chk.get("checked") and not chk.get("match"):
        print(R.paint("[warn] App 自算 summary 与 CLI 重算不一致：score %s vs %s（差 %s）—— "
                      "Score.java 与 litmus_score.py 出现了口径漂移，请先对齐公式"
                      % (chk.get("appScore"), chk.get("cliScore"), chk.get("scoreDelta")), "red", color),
              file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# score
# ---------------------------------------------------------------------------


def label_from_path(path) -> str:
    """离线复算时，尽量用「这次运行原来的 label」而不是 App 的 runId。

    runs/C2-repack-20261110-164602/report.raw.json → C2-repack
    报告标题里出现一串随机 id 对人没有任何信息量，目录名才对得上上一次 run。
    """
    try:
        name = Path(path).parent.name
    except Exception:
        return ""
    m = re.match(r"^(?P<label>.+)-\d{8}-\d{6}$", name or "")
    return m.group("label") if m else ""


def cmd_score(args) -> int:
    docs = load_docs()
    report = read_json(rp(args.report))
    try:
        expect, expect_path = load_expect(rp(args.expect) if getattr(args, "expect", None) else default_build_info())
    except CliError as e:
        raise CliError("%s\n  → 离线复算也需要 build-info.json 才能复核包完整性；用 --expect <path> 指定" % e)
    profile = args.profile
    baseline_report = None
    baseline_summary = None
    baseline_path = None
    if getattr(args, "baseline", None):
        baseline_path = rp(args.baseline)
        baseline_report, baseline_summary, _p = load_baseline(baseline_path, expect, profile)

    analysis = S.analyze(report, expect, profile=profile, baseline_report=baseline_report)
    if baseline_summary is not None:
        analysis["litmus"], analysis["baseline"] = S.baseline_block(
            analysis["summary"], baseline_summary, rel(rp(args.baseline))
        )

    label = args.label or label_from_path(rp(args.report)) or ((report.get("run") or {}).get("id") or "offline")
    run_json = assemble_run_json(
        report=report, expect=expect, expect_path=expect_path, analysis=analysis,
        label=label, framework=args.framework or "-", serial="-",
        started_at=now_iso(), finished_at=now_iso(), mode="offline",
        report_source="offline:%s" % rel(rp(args.report)),
        baseline_path=baseline_path,
        app_run_id=(report.get("run") or {}).get("id") or "",
    )

    if args.json:
        print(json.dumps(run_json, ensure_ascii=False, indent=2))
    else:
        print(R.to_terminal(run_json, color=use_color(), docs=load_docs()))
    if getattr(args, "save", None):
        out_dir = rp(args.save)
        paths = write_run_bundle(out_dir, report, run_json, docs=docs)
        print(R.paint("产物：%s" % rel(out_dir), "cyan", use_color()))
        for k in ("raw", "json", "md", "html"):
            print("  %-8s %s" % (k, rel(paths[k])))
    return 0


# ---------------------------------------------------------------------------
# matrix
# ---------------------------------------------------------------------------


def cmd_matrix(args) -> int:
    base = rp(args.runs)
    if not base.is_dir():
        raise CliError("目录不存在：%s（先跑几次 litmus.py run）" % rel(base))
    entries = []
    skipped = []
    for p in sorted(base.rglob("run.json")):
        try:
            rj = read_json(p)
        except CliError as e:
            skipped.append("%s：%s" % (rel(p), e))
            continue
        if rj.get("schema") != S.SCHEMA_RUN:
            skipped.append("%s：schema=%r" % (rel(p), rj.get("schema")))
            continue
        run = rj.get("run") or {}
        entries.append({
            "label": str(run.get("label") or p.parent.name),
            "started": str(run.get("startedAt") or ""),
            "path": str(p.parent),
            "run_json": rj,
        })
    if not entries:
        raise CliError("在 %s 下没找到任何 run.json（schema=%s）" % (rel(base), S.SCHEMA_RUN))

    # label 去重（同一 label 跑多次时要能区分）
    seen = {}
    for e in entries:
        base_label = e["label"]
        seen[base_label] = seen.get(base_label, 0) + 1
        if seen[base_label] > 1:
            e["label"] = "%s#%d" % (base_label, seen[base_label])
    entries.sort(key=lambda e: (e["label"], e["started"]))

    # 目录覆盖率：契约里声明了、但一次都没出现过的向量（实现缺口）
    catalog = S.load_catalog()
    coverage = None
    if catalog:
        seen = set()
        for e in entries:
            for s in e["run_json"].get("signals") or []:
                if s.get("id"):
                    seen.add(s["id"])
        missing = [vid for vid in catalog if vid not in seen]
        coverage = {"declared": len(catalog), "present": len(seen & set(catalog)), "missing": missing}

    md = R.matrix_markdown(entries, title=args.title or rel(base), coverage=coverage)
    out = rp(args.out) if args.out else (base / "matrix.md")
    write_text(out, md)

    color = use_color()
    print("")
    print(R.paint("Litmus matrix", "bold", color) + R.paint("  · %d 次运行 · 输出 %s" % (len(entries), rel(out)), "dim", color))
    print("")
    for e in entries:
        sc = e["run_json"].get("score") or {}
        pm = e["run_json"].get("packageModified") or {}
        print("  %-26s litmus %6s  raw %6s  盲区 %d  误报 %d  包%s" % (
            e["label"], R.fmt_score(sc.get("litmus")), R.fmt_score(sc.get("raw")),
            len(e["run_json"].get("blindSpots") or []), len(e["run_json"].get("falsePositives") or []),
            "已改" if pm.get("modified") else "未动",
        ))
    # 全程 CLEAN 的向量单独点名（疑似检测能力缺失）
    all_clean = _all_clean_vectors(entries)
    print("")
    if all_clean:
        print(R.paint("所有运行都 CLEAN 的向量（%d）—— 疑似检测能力缺失：" % len(all_clean), "yellow", color))
        for vid in all_clean:
            print("  - " + vid)
    else:
        print(R.paint("没有任何向量在所有运行里都 CLEAN（说明每条检测至少动过一次）", "green", color))
    if coverage is not None:
        miss = coverage.get("missing") or []
        if miss:
            print("")
            print(R.paint("目录覆盖率 %d/%d —— 声明了但从未出现的向量（%d）："
                          % (coverage["present"], coverage["declared"], len(miss)), "yellow", color))
            for vid in miss[:20]:
                print("  - " + vid)
            if len(miss) > 20:
                print(R.paint("  …另有 %d 条，见 matrix.md" % (len(miss) - 20), "dim", color))
        else:
            print(R.paint("目录覆盖率 %d/%d —— 全部声明向量都出现过" % (coverage["present"], coverage["declared"]), "green", color))
    for s in skipped:
        print(R.paint("[skip] " + s, "dim", color), file=sys.stderr)
    print("")
    print(R.paint("完整表格：%s" % rel(out), "dim", color))
    return 0


def _all_clean_vectors(entries) -> list:
    order = []
    verdicts = {}
    for e in entries:
        for s in e["run_json"].get("signals") or []:
            sid = s.get("id")
            if sid not in verdicts:
                order.append(sid)
                verdicts[sid] = []
            verdicts[sid].append(str(s.get("verdict")))
    out = []
    for sid in order:
        vs = verdicts[sid]
        if vs and all(v == S.CLEAN for v in vs):
            out.append(sid)
    return out


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------


def cmd_demo(args) -> int:
    docs = load_docs()
    report, expect, baseline = fixture_named(args.fixture)
    label = args.label or "DEMO-%s" % (args.fixture or "b")
    analysis = S.analyze(report, expect, profile=args.profile, baseline_report=baseline)
    run_json = assemble_run_json(
        report=report, expect=expect, expect_path=Path("schema/vectors.json#fixture"),
        analysis=analysis, label=label, framework=args.framework,
        serial="fixture-no-device", started_at=now_iso(), finished_at=now_iso(),
        mode="fixture", report_source="fixture:%s" % (args.fixture or "b"),
        baseline_path=None, app_run_id=(report.get("run") or {}).get("id") or "",
    )
    out_dir = rp(args.out) / ("%s-%s" % (label, now_stamp())) if args.dirname is None else rp(args.dirname)
    paths = write_run_bundle(out_dir, report, run_json, docs=docs)
    print(R.paint("（fixture 模式：没有碰设备，纯构造数据）", "dim", use_color()))
    for k in ("raw", "json", "md", "html"):
        print("  %-18s %s" % (k, rel(paths[k])))
    print(R.to_terminal(run_json, color=use_color(), docs=load_docs()))
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="litmus.py",
        description="Litmus · 百眼 —— Android 篡改检测评分器 CLI（只用标准库）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "常见用法：\n"
            "  python cli/litmus.py doctor\n"
            "  python cli/litmus.py run --label C1-baseline --framework none\n"
            "  python cli/litmus.py run --serial emulator-5554 --label C2-frida --framework frida --baseline runs/C1-baseline-xxx/run.json\n"
            "  python cli/litmus.py score --report runs/x/report.raw.json --expect canary/out/build-info.json\n"
            "  python cli/litmus.py matrix --runs runs\n"
            "  python cli/litmus.py selftest\n"
        ),
    )
    p.add_argument("--version", action="version", version="litmus cli %s" % CLI_VERSION)
    sub = p.add_subparsers(dest="cmd")

    d = sub.add_parser("doctor", help="环境自检")
    d.add_argument("--serial", help="目标设备序列号（默认自动选第一台在线设备）")
    d.add_argument("--adb", help="adb 可执行文件路径")
    d.add_argument("--expect", help="build-info.json 路径（默认 canary/out/build-info.json）")
    d.add_argument("--apk", help="APK 路径（默认取 build-info.apk 或 canary/out/litmus-canary-<ver>.apk）")
    d.set_defaults(func=cmd_doctor)

    r = sub.add_parser("run", help="装包 → 触发 → 拉报告 → 打分 → 写 runs/")
    r.add_argument("--serial", help="设备序列号（默认自动选第一台）")
    r.add_argument("--adb", help="adb 可执行文件路径")
    r.add_argument("--label", required=True, help="本次运行的标签，例如 C2-frida（用于目录名与 matrix 列名）")
    r.add_argument("--framework", default="none", help="修补手段，例如 frida / lsposed / repack；仅记账")
    r.add_argument("--apk", help="要安装的 APK（默认取 build-info.apk）")
    r.add_argument("--no-install", action="store_true", help="不重装，直接用设备上已装的包")
    r.add_argument("--no-uninstall", action="store_true",
                   help="签名不一致时不要自动卸载（默认会卸载重装，因为重打包包签名必然不同）")
    r.add_argument("--baseline", help="基线 run.json 或 report.raw.json（用于基线归一 + 误报判定）")
    r.add_argument("--profile", default=S.DEFAULT_PROFILE, choices=sorted(S.PROFILES), help="聚合 profile")
    r.add_argument("--out", default="runs", help="产物根目录（相对仓库根），默认 runs")
    r.add_argument("--timeout", type=float, default=25, help="等报告的最长秒数，默认 25")
    r.add_argument("--expect", help="build-info.json 路径（默认 canary/out/build-info.json）")
    r.add_argument("--trigger", help="自定义触发命令（adb shell 之后的部分），例如 \"am start -n io.litmus.canary/.MainActivity\"")
    r.add_argument("-v", "--verbose", action="store_true", help="打印 adb 调用与轮询细节")
    r.set_defaults(func=cmd_run)

    sc = sub.add_parser("score", help="离线重算（不碰设备）")
    sc.add_argument("--report", required=True, help="App 产出的 report.raw.json")
    sc.add_argument("--expect", help="build-info.json 路径（默认 canary/out/build-info.json）")
    sc.add_argument("--baseline", help="基线 run.json / report.raw.json")
    sc.add_argument("--profile", default=S.DEFAULT_PROFILE, choices=sorted(S.PROFILES))
    sc.add_argument("--label", help="覆盖 run.json 里的 label")
    sc.add_argument("--framework", help="覆盖 run.json 里的 framework")
    sc.add_argument("--json", action="store_true", help="把 run.json 打到 stdout")
    sc.add_argument("--save", help="把四件套写到这个目录")
    sc.set_defaults(func=cmd_score)

    m = sub.add_parser("matrix", help="扫 runs/ 出跨运行对比表")
    m.add_argument("--runs", default="runs", help="要扫描的根目录，默认 runs")
    m.add_argument("--out", help="输出 md 路径，默认 <runs>/matrix.md")
    m.add_argument("--title", default=None, help="表头标题")
    m.set_defaults(func=cmd_matrix)

    st = sub.add_parser("selftest", help="内置 fixture 自检（不需要设备/APK）")
    st.add_argument("-v", "--verbose", action="store_true", help="逐条打印通过的断言")
    st.set_defaults(func=cmd_selftest)

    dm = sub.add_parser("demo", help="用内置 fixture 生成一份完整 run（看 report.html 用）")
    dm.add_argument("--fixture", default="b", choices=["a", "b", "c"], help="a=包未改 b=包被改(盲区) c=基线误报")
    dm.add_argument("--out", default="runs", help="产物根目录")
    dm.add_argument("--dirname", help="直接指定本次产物目录")
    dm.add_argument("--label", help="标签")
    dm.add_argument("--framework", default="fixture")
    dm.add_argument("--profile", default=S.DEFAULT_PROFILE, choices=sorted(S.PROFILES))
    dm.set_defaults(func=cmd_demo)
    return p


def main(argv=None) -> int:
    init_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    try:
        return int(args.func(args) or 0)
    except CliError as e:
        sys.stdout.flush()  # 保证进度行先于错误行出现（stderr 无缓冲）
        print("", file=sys.stderr)
        print("[错误] %s" % e, file=sys.stderr)
        return 1
    except S.ScoreError as e:
        sys.stdout.flush()
        print("[评分错误] %s" % e, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[中断]", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
