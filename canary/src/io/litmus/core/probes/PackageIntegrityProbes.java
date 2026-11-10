package io.litmus.core.probes;

import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import io.litmus.core.LitmusContext;
import io.litmus.core.AppSnapshot;
import io.litmus.core.BuildInfo;
import io.litmus.core.Probe;

import org.json.JSONArray;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 包完整性。tier A 主力：签名链与内容哈希是密码学的，改了就一定不成立。
 *
 * <p>注意分工：{@code pkg.codepath.hash} 与 {@code pkg.zip.fingerprint} 的**期望值烘不进
 * APK 自身**（签完才有），所以这两个向量在 App 侧只产 UNKNOWN + facts，由 CLI 平面判。
 * 见 docs/04-契约.md §4.1。
 *
 * <p>所有期望值来自 {@link BuildInfo}（构建期烘进 assets）或 {@link AppSnapshot}，
 * 本文件**不含任何硬编码的哈希**。
 */
public final class PackageIntegrityProbes {

    private PackageIntegrityProbes() {
    }

    public static List<Probe> list() {
        List<Probe> out = new ArrayList<>(12);
        out.add(new SignatureLegacy());
        out.add(new SigningV3());
        out.add(new CertHistory());
        out.add(new CodePathHash());
        out.add(new ZipFingerprint());
        out.add(new ManifestProbe());
        out.add(new DexProbe());
        out.add(new Installer());
        out.add(new ProcName());
        return out;
    }

    // ------------------------------------------------------------------ 签名（A）

    /** pkg.signature —— GET_SIGNATURES 全量比对。A 级。 */
    static final class SignatureLegacy implements Probe {
        @Override
        public String id() {
            return "pkg.signature";
        }

        @Override
        public String category() {
            return "package-integrity";
        }

        @Override
        public int weight() {
            return 5;
        }

        @Override
        public String tier() {
            return "A";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                if (ctx.appSnap == null) {
                    sink.unknown("snapshot unavailable");
                    return;
                }
                String expect = Ev.nz(BuildInfo.expectedLegacyCertSha256);
                List<String> actual = safe(ctx.appSnap.installCerts);
                if (expect.isEmpty()) {
                    sink.unknown("no baked expectation (dev build), actual=" + hexList(actual));
                    return;
                }
                if (actual.isEmpty()) {
                    sink.unknown("no legacy signature returned");
                    return;
                }
                if (actual.size() == 1 && expect.equalsIgnoreCase(actual.get(0))) {
                    sink.clean("cert=" + shortHex(actual.get(0)));
                } else {
                    sink.tampered("expect=" + shortHex(expect) + " actual=" + hexList(actual), 1.0);
                }
            } catch (Throwable t) {
                sink.error("pkg.signature: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * pkg.signing.v3 —— apkContentsSigners 全量 + hasMultipleSigners。A 级。
     *
     * <p>重打包几乎必然换证书；换多张证书（多个 signer）也是痕迹。
     */
    static final class SigningV3 implements Probe {
        @Override
        public String id() {
            return "pkg.signing.v3";
        }

        @Override
        public String category() {
            return "package-integrity";
        }

        @Override
        public int weight() {
            return 5;
        }

        @Override
        public String tier() {
            return "A";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                if (ctx.appSnap == null) {
                    sink.unknown("snapshot unavailable");
                    return;
                }
                String expect = Ev.nz(BuildInfo.expectedCertSha256);
                List<String> actual = safe(ctx.appSnap.signingCerts);
                if (expect.isEmpty()) {
                    sink.unknown("no baked expectation (dev build), signers=" + actual.size());
                    return;
                }
                if (actual.isEmpty()) {
                    sink.unknown("no apkContentsSigners returned");
                    return;
                }
                int expectCount = BuildInfo.expectedSignerCount <= 0 ? 1 : BuildInfo.expectedSignerCount;
                if (ctx.appSnap.multipleSigners && expectCount == 1) {
                    sink.tampered("multipleSigners=true signers=" + hexList(actual), 1.0);
                    return;
                }
                if (actual.size() != expectCount) {
                    sink.tampered("signerCount expect=" + expectCount + " actual=" + actual.size()
                            + " " + hexList(actual), 1.0);
                    return;
                }
                boolean hit = false;
                for (String s : actual) {
                    if (expect.equalsIgnoreCase(s)) {
                        hit = true;
                        break;
                    }
                }
                if (hit) {
                    sink.clean("v3 signer=" + shortHex(actual.get(0)) + " count=" + actual.size());
                } else {
                    sink.tampered("expect=" + shortHex(expect) + " actual=" + hexList(actual), 1.0);
                }
            } catch (Throwable t) {
                sink.error("pkg.signing.v3: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * pkg.cert.history —— getSigningCertificateHistory 全量。A 级。
     *
     * <p>密钥轮换时历史链是固定的；被换过签名的人拿不到原链。期望集合来自 BuildInfo 里的
     * JSON 字面量（构建期写入），不是硬编码。
     */
    static final class CertHistory implements Probe {
        @Override
        public String id() {
            return "pkg.cert.history";
        }

        @Override
        public String category() {
            return "package-integrity";
        }

        @Override
        public int weight() {
            return 3;
        }

        @Override
        public String tier() {
            return "A";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                if (ctx.appSnap == null) {
                    sink.unknown("snapshot unavailable");
                    return;
                }
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                    sink.unknown("SigningInfo requires API 28+");
                    return;
                }
                Set<String> expect = new HashSet<>();
                try {
                    JSONArray a = new JSONArray(Ev.nz(BuildInfo.expectedCertHistoryJson).trim());
                    for (int i = 0; i < a.length() && expect.size() < 8; i++) {
                        String s = a.optString(i, "");
                        if (!s.isEmpty()) {
                            expect.add(s.toLowerCase());
                        }
                    }
                } catch (Throwable ignored) {
                    // 解析失败按「没有期望值」处理
                }
                List<String> actual = safe(ctx.appSnap.certHistory);
                if (expect.isEmpty()) {
                    sink.unknown("no baked history expectation (dev build), history=" + actual.size());
                    return;
                }
                Set<String> got = new HashSet<>();
                for (String s : actual) {
                    got.add(Ev.nz(s).toLowerCase());
                }
                if (actual.isEmpty()) {
                    sink.unknown("certHistory empty (non-rotated or pruned)");
                } else if (got.equals(expect)) {
                    sink.clean("history=" + actual.size() + " matches baked set");
                } else {
                    // 措辞要点：先给「期望 vs 实际」的哈希，再给条数。否则一眼看去像「数量不符」，
                    // 实际这里最常见的是「条数相同、证书被换」。
                    sink.tampered("expect=" + hexList(new ArrayList<>(expect))
                            + " actual=" + hexList(actual)
                            + " (n=" + expect.size() + "/" + actual.size() + ")", 0.95);
                }
            } catch (Throwable t) {
                sink.error("pkg.cert.history: " + t.getClass().getSimpleName());
            }
        }
    }

    // ------------------------------------------------------------------ 内容哈希（CLI 判）

    /**
     * pkg.codepath.hash —— codePath 内容哈希。
     *
     * <p>APK 自己的 sha256 烘不进自己（签完才有），所以 App 侧只报 UNKNOWN + facts，
     * 期望值由 CLI 从 build-info.json 取（契约 §4.1 / §4.2）。
     */
    static final class CodePathHash implements Probe {
        @Override
        public String id() {
            return "pkg.codepath.hash";
        }

        @Override
        public String category() {
            return "package-integrity";
        }

        @Override
        public int weight() {
            return 5;
        }

        @Override
        public String tier() {
            return "A";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                if (ctx.appSnap == null) {
                    sink.unknown("snapshot unavailable");
                    return;
                }
                String sha = Ev.nz(ctx.appSnap.apkSha256);
                ctx.facts.put("apk.sha256", sha).put("apk.codePath", Ev.nz(ctx.appSnap.codePath));
                if (sha.isEmpty()) {
                    sink.unknown("codePath unreadable: " + Ev.clip(ctx.appSnap.codePath, 120));
                } else {
                    sink.unknown("sha256=" + shortHex(sha) + " (CLI compares, codePath="
                            + Ev.base(ctx.appSnap.codePath) + ")");
                }
            } catch (Throwable t) {
                sink.error("pkg.codepath.hash: " + t.getClass().getSimpleName());
            }
        }
    }

    /** pkg.zip.fingerprint —— ZipEntry 指纹，算法见契约 §4.4。同样只产 UNKNOWN + facts。 */
    static final class ZipFingerprint implements Probe {
        @Override
        public String id() {
            return "pkg.zip.fingerprint";
        }

        @Override
        public String category() {
            return "package-integrity";
        }

        @Override
        public int weight() {
            return 5;
        }

        @Override
        public String tier() {
            return "A";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                if (ctx.appSnap == null) {
                    sink.unknown("snapshot unavailable");
                    return;
                }
                String fp = Ev.nz(ctx.appSnap.zipFingerprint);
                ctx.facts.put("apk.zip.fingerprint", fp);
                if (fp.isEmpty()) {
                    sink.unknown("zip unreadable: " + Ev.base(ctx.appSnap.codePath));
                } else {
                    sink.unknown("zipFp=" + shortHex(fp) + " (CLI compares)");
                }
            } catch (Throwable t) {
                sink.error("pkg.zip.fingerprint: " + t.getClass().getSimpleName());
            }
        }
    }

    // ------------------------------------------------------------------ 清单 / dex

    /**
     * pkg.manifest —— appComponentFactory / appClass 是否被改。
     *
     * <p>B 级不变量：PackageManager 报的 Application 类名是**清单里的值**，而运行时真正跑
     * 的是当前对象。两者不符 = 有人在装载阶段把 Application 换掉了（这是最常见的注入入口）。
     * 允许子类（有的安全 SDK 会派生一层）。
     */
    static final class ManifestProbe implements Probe {
        @Override
        public String id() {
            return "pkg.manifest";
        }

        @Override
        public String category() {
            return "package-integrity";
        }

        @Override
        public int weight() {
            return 4;
        }

        @Override
        public String tier() {
            return "B";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                if (ctx.appSnap == null) {
                    sink.unknown("snapshot unavailable");
                    return;
                }
                String declared = Ev.nz(ctx.appSnap.appClass);
                String factory = Ev.nz(ctx.appSnap.appComponentFactory);
                String runtime = "";
                try {
                    runtime = ctx.app.getApplicationContext().getClass().getName();
                } catch (Throwable ignored) {
                    // 拿不到就不判类名
                }
                ctx.facts.put("app.class", declared).put("app.runtimeClass", runtime)
                        .put("app.componentFactory", factory);

                if (!declared.isEmpty() && !runtime.isEmpty() && !declared.equals(runtime)) {
                    if (isSubclass(declared, runtime)) {
                        sink.clean("appClass=" + Ev.base(declared) + " runtime subclass ok", 0.85);
                    } else {
                        sink.tampered("manifest appClass=" + declared + " runtime=" + runtime, 0.9);
                    }
                    return;
                }
                // ApplicationInfo.appComponentFactory 是 API 28 才有的字段
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && factory.isEmpty()) {
                    sink.suspect("appComponentFactory empty in ApplicationInfo "
                            + "(manifest attr dropped?)", 0.45);
                    return;
                }
                if (declared.isEmpty() && runtime.isEmpty()) {
                    sink.unknown("neither manifest nor runtime appClass available");
                } else {
                    sink.clean("appClass=" + Ev.base(declared) + " factory="
                            + (factory.isEmpty() ? "none" : Ev.base(factory)));
                }
            } catch (Throwable t) {
                sink.error("pkg.manifest: " + t.getClass().getSimpleName());
            }
        }

        private static boolean isSubclass(String declared, String runtime) {
            try {
                Class<?> a = Class.forName(declared);
                Class<?> b = Class.forName(runtime);
                return a.isAssignableFrom(b);
            } catch (Throwable ignored) {
                return false;
            }
        }
    }

    /**
     * pkg.dex —— classes*.dex 数量与完整性。
     *
     * <p>B 级：dex 数量来自快照里的 zip 目录；这里再验一遍每个 dex 的魔数（{@code dex\n}）。
     * 加固/加壳器常把 dex 换成自有格式或塞空壳，魔数会对不上。
     */
    static final class DexProbe implements Probe {
        private static final int MAX_CHECK = 6;

        @Override
        public String id() {
            return "pkg.dex";
        }

        @Override
        public String category() {
            return "package-integrity";
        }

        @Override
        public int weight() {
            return 4;
        }

        @Override
        public String tier() {
            return "B";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                AppSnapshot snap = ctx.appSnap;
                if (snap == null) {
                    sink.unknown("snapshot unavailable");
                    return;
                }
                int count = snap.dexCount;
                ctx.facts.put("apk.dex.count", count).put("apk.dex.bytes", snap.dexBytes);
                if (count < 0) {
                    sink.unknown("zip unreadable: " + Ev.base(snap.codePath));
                    return;
                }
                if (count == 0) {
                    sink.suspect("no classes*.dex in " + Ev.base(snap.codePath), 0.6);
                    return;
                }

                List<String> entries = new ArrayList<>();
                int badMagic = 0;
                ZipFile zf = null;
                try {
                    zf = new ZipFile(new File(snap.codePath));
                    java.util.Enumeration<? extends ZipEntry> en = zf.entries();
                    while (en.hasMoreElements()) {
                        ZipEntry e = en.nextElement();
                        String nm = e.getName();
                        if (!nm.startsWith("classes") || !nm.endsWith(".dex")) {
                            continue;
                        }
                        if (entries.size() < 8) {
                            entries.add(nm + "|" + e.getSize() + "|" + String.format("%08x", e.getCrc()));
                        }
                        if (entries.size() <= MAX_CHECK && !magicOk(zf, e)) {
                            badMagic++;
                        }
                    }
                } finally {
                    ProcFs.close(zf);
                }
                ctx.facts.put("apk.dex.entries", entries);

                if (badMagic > 0) {
                    sink.tampered("dex magic broken on " + badMagic + " entries "
                            + Ev.clipList(entries, 2), 0.9);
                } else {
                    sink.clean("dex=" + count + " bytes=" + snap.dexBytes + " magic ok");
                }
            } catch (Throwable t) {
                sink.error("pkg.dex: " + t.getClass().getSimpleName());
            }
        }

        private static boolean magicOk(ZipFile zf, ZipEntry e) {
            InputStream in = null;
            try {
                in = zf.getInputStream(e);
                byte[] b = new byte[8];
                int off = 0;
                while (off < 8) {
                    int n = in.read(b, off, 8 - off);
                    if (n <= 0) {
                        return false;
                    }
                    off += n;
                }
                // 0x64 0x65 0x78 0x0a = "dex\n"
                return b[0] == 0x64 && b[1] == 0x65 && b[2] == 0x78 && b[3] == 0x0a;
            } catch (Throwable t) {
                return true;   // 读失败不算「魔数坏」
            } finally {
                ProcFs.close(in);
            }
        }
    }

    // ------------------------------------------------------------------ 安装来源 / 进程名

    /**
     * pkg.installer —— installerPackageName。tier C。
     *
     * <p>adb / 侧载安装的 installer 是 null，这在本项目里是**正常基线**（靶包就是 adb 装的），
     * 所以 null 不能算痕迹；只有「来源是个不认识的三方包名」才给弱 SUSPECT。
     */
    static final class Installer implements Probe {
        private static final String[] KNOWN = {
                "com.android.vending", "com.google.android.packageinstaller",
                "com.android.packageinstaller", "com.android.shell",
                "com.google.android.gsf", "com.miui.packageinstaller",
                "com.samsung.android.packageinstaller", "com.huawei.appmarket",
                "com.oppo.market", "com.heytap.market", "com.bbk.appstore",
        };

        @Override
        public String id() {
            return "pkg.installer";
        }

        @Override
        public String category() {
            return "package-integrity";
        }

        @Override
        public int weight() {
            return 2;
        }

        @Override
        public String tier() {
            return "C";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                if (ctx.appSnap == null) {
                    sink.unknown("snapshot unavailable");
                    return;
                }
                PackageManager pm = ctx.app.getPackageManager();
                String pkg = ctx.appSnap.packageName;
                String installer = null;
                String initiating = "";
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        InstallSourceInfo info = pm.getInstallSourceInfo(pkg);
                        if (info != null) {
                            installer = info.getInstallingPackageName();
                            try {
                                initiating = Ev.nz(info.getInitiatingPackageName());
                            } catch (Throwable ignored) {
                                // 拿不到 initiating 不影响判定
                            }
                        }
                    } else {
                        installer = pm.getInstallerPackageName(pkg);
                    }
                } catch (Throwable t) {
                    sink.unknown("install source query failed: " + t.getClass().getSimpleName());
                    return;
                }
                ctx.facts.put("apk.installer", Ev.nz(installer))
                        .put("apk.installerInitiator", initiating);

                if (installer == null || installer.isEmpty()) {
                    sink.clean("installer=null (adb/sideload baseline)");
                    return;
                }
                for (String k : KNOWN) {
                    if (k.equals(installer)) {
                        sink.clean("installer=" + installer);
                        return;
                    }
                }
                sink.suspect("installer=" + Ev.clip(installer, 80)
                        + (initiating.isEmpty() ? "" : " initiator=" + Ev.clip(initiating, 60)), 0.4);
            } catch (Throwable t) {
                sink.error("pkg.installer: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * pkg.proc.name —— /proc/self/cmdline 与 PackageManager 报的包名是否一致。B 级。
     *
     * <p>多开容器/改名共存最常见的手法是把包名换掉，进程名却还留着容器自己的名字。
     * 正常应用（含 :子进程）两者恒等。
     */
    static final class ProcName implements Probe {
        @Override
        public String id() {
            return "pkg.proc.name";
        }

        @Override
        public String category() {
            return "package-integrity";
        }

        @Override
        public int weight() {
            return 3;
        }

        @Override
        public String tier() {
            return "B";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                if (ctx.appSnap == null) {
                    sink.unknown("snapshot unavailable");
                    return;
                }
                String pkg = Ev.nz(ctx.appSnap.packageName);
                String proc = Ev.nz(ctx.appSnap.processName);
                String cmd = "";
                String raw = ProcFs.readText("/proc/self/cmdline", 8192);
                if (raw != null) {
                    int z = raw.indexOf('\0');
                    cmd = (z >= 0 ? raw.substring(0, z) : raw).trim();
                }
                if (proc.isEmpty()) {
                    proc = cmd;
                }
                ctx.facts.put("proc.name", proc).put("proc.cmdline", cmd);

                String procBase = baseOf(proc);
                String cmdBase = baseOf(cmd);
                if (pkg.isEmpty()) {
                    sink.unknown("package name unavailable");
                } else if (procBase.isEmpty() && cmdBase.isEmpty()) {
                    sink.unknown("process name unreadable");
                } else if (pkg.equals(procBase) || pkg.equals(cmdBase)) {
                    sink.clean("proc=" + Ev.clip(proc, 60) + " pkg=" + pkg);
                } else {
                    sink.suspect("pkg=" + pkg + " proc=" + Ev.clip(procBase, 50)
                            + " cmdline=" + Ev.clip(cmdBase, 50), 0.6);
                }
            } catch (Throwable t) {
                sink.error("pkg.proc.name: " + t.getClass().getSimpleName());
            }
        }

        private static String baseOf(String procName) {
            if (procName == null || procName.isEmpty()) {
                return "";
            }
            int c = procName.indexOf(':');
            return (c > 0 ? procName.substring(0, c) : procName).trim();
        }
    }

    // ------------------------------------------------------------------ 工具

    static String shortHex(String hex) {
        if (hex == null) {
            return "";
        }
        return hex.length() <= 16 ? hex : hex.substring(0, 16) + "…";
    }

    static String hexList(List<String> list) {
        StringBuilder sb = new StringBuilder("[");
        int n = 0;
        for (String s : list) {
            if (n >= 4) {
                sb.append(",..");
                break;
            }
            if (n > 0) {
                sb.append(',');
            }
            sb.append(shortHex(s));
            n++;
        }
        return sb.append(']').toString();
    }

    static List<String> safe(List<String> l) {
        return l == null ? new ArrayList<String>() : l;
    }

    /** 供其它包内 probe 复用：把 AppSnapshot 的证书列表规范化。 */
    static List<String> normalized(AppSnapshot s) {
        return s == null ? new ArrayList<String>() : new ArrayList<>(safe(s.installCerts));
    }
}
