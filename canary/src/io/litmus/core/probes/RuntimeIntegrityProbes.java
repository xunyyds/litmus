package io.litmus.core.probes;

import io.litmus.core.LitmusContext;
import io.litmus.core.Probe;

import java.io.File;
import java.io.FileInputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 运行时完整性（tier A/B 的主力，也是「通吃」的核心）。
 *
 * <p>这里的判据全部是**不变量**：不找 Frida/Xposed 的特征，只问「这个进程的内存/系统调用
 * 还符不符合一个未被插桩的进程应有的样子」。因此对任何框架都成立。
 *
 * <p>数据来源两个视图，同一事实两条路径读：
 * <ul>
 *   <li>native 快照（{@link io.litmus.core.NativeSnapshot}，契约 §4.5，一次采样）；</li>
 *   <li>Java 侧自己解析 {@code /proc/self/*}（{@link ProcFs}）。</li>
 * </ul>
 * 两个视图对不上本身就是痕迹（有人只过滤了其中一条路径）。
 *
 * <p>判据阈值全部按「干净 Android 12/13 真机能过」定，宁松不严：拿不准就 SUSPECT/UNKNOWN，
 * 绝不为了抓人把干净机打成 TAMPERED。
 */
public final class RuntimeIntegrityProbes {

    private RuntimeIntegrityProbes() {
    }

    /** 向量顺序 = 报告顺序：先不变量（A/B）后特征（C）。 */
    public static List<Probe> list() {
        List<Probe> out = new ArrayList<>(16);
        out.add(new TracerPid());
        out.add(new ProcPid());
        out.add(new GotIntegrity());
        out.add(new MapFileIntegrity());
        out.add(new MapDeleted());
        out.add(new Memfd());
        out.add(new AnonExec());
        out.add(new MapExecFiles());
        out.add(new Vdso());
        out.add(new Timing());
        out.add(new ThreadName());
        out.add(new StackFrames());
        return out;
    }

    // ------------------------------------------------------------------ A：不变量

    /**
     * rt.tracerpid —— /proc/self/status 的 TracerPid + native 视图交叉。
     *
     * <p>A 级：ptrace 挂上去就一定非 0，没有任何「正常场景」会写 TracerPid。两条路径读数不一致
     * （一条 0 一条非 0）只有在有人过滤 /proc 时才发生。
     */
    static final class TracerPid implements Probe {
        @Override
        public String id() {
            return "rt.tracerpid";
        }

        @Override
        public String category() {
            return "runtime-integrity";
        }

        @Override
        public int weight() {
            return 4;
        }

        @Override
        public String tier() {
            return "A";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                int nat = (ctx.nat == null || !ctx.nat.ok) ? -1 : ctx.nat.tracerPid;
                int proc = ProcFs.statusInt("TracerPid");
                ctx.facts.put("rt.tracerpid.proc", proc).put("rt.tracerpid.native", nat);

                if (proc > 0) {
                    sink.tampered("TracerPid=" + proc + " (/proc/self/status)", 0.98);
                } else if (proc == 0) {
                    if (nat > 0) {
                        sink.tampered("status TracerPid=0 but native=" + nat + " (one view filtered)", 0.9);
                    } else {
                        sink.clean("TracerPid=0" + (nat == 0 ? " (status+native agree)" : ""));
                    }
                } else if (nat == 0) {
                    sink.clean("TracerPid=0 (native only; status unreadable)", 0.8);
                } else if (nat > 0) {
                    sink.tampered("native TracerPid=" + nat, 0.95);
                } else {
                    sink.unknown("TracerPid unreadable on both views");
                }
            } catch (Throwable t) {
                sink.error("rt.tracerpid: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * rt.proc.pid —— 进程号三视图交叉（Java / native / /proc/self/stat）。
     *
     * <p>B 级：正常情况下三者恒等。不一致说明有人替换了 /proc 视图，或 probe 跑在
     * fork 出来的影子进程里。
     */
    static final class ProcPid implements Probe {
        @Override
        public String id() {
            return "rt.proc.pid";
        }

        @Override
        public String category() {
            return "runtime-integrity";
        }

        @Override
        public int weight() {
            return 2;
        }

        @Override
        public String tier() {
            return "B";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                int javaPid = android.os.Process.myPid();
                int natPid = ctx.nat == null ? -1 : ctx.nat.pid;
                int statPid = ProcFs.statPid();
                ctx.facts.put("rt.proc.pid.java", javaPid)
                        .put("rt.proc.pid.native", natPid)
                        .put("rt.proc.pid.stat", statPid);

                boolean mismatch = (natPid > 0 && natPid != javaPid) || (statPid > 0 && statPid != javaPid);
                if (mismatch) {
                    sink.suspect("pid java=" + javaPid + " native=" + natPid + " stat=" + statPid, 0.65);
                } else if (statPid > 0) {
                    sink.clean("pid=" + javaPid + " (java+stat agree)", 0.9);
                } else {
                    sink.unknown("/proc/self/stat unreadable (pid=" + javaPid + ")");
                }
            } catch (Throwable t) {
                sink.error("rt.proc.pid: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * rt.got.integrity —— GOT/PLT 落点合法性（native gotCheck）。
     *
     * <p>A 级：GOT 表项被改成指向非目标二进制的地址，是注入的硬痕迹。native 侧尚未实现扫描时
     * scanned=0，这里必须报 UNKNOWN 而不是 CLEAN —— 否则「没测」会被读成「干净」。
     */
    static final class GotIntegrity implements Probe {
        @Override
        public String id() {
            return "rt.got.integrity";
        }

        @Override
        public String category() {
            return "runtime-integrity";
        }

        @Override
        public int weight() {
            return 4;
        }

        @Override
        public String tier() {
            return "A";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                if (ctx.nat == null || !ctx.nat.ok || ctx.nat.gotScanned < 0) {
                    sink.unknown("native snapshot unavailable");
                    return;
                }
                int scanned = ctx.nat.gotScanned;
                int bad = ctx.nat.gotBad;
                String sample = ctx.nat.gotSamples.isEmpty() ? "" : " e0=" + Ev.clip(ctx.nat.gotSamples.get(0), 90);
                if (scanned <= 0) {
                    sink.unknown("gotCheck scanned=0 (native side not implemented)");
                } else if (bad > 0) {
                    sink.tampered("GOT bad=" + bad + "/" + scanned + sample, 0.95);
                } else {
                    sink.clean("GOT scanned=" + scanned + " bad=0", 0.9);
                }
            } catch (Throwable t) {
                sink.error("rt.got.integrity: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * rt.maps.file_integrity —— 已映射 .so 的 r-x 段字节 vs 磁盘文件。
     *
     * <p>做法：从 /proc/self/maps 取「可执行 + 文件映射」的段，按 maps 里的 file offset 从
     * /proc/self/mem 读前 192 字节，再从磁盘同一 offset 读同样字节比对。页表是真值，任何
     * 内存补丁（inline hook、热替换、脱壳后改 so）都过不了这一关。
     *
     * <p>降级：Android 15+ 的 exec-only 页 / pkey 会让 /proc/self/mem 读失败，读不到就
     * 跳过；全跳过 → UNKNOWN（不算分），绝不因为读不到就打 TAMPERED。
     */
    static final class MapFileIntegrity implements Probe {
        private static final int MAX_PAGES = 5;
        private static final int BYTES = 192;

        @Override
        public String id() {
            return "rt.maps.file_integrity";
        }

        @Override
        public String category() {
            return "runtime-integrity";
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
                List<ProcFs.Region> maps = ProcFs.mapsOrNull();
                if (maps == null) {
                    sink.unknown("/proc/self/maps unreadable");
                    return;
                }
                String pkg = ctx.appSnap == null ? "" : Ev.nz(ctx.appSnap.packageName);
                String codeDir = ctx.appSnap == null ? "" : Ev.dirOf(ctx.appSnap.codePath);

                List<ProcFs.Region> picked = new ArrayList<>();
                Set<String> seen = new HashSet<>();
                Set<String> ownPaths = new HashSet<>();
                for (int pass = 0; pass < 2 && picked.size() < MAX_PAGES; pass++) {
                    for (ProcFs.Region r : maps) {
                        if (picked.size() >= MAX_PAGES) {
                            break;
                        }
                        if (!r.exec() || !r.fileBacked()) {
                            continue;
                        }
                        if (!r.path.endsWith(".so") && !r.path.endsWith(".apk")) {
                            continue;
                        }
                        if (pass == 0 && !Ev.isOwnPath(r.path, pkg, codeDir)) {
                            continue;
                        }
                        if (!seen.add(r.path)) {
                            continue;
                        }
                        if (pass == 0) {
                            ownPaths.add(r.path);
                        }
                        picked.add(r);
                    }
                }
                if (picked.isEmpty()) {
                    sink.unknown("no executable file-backed .so/.apk mapping");
                    return;
                }

                RandomAccessFile mem;
                try {
                    mem = new RandomAccessFile("/proc/self/mem", "r");
                } catch (Throwable t) {
                    sink.unknown("/proc/self/mem open denied (" + t.getClass().getSimpleName() + ")");
                    return;
                }

                int checked = 0;
                int bad = 0;
                int ownBad = 0;
                String firstBad = "";
                try {
                    for (ProcFs.Region r : picked) {
                        int len = (int) Math.min((long) BYTES, r.size());
                        if (len <= 0) {
                            continue;
                        }
                        byte[] inMem = new byte[len];
                        if (!ProcFs.readAt(mem, r.start, inMem)) {
                            continue;
                        }
                        byte[] onDisk = ProcFs.readFileAt(r.path, r.offset, len);
                        if (onDisk == null) {
                            continue;
                        }
                        checked++;
                        if (!Arrays.equals(inMem, onDisk)) {
                            bad++;
                            if (ownPaths.contains(r.path)) {
                                ownBad++;
                            }
                            if (firstBad.isEmpty()) {
                                firstBad = Ev.base(r.path) + "+0x" + Long.toHexString(r.offset);
                            }
                        }
                    }
                } finally {
                    ProcFs.close(mem);
                }

                ctx.facts.put("rt.file.integrity.checked", checked)
                        .put("rt.file.integrity.bad", bad)
                        .put("rt.file.integrity.ownBad", ownBad);
                if (checked == 0) {
                    sink.unknown("exec pages unreadable on both sides (exec-only/pkey)");
                } else if (ownBad > 0) {
                    // 自家库的 r-x 段与自家 APK 里的字节不符 —— 只可能是内存被改
                    sink.tampered("own-lib rx!=disk n=" + ownBad + "/" + checked + " e0=" + firstBad, 0.9);
                } else if (bad >= 3) {
                    sink.tampered("system-lib rx!=disk on " + bad + "/" + checked + " e0=" + firstBad, 0.85);
                } else if (bad > 0) {
                    sink.suspect("rx!=disk on " + bad + "/" + checked + " mapping e0=" + firstBad, 0.65);
                } else {
                    sink.clean("rx bytes==disk for " + checked + " mapping(s)", 0.9);
                }
            } catch (Throwable t) {
                sink.error("rt.maps.file_integrity: " + t.getClass().getSimpleName());
            }
        }
    }

    // ------------------------------------------------------------------ B：交叉视图

    /**
     * rt.maps.deleted —— maps 里 (deleted) 的 file-backed 段。
     *
     * <p>重打包/热替换的典型形状：进程映射着一份「已删除」的库或 APK（原文件已被换掉）。
     *
     * <p>必须过滤 ART 的伪路径：{@code /dev/ashmem/dalvik-* (deleted)} 与
     * {@code memfd:jit-cache (deleted)} 在**每台**干净机上都存在，不过滤就是 100% 误报。
     */
    static final class MapDeleted implements Probe {
        @Override
        public String id() {
            return "rt.maps.deleted";
        }

        @Override
        public String category() {
            return "runtime-integrity";
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
                List<ProcFs.Region> maps = ProcFs.mapsOrNull();
                if (maps == null) {
                    sink.unknown("/proc/self/maps unreadable");
                    return;
                }
                String pkg = ctx.appSnap == null ? "" : Ev.nz(ctx.appSnap.packageName);
                String codeDir = ctx.appSnap == null ? "" : Ev.dirOf(ctx.appSnap.codePath);
                String dataDir = ctx.appSnap == null ? "" : Ev.nz(ctx.appSnap.dataDir);

                List<String> hard = new ArrayList<>();   // /data/local/tmp、sdcard、自家 dataDir
                List<String> own = new ArrayList<>();    // 自家 codePath 目录（升级/热替换）
                List<String> other = new ArrayList<>();
                for (ProcFs.Region r : maps) {
                    if (!r.deleted || !r.fileBacked() || ProcFs.isPseudoPath(r.path)) {
                        continue;
                    }
                    if (Ev.isBadRoot(r.path, dataDir)) {
                        hard.add(r.path);
                    } else if (Ev.isOwnPath(r.path, pkg, codeDir)) {
                        own.add(r.path);
                    } else {
                        other.add(r.path);
                    }
                }
                ctx.facts.put("rt.maps.deleted.hard", Ev.clipList(hard, 3))
                        .put("rt.maps.deleted.own", Ev.clipList(own, 3))
                        .put("rt.maps.deleted.other", Ev.clipList(other, 3));

                if (!hard.isEmpty()) {
                    sink.tampered("deleted exec-path mapping n=" + hard.size() + " e0=" + Ev.clip(hard.get(0), 110), 0.85);
                } else if (!own.isEmpty()) {
                    sink.suspect("own codePath deleted-mapped n=" + own.size() + " e0=" + Ev.clip(own.get(0), 110), 0.6);
                } else if (!other.isEmpty()) {
                    sink.suspect("deleted file mapping n=" + other.size() + " e0=" + Ev.clip(other.get(0), 110), 0.5);
                } else {
                    sink.clean("no file-backed (deleted) mapping");
                }
            } catch (Throwable t) {
                sink.error("rt.maps.deleted: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * rt.memfd —— memfd 可执行加载。
     *
     * <p>memfd 是「无文件注入」的标准载体：payload 不落盘，只在内存里。但 ART 自己的
     * {@code memfd:jit-cache} 是干净的，必须排除，否则干净机全红。
     */
    static final class Memfd implements Probe {
        @Override
        public String id() {
            return "rt.memfd";
        }

        @Override
        public String category() {
            return "runtime-integrity";
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
                List<ProcFs.Region> maps = ProcFs.mapsOrNull();
                int n;
                int benign = 0;
                List<String> names = new ArrayList<>();
                if (maps != null) {
                    n = 0;
                    for (ProcFs.Region r : maps) {
                        if (!r.exec() || !r.path.contains("memfd:")) {
                            continue;
                        }
                        // memfd 路径不以 '/' 开头，isPseudoPath 一律为真，所以这里必须自己判名字：
                        // ART 的 memfd:jit-cache / app-image 是干净机的常客
                        String lower = r.path.toLowerCase();
                        if (lower.contains("jit") || lower.contains("dalvik")
                                || lower.contains("art-image") || lower.contains("app-image")
                                || lower.contains("gpu")) {
                            benign++;
                            continue;
                        }
                        n++;
                        if (names.size() < 3) {
                            names.add(r.path);
                        }
                    }
                } else if (ctx.nat != null && ctx.nat.memfdCount >= 0) {
                    n = ctx.nat.memfdCount;
                    names.addAll(ctx.nat.memfdSamples.size() > 3
                            ? ctx.nat.memfdSamples.subList(0, 3) : ctx.nat.memfdSamples);
                    benign = -1;
                } else {
                    sink.unknown("maps unreadable + native memfd unavailable");
                    return;
                }
                ctx.facts.put("rt.memfd.count", n).put("rt.memfd.names", Ev.clipList(names, 3));
                String ev = "memfd=" + n + (benign > 0 ? " (art-jit excluded=" + benign + ")" : "")
                        + (names.isEmpty() ? "" : " e0=" + Ev.clip(names.get(0), 90));

                if (n <= 0) {
                    sink.clean(ev);
                } else if (n <= 2) {
                    sink.suspect(ev + " (anonymous exec payload?)", 0.6);
                } else {
                    sink.tampered(ev, 0.8);
                }
            } catch (Throwable t) {
                sink.error("rt.memfd: " + t.getClass().getSimpleName());
            }
        }
    }

    /** rt.maps.anon_exec —— 匿名可执行映射（hook 引擎的 trampoline 池）。 */
    static final class AnonExec implements Probe {
        @Override
        public String id() {
            return "rt.maps.anon_exec";
        }

        @Override
        public String category() {
            return "runtime-integrity";
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
                int n;
                long bytes;
                String sample = "";
                List<ProcFs.Region> maps = ProcFs.mapsOrNull();
                if (maps != null) {
                    n = 0;
                    bytes = 0L;
                    for (ProcFs.Region r : maps) {
                        // 真正「无名字」的可执行段；[anon:dalvik-*] 这类有名字的不算
                        if (!r.exec() || !r.path.isEmpty()) {
                            continue;
                        }
                        n++;
                        bytes += r.size();
                        if (sample.isEmpty()) {
                            sample = r.hexRange() + " " + r.perms;
                        }
                    }
                } else if (ctx.nat != null && ctx.nat.anonExecCount >= 0) {
                    n = ctx.nat.anonExecCount;
                    bytes = ctx.nat.anonExecBytes;
                    sample = ctx.nat.anonExecSamples.isEmpty() ? "" : ctx.nat.anonExecSamples.get(0);
                } else {
                    sink.unknown("maps unreadable + native anonExec unavailable");
                    return;
                }
                ctx.facts.put("rt.anon_exec.count", n).put("rt.anon_exec.bytes", bytes);
                String ev = "anon-exec=" + n + " bytes=" + bytes + (sample.isEmpty() ? "" : " e0=" + Ev.clip(sample, 70));

                if (n == 0) {
                    sink.clean(ev);
                } else if (n <= 3 && bytes <= 2L * 1024 * 1024) {
                    // JIT / V8 code range 也就这么大，干净机上允许存在
                    sink.clean(ev + " (jit-like)", 0.8);
                } else if (n <= 8) {
                    sink.suspect(ev, 0.55);
                } else {
                    sink.tampered(ev, 0.8);
                }
            } catch (Throwable t) {
                sink.error("rt.maps.anon_exec: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * rt.maps.exec_files —— 从「不可能可执行」的路径映射了可执行段。
     *
     * <p>Android 10+ 对 app 可写目录是 W^X 的：{@code /data/local/tmp}、sdcard、自家 data dir
     * 里都不应该出现 r-x 的文件映射。出现即「从外部拉了一份代码执行」。
     */
    static final class MapExecFiles implements Probe {
        @Override
        public String id() {
            return "rt.maps.exec_files";
        }

        @Override
        public String category() {
            return "runtime-integrity";
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
                List<ProcFs.Region> maps = ProcFs.mapsOrNull();
                if (maps == null) {
                    sink.unknown("/proc/self/maps unreadable");
                    return;
                }
                String pkg = ctx.appSnap == null ? "" : Ev.nz(ctx.appSnap.packageName);
                String dataDir = ctx.appSnap == null ? "" : Ev.nz(ctx.appSnap.dataDir);

                List<String> hard = new ArrayList<>();
                List<String> soft = new ArrayList<>();
                for (ProcFs.Region r : maps) {
                    if (!r.exec() || !r.fileBacked() || ProcFs.isPseudoPath(r.path)) {
                        continue;
                    }
                    if (Ev.isSystemLibPath(r.path)) {
                        continue;
                    }
                    if (Ev.isBadRoot(r.path, dataDir)) {
                        if (!hard.contains(r.path) && hard.size() < 4) {
                            hard.add(r.path);
                        }
                    } else if (!Ev.isOwnPath(r.path, pkg, "")) {
                        if (!soft.contains(r.path) && soft.size() < 4) {
                            soft.add(r.path);
                        }
                    }
                }
                ctx.facts.put("rt.maps.exec.hard", hard).put("rt.maps.exec.soft", soft);

                if (!hard.isEmpty()) {
                    sink.tampered("exec mapping from bad root n=" + hard.size() + " e0=" + Ev.clip(hard.get(0), 110), 0.85);
                } else if (!soft.isEmpty()) {
                    sink.suspect("exec mapping outside whitelist n=" + soft.size() + " e0=" + Ev.clip(soft.get(0), 110), 0.55);
                } else {
                    sink.clean("all exec file mappings under system/codePath", 0.9);
                }
            } catch (Throwable t) {
                sink.error("rt.maps.exec_files: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * rt.vdso —— vdso 双视图一致性。
     *
     * <p>[vdso] 是内核映射的只读页，大小固定且是页对齐。有人改 syscall 路径（PLT/GOT 或
     * seccomp 注入）时，常常顺带把 /proc/self/maps 也过滤一遍，于是 native 与 Java 两个
     * 视图的 [vdso] 大小对不上。
     */
    static final class Vdso implements Probe {
        @Override
        public String id() {
            return "rt.vdso";
        }

        @Override
        public String category() {
            return "runtime-integrity";
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
                long natSize = (ctx.nat == null || !ctx.nat.ok) ? 0L : ctx.nat.vdsoSize;
                long javaSize = -1L;
                List<ProcFs.Region> maps = ProcFs.mapsOrNull();
                if (maps != null) {
                    for (ProcFs.Region r : maps) {
                        if ("[vdso]".equals(r.path)) {
                            javaSize = r.size();
                        }
                    }
                }
                ctx.facts.put("rt.vdso.native", natSize).put("rt.vdso.java", javaSize);

                if (natSize <= 0 && javaSize <= 0) {
                    sink.unknown("no [vdso] mapping in either view");
                    return;
                }
                if (natSize > 0 && javaSize > 0 && natSize != javaSize) {
                    sink.suspect("vdso native=" + natSize + "B java=" + javaSize + "B (views disagree)", 0.7);
                    return;
                }
                long size = natSize > 0 ? natSize : javaSize;
                if (size < 4096L || size > 64L * 1024 || (size & 0xfffL) != 0L) {
                    sink.suspect("vdso size=" + size + "B implausible", 0.6);
                } else {
                    sink.clean("vdso=" + size + "B (both views agree)", 0.9);
                }
            } catch (Throwable t) {
                sink.error("rt.vdso: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * rt.timing —— syscall 耗时抖动。
     *
     * <p>直接读 native 快照里的 200 次 openat 采样（**不自己再采样**，契约 §1.2）。hook 掉
     * libc 的 open/openat 会把中位数抬到微秒甚至毫秒级，或者尾部抖动暴涨。
     *
     * <p>阈值刻意放很宽：干净机 openat 中位数 ~1-3µs，这里卡 2ms，热节流也不会误报。
     */
    static final class Timing implements Probe {
        @Override
        public String id() {
            return "rt.timing";
        }

        @Override
        public String category() {
            return "runtime-integrity";
        }

        @Override
        public int weight() {
            return 2;
        }

        @Override
        public String tier() {
            return "B";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                if (ctx.nat == null || !ctx.nat.ok || ctx.nat.timingN <= 0) {
                    sink.unknown("native timing not sampled");
                    return;
                }
                long med = ctx.nat.timingMedianNs;
                long p99 = ctx.nat.timingP99Ns;
                long jit = ctx.nat.timingJitterNs;
                int n = ctx.nat.timingN;
                String ev = "openat median=" + med + "ns p99=" + p99 + "ns jitter=" + jit + "ns n=" + n;

                if (med <= 0) {
                    sink.unknown("timing median=0 (clock or seccomp)");
                } else if (med > 2000000L) {
                    sink.suspect(ev + " (median>2ms: libc hook?)", 0.6);
                } else if (p99 > 20000000L) {
                    sink.suspect(ev + " (p99>20ms)", 0.5);
                } else if (jit > 1000000L && jit > 50L * med) {
                    sink.suspect(ev + " (jitter>>median)", 0.45);
                } else {
                    sink.clean(ev, 0.85);
                }
            } catch (Throwable t) {
                sink.error("rt.timing: " + t.getClass().getSimpleName());
            }
        }
    }

    // ------------------------------------------------------------------ C：特征（只许 SUSPECT）

    /**
     * rt.thread.name —— 线程名黑名单。
     *
     * <p>tier C：特征匹配，只出 SUSPECT。特征来源是各 hook 引擎自己起的线程名
     * （Frida 的 gum-js-loop/gmain/gdbus/pool-frida、注入器的 linjector…）。
     * 短名用**精确匹配**（gmain 不能拿 contains，否则 ImageMain 之类会误报）。
     */
    static final class ThreadName implements Probe {
        private static final String[] EXACT = {
                "gmain", "gdbus", "gum-js-loop", "gum-js-loop2", "pool-frida", "frida",
                "frida-main", "linjector", "gdbus-proxy", "gum-js",
        };
        private static final String[] CONTAINS = {
                "frida", "gum-js", "linjector", "substrate", "xposed", "lsposed",
                "zygisk", "riru", "sandhook", "dobby",
        };

        @Override
        public String id() {
            return "rt.thread.name";
        }

        @Override
        public String category() {
            return "runtime-integrity";
        }

        @Override
        public int weight() {
            return 3;
        }

        @Override
        public String tier() {
            return "C";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                List<String> names;
                if (ctx.nat != null && ctx.nat.ok && !ctx.nat.threadNames.isEmpty()) {
                    names = ctx.nat.threadNames;
                } else {
                    names = ProcFs.taskComms();
                }
                if (names.isEmpty()) {
                    sink.unknown("thread names unavailable");
                    return;
                }
                List<String> hits = new ArrayList<>();
                int renderThread = 0;
                for (String raw : names) {
                    if (raw == null || raw.isEmpty()) {
                        continue;
                    }
                    String nm = raw.trim();
                    String lower = nm.toLowerCase();
                    if ("RenderThread".equals(nm)) {
                        renderThread++;
                    }
                    boolean hit = false;
                    for (String e : EXACT) {
                        if (e.equals(lower)) {
                            hit = true;
                            break;
                        }
                    }
                    if (!hit) {
                        for (String c : CONTAINS) {
                            if (lower.contains(c)) {
                                hit = true;
                                break;
                            }
                        }
                    }
                    if (hit && hits.size() < 4) {
                        hits.add(nm);
                    }
                }
                ctx.facts.put("rt.thread.count", names.size()).put("rt.thread.hits", hits);

                if (!hits.isEmpty()) {
                    sink.suspect("thread names=" + names.size() + " hits=" + Ev.clipList(hits, 4), 0.6);
                } else if (renderThread > 1) {
                    sink.suspect("RenderThread x" + renderThread + " (dup renderer thread)", 0.35);
                } else {
                    sink.clean("thread names=" + names.size() + " no blacklist hit");
                }
            } catch (Throwable t) {
                sink.error("rt.thread.name: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * rt.stack.frames —— ART 栈帧里的 hook 框架影子帧。
     *
     * <p>tier C：Java 方法被 Xposed/LSPlant 之类 hook 时，调用栈里会多出框架的帧。
     */
    static final class StackFrames implements Probe {
        private static final String[] MARKS = {
                "de.robv.android.xposed", "org.lsposed", "io.github.lsposed", "com.swift.sandhook",
                "me.weishu", "top.canyie", "com.saurik.substrate", "io.va.exposed",
                "org.meowcat.", "com.elderdrivers", "github.tornaco", "com.taobao.android.dexposed",
        };

        @Override
        public String id() {
            return "rt.stack.frames";
        }

        @Override
        public String category() {
            return "runtime-integrity";
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
                StackTraceElement[] frames = new Throwable().getStackTrace();
                List<String> hits = new ArrayList<>();
                for (StackTraceElement f : frames) {
                    String cn = f.getClassName();
                    if (cn == null) {
                        continue;
                    }
                    String lower = cn.toLowerCase();
                    for (String m : MARKS) {
                        if (lower.contains(m)) {
                            if (hits.size() < 3) {
                                hits.add(cn);
                            }
                            break;
                        }
                    }
                }
                ctx.facts.put("rt.stack.frames", frames.length);
                if (!hits.isEmpty()) {
                    sink.suspect("frames=" + frames.length + " hook-class=" + Ev.clipList(hits, 3), 0.6);
                } else {
                    sink.clean("frames=" + frames.length + " no hook frame");
                }
            } catch (Throwable t) {
                sink.error("rt.stack.frames: " + t.getClass().getSimpleName());
            }
        }
    }
}

// ====================================================================== 包内共享工具

/**
 * /proc 读取与解析。**只产事实，不产结论**，所有方法都不抛异常。
 *
 * <p>放在这里是因为它被 rt.* / inj.* / priv.* / pkg.* 多处复用；maps 解析做了 900ms 缓存，
 * 保证一轮报告里所有向量看到的是同一份 maps（契约 §1.3「一次采样、全体复用」的精神）。
 */
final class ProcFs {

    /** 一行 /proc/self/maps。 */
    static final class Region {
        final long start;
        final long end;
        final long offset;
        final String perms;
        final String path;
        final boolean deleted;

        Region(long start, long end, String perms, long offset, String path, boolean deleted) {
            this.start = start;
            this.end = end;
            this.perms = perms;
            this.offset = offset;
            this.path = path;
            this.deleted = deleted;
        }

        boolean exec() {
            return perms.indexOf('x') >= 0;
        }

        boolean writable() {
            return perms.indexOf('w') >= 0;
        }

        /** 真正落在文件系统上的映射（排除 ashmem / memfd / [anon:*] / [vdso] / /dev/* 等伪路径）。 */
        boolean fileBacked() {
            return !path.isEmpty() && path.charAt(0) == '/'
                    && !path.startsWith("/dev/")
                    && !path.contains("/dalvik-") && !path.contains("/dalvik/");
        }

        long size() {
            return end - start;
        }

        String hexRange() {
            return Long.toHexString(start) + "-" + Long.toHexString(end);
        }
    }

    private static final Object LOCK = new Object();
    private static boolean mapsLoaded;
    private static boolean mapsOk;
    private static List<Region> mapsCache;
    private static long mapsAt;

    private ProcFs() {
    }

    /** /proc/self/maps；读不到返回 null（调用方决定 UNKNOWN）。 */
    static List<Region> mapsOrNull() {
        synchronized (LOCK) {
            if (mapsLoaded && System.nanoTime() - mapsAt < 900000000L) {
                return mapsOk ? mapsCache : null;
            }
            String text = readText("/proc/self/maps", 3 * 1024 * 1024);
            mapsCache = text == null ? null : parseMaps(text);
            mapsOk = mapsCache != null;
            mapsLoaded = true;
            mapsAt = System.nanoTime();
            return mapsCache;
        }
    }

    /** ART 自己的伪路径：ashmem 命名段、[anon:*]、memfd、/dev/*、dalvik 生成物。不算文件映射。 */
    static boolean isPseudoPath(String path) {
        if (path == null || path.isEmpty()) {
            return true;
        }
        if (path.charAt(0) != '/') {
            return true;   // [vdso] / [stack] / [anon:...] / memfd:...
        }
        if (path.startsWith("/dev/")) {
            return true;
        }
        // maps 里 memfd 会显示成 "/memfd:jit-zygote-cache"，带前导斜杠，会绕过上面的 charAt 判断。
        // 这是 ART 自己的 JIT/zygote 缓存，不是文件映射 —— 不过滤就是干净机上 100% 误报。
        if (path.startsWith("/memfd:") || path.contains("/ashmem/")) {
            return true;
        }
        return path.contains("/dalvik-") || path.contains("/dalvik/");
    }

    static int statusInt(String key) {
        String st = readText("/proc/self/status", 128 * 1024);
        if (st == null) {
            return -1;
        }
        int from = 0;
        while (from < st.length()) {
            int e = st.indexOf('\n', from);
            if (e < 0) {
                e = st.length();
            }
            if (st.startsWith(key, from)) {
                int c = st.indexOf(':', from);
                if (c >= from && c < e) {
                    return firstInt(st.substring(c + 1, e).trim());
                }
            }
            from = e + 1;
        }
        return -1;
    }

    /** /proc/self/stat 第 1 个字段（pid）。 */
    static int statPid() {
        String st = readText("/proc/self/stat", 8192);
        if (st == null) {
            return -1;
        }
        return firstInt(st.trim());
    }

    /** /proc/self/task/<tid>/comm 全量，native 快照缺字段时的 Java 兜底。 */
    static List<String> taskComms() {
        List<String> out = new ArrayList<>();
        File dir = new File("/proc/self/task");
        String[] tids;
        try {
            tids = dir.list();
        } catch (Throwable t) {
            return out;
        }
        if (tids == null) {
            return out;
        }
        for (String tid : tids) {
            String comm = readText("/proc/self/task/" + tid + "/comm", 256);
            if (comm != null) {
                String s = comm.trim();
                if (!s.isEmpty() && out.size() < 256) {
                    out.add(s);
                }
            }
        }
        return out;
    }

    /** 读文本；失败返回 null。cap 是字符上限（maps/environ/mounts 都是 ASCII/UTF-8 单行）。 */
    static String readText(String path, int cap) {
        FileInputStream in = null;
        try {
            in = new FileInputStream(path);
            byte[] buf = new byte[16 * 1024];
            StringBuilder sb = new StringBuilder(4096);
            int n;
            while ((n = in.read(buf)) > 0) {
                for (int i = 0; i < n; i++) {
                    sb.append((char) (buf[i] & 0xff));
                }
                if (sb.length() >= cap) {
                    break;
                }
            }
            return sb.toString();
        } catch (Throwable t) {
            return null;
        } finally {
            close(in);
        }
    }

    /** 从 RandomAccessFile（通常是 /proc/self/mem）读满 buf；读不到返回 false。 */
    static boolean readAt(RandomAccessFile raf, long addr, byte[] buf) {
        try {
            raf.seek(addr);
            int off = 0;
            while (off < buf.length) {
                int n = raf.read(buf, off, buf.length - off);
                if (n <= 0) {
                    return false;
                }
                off += n;
            }
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /** 从普通文件指定偏移读 len 字节；读不满返回 null。 */
    static byte[] readFileAt(String path, long offset, int len) {
        RandomAccessFile raf = null;
        try {
            raf = new RandomAccessFile(path, "r");
            raf.seek(offset);
            byte[] buf = new byte[len];
            int off = 0;
            while (off < len) {
                int n = raf.read(buf, off, len - off);
                if (n <= 0) {
                    return null;
                }
                off += n;
            }
            return buf;
        } catch (Throwable t) {
            return null;
        } finally {
            close(raf);
        }
    }

    static void close(java.io.Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Throwable ignored) {
                // 关闭失败不影响结论
            }
        }
    }

    // ------------------------------------------------------------------ 内部

    private static List<Region> parseMaps(String text) {
        List<Region> out = new ArrayList<>(512);
        int from = 0;
        while (from < text.length()) {
            int e = text.indexOf('\n', from);
            if (e < 0) {
                e = text.length();
            }
            addLine(text.substring(from, e), out);
            from = e + 1;
        }
        return out;
    }

    private static void addLine(String line, List<Region> out) {
        if (line.isEmpty()) {
            return;
        }
        String[] f = line.split(" +", 6);
        if (f.length < 5) {
            return;
        }
        long start;
        long end;
        long offset;
        try {
            int dash = f[0].indexOf('-');
            if (dash <= 0) {
                return;
            }
            start = Long.parseLong(f[0].substring(0, dash), 16);
            end = Long.parseLong(f[0].substring(dash + 1), 16);
            offset = Long.parseLong(f[2], 16);
        } catch (Throwable t) {
            return;
        }
        String path = f.length >= 6 ? f[5].trim() : "";
        boolean deleted = path.endsWith(" (deleted)");
        if (deleted) {
            path = path.substring(0, path.length() - 10).trim();
        }
        out.add(new Region(start, end, f[1], offset, path, deleted));
    }

    private static int firstInt(String s) {
        if (s == null || s.isEmpty()) {
            return -1;
        }
        int i = 0;
        int n = s.length();
        while (i < n && (s.charAt(i) == ' ' || s.charAt(i) == '\t')) {
            i++;
        }
        int j = i;
        if (j < n && s.charAt(j) == '-') {
            j++;
        }
        while (j < n && Character.isDigit(s.charAt(j))) {
            j++;
        }
        if (j <= i) {
            return -1;
        }
        try {
            return Integer.parseInt(s.substring(i, j));
        } catch (Throwable t) {
            return -1;
        }
    }
}

/** 证据串与路径工具。所有方法都不抛异常，输出保证单行、可截断。 */
final class Ev {

    private Ev() {
    }

    static String nz(String s) {
        return s == null ? "" : s;
    }

    /** 单行化 + 长度截断（evidence 上限 300 字符，这里更保守）。 */
    static String clip(String s, int max) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            sb.append(c == '\n' || c == '\r' || c == '\t' || c == '\0' ? ' ' : c);
        }
        String one = sb.toString().trim();
        if (max > 8 && one.length() > max) {
            return one.substring(0, max - 3) + "...";
        }
        return one;
    }

    /** ["a","b"] → "a,b"（每项截断，最多 max 项）。 */
    static String clipList(List<String> list, int max) {
        if (list == null || list.isEmpty()) {
            return "[]";
        }
        StringBuilder sb = new StringBuilder("[");
        int n = 0;
        for (String s : list) {
            if (n >= max) {
                sb.append(",..");
                break;
            }
            if (n > 0) {
                sb.append(',');
            }
            sb.append(clip(s, 80));
            n++;
        }
        return sb.append(']').toString();
    }

    static String base(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        int i = path.lastIndexOf('/');
        return i < 0 ? path : path.substring(i + 1);
    }

    static String dirOf(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        int i = path.lastIndexOf('/');
        return i <= 0 ? "" : path.substring(0, i);
    }

    /** 路径是否属于「我们自己的包」（codePath 目录 / 包名出现其中）。 */
    static boolean isOwnPath(String path, String pkg, String codeDir) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        if (pkg != null && !pkg.isEmpty() && path.contains(pkg)) {
            return true;
        }
        return codeDir != null && !codeDir.isEmpty() && path.startsWith(codeDir);
    }

    /** 系统库根（这些路径下的可执行映射是正常的）。 */
    static boolean isSystemLibPath(String path) {
        if (path == null) {
            return false;
        }
        return path.startsWith("/system/") || path.startsWith("/system_ext/")
                || path.startsWith("/apex/") || path.startsWith("/vendor/")
                || path.startsWith("/product/") || path.startsWith("/odm/")
                || path.startsWith("/vendor_dlkm/") || path.startsWith("/system_dlkm/")
                || path.startsWith("/data/app/") || path.startsWith("/data/dalvik-cache/");
    }

    /** 「不该出现代码」的根：外部可写区 / 自家可写数据区。 */
    static boolean isBadRoot(String path, String dataDir) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        if (path.startsWith("/data/local/tmp/") || path.startsWith("/data/local/")
                || path.startsWith("/sdcard/") || path.startsWith("/storage/")
                || path.startsWith("/mnt/sdcard")) {
            return true;
        }
        return dataDir != null && !dataDir.isEmpty() && path.startsWith(dataDir + "/");
    }
}
