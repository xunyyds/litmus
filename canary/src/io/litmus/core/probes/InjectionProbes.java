package io.litmus.core.probes;

import io.litmus.core.LitmusContext;
import io.litmus.core.Probe;

import java.io.File;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 注入痕迹（框架痕迹面）。tier C 为主，**只允许 SUSPECT**。
 *
 * <p>为什么 tier C 不能下 TAMPERED：这些是「特征匹配」，误报率天然高
 * （用户装了 LSPosed 但没启用模块、或某个正常应用恰好起了同名线程）。
 * 真正的判定要靠 {@link RuntimeIntegrityProbes} 的不变量。
 *
 * <p>本文件里只有 {@code inj.elf.inline} / {@code inj.proc.env} 是 tier B（交叉视图/硬痕迹），
 * 其余 C 级向量一律 CLEAN / SUSPECT / UNKNOWN，绝不 TAMPERED。
 */
public final class InjectionProbes {

    private InjectionProbes() {
    }

    public static List<Probe> list() {
        List<Probe> out = new ArrayList<>(8);
        out.add(new ElfInline());
        out.add(new ProcEnv());
        out.add(new ModulePaths());
        out.add(new ModuleMarker());
        out.add(new RwxSegment());
        out.add(new FridaPort());
        out.add(new FridaSocket());
        return out;
    }

    // ------------------------------------------------------------------ B

    /**
     * inj.elf.inline —— ARM64 inline hook trampoline 字节扫描（native inlineHook）。
     *
     * <p>B 级交叉视图：函数入口的原始字节都在磁盘 ELF 里，内存里前几条指令被改成跳转就是
     * 硬痕迹。native 侧未实现（scanned=0）时必须 UNKNOWN，不能当干净。
     */
    static final class ElfInline implements Probe {
        @Override
        public String id() {
            return "inj.elf.inline";
        }

        @Override
        public String category() {
            return "injection";
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
                if (ctx.nat == null || !ctx.nat.ok || ctx.nat.inlineScanned < 0) {
                    sink.unknown("native snapshot unavailable");
                    return;
                }
                int scanned = ctx.nat.inlineScanned;
                int hits = ctx.nat.inlineHits;
                String sample = ctx.nat.inlineSamples.isEmpty()
                        ? "" : " e0=" + Ev.clip(ctx.nat.inlineSamples.get(0), 90);
                if (scanned <= 0) {
                    sink.unknown("inlineHook scanned=0 (native side not implemented)");
                } else if (hits > 0) {
                    sink.tampered("inline-hook hits=" + hits + "/" + scanned + sample, 0.85);
                } else {
                    sink.clean("inline scan " + scanned + " entries, 0 hit", 0.8);
                }
            } catch (Throwable t) {
                sink.error("inj.elf.inline: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * inj.proc.env —— /proc/self/environ 里的 LD_PRELOAD / CLASSPATH 之类。
     *
     * <p>B 级：环境变量是进程启动时的定值，重打包的 wrapper 脚本只能靠它布防；一旦读到
     * LD_PRELOAD 指向外部可写目录，就是「先加载我的库再交给 ART」。
     */
    static final class ProcEnv implements Probe {
        private static final String[] KEYS = {
                "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "CLASSPATH", "BOOTCLASSPATH",
        };

        @Override
        public String id() {
            return "inj.proc.env";
        }

        @Override
        public String category() {
            return "injection";
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
                String raw = ProcFs.readText("/proc/self/environ", 256 * 1024);
                if (raw == null || raw.isEmpty()) {
                    sink.unknown("/proc/self/environ unreadable or empty");
                    return;
                }
                List<String> entries = new ArrayList<>();
                int from = 0;
                while (from < raw.length() && entries.size() < 256) {
                    int e = raw.indexOf('\0', from);
                    if (e < 0) {
                        e = raw.length();
                    }
                    if (e > from) {
                        entries.add(raw.substring(from, e));
                    }
                    from = e + 1;
                }
                if (entries.isEmpty()) {
                    sink.unknown("/proc/self/environ parsed 0 entries");
                    return;
                }

                List<String> seen = new ArrayList<>();
                String preload = "";
                String otherHit = "";
                for (String kv : entries) {
                    int eq = kv.indexOf('=');
                    String k = eq < 0 ? kv : kv.substring(0, eq);
                    String v = eq < 0 ? "" : kv.substring(eq + 1).trim();
                    for (String want : KEYS) {
                        if (!want.equals(k)) {
                            continue;
                        }
                        if (v.isEmpty()) {
                            break;
                        }
                        seen.add(k);
                        if ("LD_PRELOAD".equals(k)) {
                            preload = v;
                        } else if (otherHit.isEmpty()) {
                            otherHit = k + "=" + Ev.clip(v, 90);
                        }
                        break;
                    }
                }
                ctx.facts.put("inj.proc.env.count", entries.size()).put("inj.proc.env.hit", seen);

                String dataDir = ctx.appSnap == null ? "" : Ev.nz(ctx.appSnap.dataDir);
                if (!preload.isEmpty()) {
                    if (Ev.isBadRoot(preload, dataDir)) {
                        sink.tampered("LD_PRELOAD=" + Ev.clip(preload, 120), 0.85);
                    } else {
                        sink.suspect("LD_PRELOAD=" + Ev.clip(preload, 120), 0.7);
                    }
                } else if (!otherHit.isEmpty()) {
                    sink.suspect(otherHit, 0.6);
                } else {
                    sink.clean("environ n=" + entries.size() + ", no LD_*/CLASSPATH set");
                }
            } catch (Throwable t) {
                sink.error("inj.proc.env: " + t.getClass().getSimpleName());
            }
        }
    }

    // ------------------------------------------------------------------ C（只许 SUSPECT）

    /**
     * inj.module.paths —— 已加载 .so 的路径白名单外命中。
     *
     * <p>tier C：加载器只从 /system、/apex、/vendor 和 app 的 codePath 里映射 so。出现别处
     * （/data/local/tmp、sdcard、别人家的 data 目录）就是有人自己拉了一份。
     */
    static final class ModulePaths implements Probe {
        @Override
        public String id() {
            return "inj.module.paths";
        }

        @Override
        public String category() {
            return "injection";
        }

        @Override
        public int weight() {
            return 4;
        }

        @Override
        public String tier() {
            return "C";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                List<ProcFs.Region> maps = ProcFs.mapsOrNull();
                if (maps == null) {
                    sink.unknown("/proc/self/maps unreadable");
                    return;
                }
                Set<String> libs = new HashSet<>();
                List<String> outside = new ArrayList<>();
                for (ProcFs.Region r : maps) {
                    if (!r.fileBacked() || ProcFs.isPseudoPath(r.path) || !r.path.endsWith(".so")) {
                        continue;
                    }
                    if (!libs.add(r.path)) {
                        continue;
                    }
                    if (!Ev.isSystemLibPath(r.path) && outside.size() < 4) {
                        outside.add(r.path);
                    }
                }
                ctx.facts.put("inj.module.libs", libs.size()).put("inj.module.outside", outside);

                if (libs.isEmpty()) {
                    sink.unknown("no file-backed .so mapping found");
                } else if (!outside.isEmpty()) {
                    sink.suspect("libs=" + libs.size() + " outside=" + Ev.clipList(outside, 2), 0.6);
                } else {
                    sink.clean("libs=" + libs.size() + " all under whitelist root");
                }
            } catch (Throwable t) {
                sink.error("inj.module.paths: " + t.getClass().getSimpleName());
            }
        }
    }

    /** inj.module.marker —— 已加载库的**文件名**命中 hook 引擎特征。tier C。 */
    static final class ModuleMarker implements Probe {
        private static final String[] MARKS = {
                "frida", "gum-js", "libgadget", "gadget", "substrate", "xposed", "lsposed",
                "sandhook", "dobby", "libwhale", "whale", "riru", "zygisk", "magisk",
                "libepic", "libpine", "libyuki", "inlinehook", "libhookzz", "bhook",
        };

        @Override
        public String id() {
            return "inj.module.marker";
        }

        @Override
        public String category() {
            return "injection";
        }

        @Override
        public int weight() {
            return 4;
        }

        @Override
        public String tier() {
            return "C";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                List<ProcFs.Region> maps = ProcFs.mapsOrNull();
                if (maps == null) {
                    sink.unknown("/proc/self/maps unreadable");
                    return;
                }
                Set<String> libs = new HashSet<>();
                List<String> hits = new ArrayList<>();
                for (ProcFs.Region r : maps) {
                    if (ProcFs.isPseudoPath(r.path) || !r.path.endsWith(".so")) {
                        continue;
                    }
                    if (!libs.add(r.path)) {
                        continue;
                    }
                    String name = Ev.base(r.path).toLowerCase();
                    for (String m : MARKS) {
                        if (name.contains(m)) {
                            if (hits.size() < 4) {
                                hits.add(Ev.base(r.path));
                            }
                            break;
                        }
                    }
                }
                ctx.facts.put("inj.module.marker", hits);
                if (libs.isEmpty()) {
                    sink.unknown("no mapped .so to match");
                } else if (!hits.isEmpty()) {
                    sink.suspect("libs=" + libs.size() + " marker=" + Ev.clipList(hits, 3), 0.6);
                } else {
                    sink.clean("libs=" + libs.size() + " no engine marker in names");
                }
            } catch (Throwable t) {
                sink.error("inj.module.marker: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * inj.elf.rwx —— 同时可写可执行的内存段。
     *
     * <p>tier C。必须排除 ART 的 JIT code cache：它在很多 ROM 上就是 rwx 且有名字
     * （{@code [anon:dalvik-jit-code-cache]} / {@code /dev/ashmem/dalvik-jit-code-cache}），
     * 不过滤的话干净机 100% 命中。
     */
    static final class RwxSegment implements Probe {
        @Override
        public String id() {
            return "inj.elf.rwx";
        }

        @Override
        public String category() {
            return "injection";
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
                List<ProcFs.Region> maps = ProcFs.mapsOrNull();
                int suspicious;
                int art = 0;
                String sample = "";
                if (maps != null) {
                    suspicious = 0;
                    for (ProcFs.Region r : maps) {
                        if (!r.exec() || !r.writable()) {
                            continue;
                        }
                        String lower = r.path.toLowerCase();
                        if (lower.contains("dalvik") || lower.contains("jit")
                                || lower.contains("art-image") || lower.contains("app-image")) {
                            art++;
                            continue;
                        }
                        suspicious++;
                        if (sample.isEmpty()) {
                            sample = r.hexRange() + " " + r.perms
                                    + (r.path.isEmpty() ? "" : " " + Ev.clip(r.path, 40));
                        }
                    }
                } else if (ctx.nat != null && ctx.nat.rwxCount >= 0) {
                    suspicious = ctx.nat.rwxCount;
                    sample = ctx.nat.rwxSamples.isEmpty()
                            ? "" : Ev.clip(ctx.nat.rwxSamples.get(0), 60);
                } else {
                    sink.unknown("maps unreadable + native rwx unavailable");
                    return;
                }
                ctx.facts.put("inj.rwx.count", suspicious).put("inj.rwx.artExcluded", art);
                String ev = "rwx=" + suspicious + (art > 0 ? " (art-jit excluded=" + art + ")" : "")
                        + (sample.isEmpty() ? "" : " e0=" + sample);

                if (suspicious == 0) {
                    sink.clean(ev);
                } else if (suspicious <= 2) {
                    sink.suspect(ev, 0.45);
                } else {
                    sink.suspect(ev, 0.6);
                }
            } catch (Throwable t) {
                sink.error("inj.elf.rwx: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * inj.frida.port —— 本机 27042/27043 是否在监听。tier C。
     *
     * <p>只连 loopback，connect 超时 15ms；关闭端口的 connect 会立刻 ECONNREFUSED，实测
     * 单端口 < 1ms，两端口合计远低于 50ms 预算。
     */
    static final class FridaPort implements Probe {
        private static final int[] PORTS = {27042, 27043};

        @Override
        public String id() {
            return "inj.frida.port";
        }

        @Override
        public String category() {
            return "injection";
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
                List<Integer> open = new ArrayList<>();
                boolean denied = false;
                for (int port : PORTS) {
                    Socket s = new Socket();
                    try {
                        s.connect(new InetSocketAddress("127.0.0.1", port), 15);
                        open.add(port);
                    } catch (SocketException se) {
                        String m = String.valueOf(se.getMessage()).toLowerCase();
                        if (m.contains("denied") || m.contains("eacces") || m.contains("eperm")) {
                            denied = true;
                        }
                    } catch (Throwable ignored) {
                        // 超时/拒绝都算端口未开
                    } finally {
                        ProcFs.close(s);
                    }
                }
                ctx.facts.put("inj.frida.openPorts", open);
                if (denied && open.isEmpty()) {
                    // 没有 INTERNET 权限时 connect 直接 EACCES，别把它当干净
                    sink.unknown("loopback connect denied (no INTERNET / seccomp)");
                } else if (!open.isEmpty()) {
                    sink.suspect("tcp loopback open on " + open.size() + " port(s) e0=" + open.get(0), 0.6);
                } else {
                    sink.clean("tcp 27042/27043 closed");
                }
            } catch (Throwable t) {
                sink.error("inj.frida.port: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * inj.frida.socket —— frida 的 unix socket / 落地文件痕迹。tier C。
     *
     * <p>三条路取证，任何一条命中即可：/data/local/tmp 下的 frida 落地文件、maps 里的
     * frida/gum 映射名、/proc/self/net/unix 里的 socket 名（后者多数 ROM 上读不到，
     * 读不到就只用前两条，不影响干净机给 CLEAN）。
     */
    static final class FridaSocket implements Probe {
        private static final String[] ARTIFACTS = {
                "/data/local/tmp/frida-server",
                "/data/local/tmp/re.frida.server",
                "/data/local/tmp/linjector",
                "/data/local/tmp/libgadget.so",
                "/data/local/tmp/frida-gadget.so",
                "/data/local/tmp/frida-agent.so",
        };

        @Override
        public String id() {
            return "inj.frida.socket";
        }

        @Override
        public String category() {
            return "injection";
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
                List<String> hits = new ArrayList<>();

                for (String p : ARTIFACTS) {
                    try {
                        if (new File(p).exists() && hits.size() < 4) {
                            hits.add("file:" + Ev.base(p));
                        }
                    } catch (Throwable ignored) {
                        // stat 被拒就跳过
                    }
                }

                List<ProcFs.Region> maps = ProcFs.mapsOrNull();
                int mapHits = 0;
                if (maps != null) {
                    for (ProcFs.Region r : maps) {
                        String lower = r.path.toLowerCase();
                        if (lower.contains("frida") || lower.contains("libgadget") || lower.contains("gum-js")) {
                            mapHits++;
                            if (hits.size() < 4) {
                                hits.add("map:" + Ev.clip(Ev.base(r.path), 40));
                            }
                        }
                    }
                }

                boolean unixReadable = false;
                String unix = ProcFs.readText("/proc/self/net/unix", 512 * 1024);
                if (unix != null) {
                    unixReadable = true;
                    String lower = unix.toLowerCase();
                    if (lower.contains("frida") || lower.contains("gum-js") || lower.contains("gmain")) {
                        if (hits.size() < 4) {
                            hits.add("unix:socket");
                        }
                    }
                }

                ctx.facts.put("inj.frida.hits", hits).put("inj.frida.unixReadable", unixReadable);
                if (!hits.isEmpty()) {
                    sink.suspect("frida trace=" + Ev.clipList(hits, 3), 0.55);
                } else {
                    sink.clean("no frida file/map/unix-socket trace (unix="
                            + (unixReadable ? "readable" : "denied") + ")");
                }
            } catch (Throwable t) {
                sink.error("inj.frida.socket: " + t.getClass().getSimpleName());
            }
        }
    }
}
